"""
PFS Cosmic Web View -- GUI phase (v4, 2026-07-24).

Architecture: embeds VaultSession directly, same process, like pfs_cli.py
-- no IPC, no dependency on the FUSE daemon. See manual.txt PART 10/PART 0
for the full reasoning (including why there's no path/directory concept
anywhere in this file).

THREE VIEW MODES (toggle, top-left):
  - Cosmic Web: one node per label (current tip), force-directed by
    SIMILARITY_PROFILE closeness.
  - Lineage Tree: the FULL DAG -- every recorded generation of every
    label, laid out by depth from its root. Divergent branches (forks)
    get distinct per-branch edge colors; a branch head's right-click menu
    has a real "Merge branches..." action.
  - Clade Tree: a REAL UPGMA or Neighbor-Joining dendrogram
    (TreeConstructor.build_tree_upgma_from_traits /
    build_tree_nj_from_traits), toggleable live -- watch the exact same
    files regroup differently under the two algorithms' different
    assumptions (constant mutation rate vs. not).

LIVE PHYSICS, not a one-shot static layout: a continuously-running
force simulation (repulsion between all nodes, springs along edges, a
weak centering pull, and -- in Tree/Clade Tree modes -- a weak vertical
bias keeping children below parents) runs every ~33ms. Dragging a node
"pins" it (the simulation stops writing its position but keeps reading
it, so neighbors still react in real time) and releases it back into the
simulation on mouse-up. This is what makes the graph feel alive/organic
under a drag instead of just a static diagram with movable dots.

OVERLAYS: search (dims non-matches), Time Machine slider (hides anything
that didn't exist yet, by real birth_timestamp), Outline Clades (draws a
boundary around each TreeConstructor.compute_clades() cluster, web mode),
Dedup Heat (recolors by shared vs. unique content, both graph modes), a
minimap inset (always-visible small overview + viewport indicator), and a
live stats HUD in the status bar.

WRITE ACTIONS, all routed through the same VaultSession methods the CLI
uses: right-click a node for Info / Rename / Duplicate (zero-cost alias)
/ Delete / Trace ancestry / Reveal in Tree (web mode); Info / Checkout /
Prune / Fork from here / Merge branches (tree mode, where applicable).
"+ New File" and canvas drag-and-drop both support MULTIPLE files at
once. Selecting two nodes (ctrl-click) shows a live similarity/shared-
chunk readout between them. A newly-appearing node grows in with a short
animation; successful actions show a toast instead of a silent rebuild.

Deferred, tracked in gui_ideas.txt (not silently dropped): a full ⌘K
command palette, a fully bespoke curved/interlocking "braid" edge
renderer (current per-branch edge coloring + working Merge is the
functional core), point-in-time CONTENT reconstruction in the Time
Machine (current version is existence-based), and a light theme variant.
"""
import argparse
import sys
import os
import math
import tempfile
import time
import difflib
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QGraphicsView, QGraphicsScene,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsSimpleTextItem,
    QGraphicsRectItem, QGraphicsItem, QGraphicsTextItem,
    QInputDialog, QLineEdit, QMessageBox, QDockWidget, QTextEdit,
    QStatusBar, QToolBar, QSlider, QLabel, QPushButton, QMenu, QFileDialog,
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QTableWidget, QTableWidgetItem,
    QWidget, QHeaderView, QPlainTextEdit, QScrollArea, QToolTip,
)
from PySide6.QtGui import (
    QColor, QBrush, QPen, QPainter, QFont, QKeySequence, QAction,
    QActionGroup, QRadialGradient, QImage, QDesktopServices, QPolygonF,
    QPainterPath, QShortcut, QPixmap,
)
from PySide6.QtCore import (
    Qt, QRectF, QLineF, QPointF, QPoint, Signal, QVariantAnimation, QEasingCurve, QTimer,
    QFileSystemWatcher, QUrl, QEvent,
)

import networkx as nx

from vault_session import VaultSession, VaultUnlockError, MutationConflictError
from PhylogeneticAnalyzer import PhylogeneticAnalyzer
from TreeConstructor import TreeConstructor
from pfs_engine_adapter import PythonEngineAdapter, CppEngineAdapter
import lineage_diff

# ---------- palette ----------
ACCENT = "#2dd4bf"
ACCENT_DIM = "#1f6f5c"
BG = "#0b0d12"
PANEL_BG = "#14161d"
INPUT_BG = "#1a1c24"
BORDER = "#2a2d38"
TEXT = "#e4e6ec"
TEXT_DIM = "#8891a5"

# One hue per FORMAT, not per broad "kind" -- more visual variety across
# a real, diverse vault (the flat 7-color grouping in the first version
# made anything but a handful of file types look monotone).
_COLOR_RULES = [
    ("PDF", "#4c8bf5"), ("Text", "#5aa9e6"),
    ("PNG", "#e8a33d"), ("JPEG", "#f2b705"), ("GIF", "#f4d35e"), ("BMP", "#eec170"),
    ("MP3", "#8e5fd6"), ("MP4", "#a06cd5"), ("RIFF", "#c77dff"),
    ("ZIP", "#4caf6e"), ("GZIP", "#6fcf97"),
    ("ELF", "#e05252"), ("SQLite", "#2fb6b2"),
]
_UNKNOWN_COLOR = "#7a7a85"

# Extension hint ONLY for the temp copy handed to the OS's default-app
# opener (Edit action) -- the vault itself stays fully extensionless,
# this is purely so "open with the right app" has its best chance of
# working, since not every desktop environment's file-open dialog
# reliably content-sniffs an extensionless file the way this project's
# own phenotype detection does.
_PHENOTYPE_EXTENSION_RULES = [
    ("PDF", ".pdf"), ("PNG", ".png"), ("JPEG", ".jpg"), ("GIF", ".gif"), ("BMP", ".bmp"),
    ("MP3", ".mp3"), ("MP4", ".mp4"), ("RIFF", ".wav"), ("ZIP", ".zip"), ("GZIP", ".gz"),
    ("SQLite", ".sqlite"), ("ELF", ""), ("Text", ".txt"),
]


def _extension_for_phenotype(name: str) -> str:
    for keyword, ext in _PHENOTYPE_EXTENSION_RULES:
        if keyword.lower() in name.lower():
            return ext
    return ""


# Plain typographic symbols, deliberately NOT full-color emoji -- emoji
# glyphs don't reliably respect QGraphicsSimpleTextItem's single-color
# brush (color-emoji fonts render their own fixed colors, ignoring
# setBrush), so a faint, tinted, always-visible glyph needs a character
# a normal text font actually has a monochrome glyph for.
_PHENOTYPE_GLYPH_RULES = [
    ("PDF", "▤"), ("Text", "▤"),
    ("PNG", "▧"), ("JPEG", "▧"), ("GIF", "▧"), ("BMP", "▧"),
    ("MP3", "♪"), ("MP4", "▶"), ("RIFF", "♪"),
    ("ZIP", "▦"), ("GZIP", "▦"),
    ("ELF", "⚙"), ("SQLite", "▥"),
]
_UNKNOWN_GLYPH = "◆"


def _glyph_for_phenotype(name: str) -> str:
    for keyword, glyph in _PHENOTYPE_GLYPH_RULES:
        if keyword.lower() in name.lower():
            return glyph
    return _UNKNOWN_GLYPH


# Which phenotypes get a genuine in-app, real-time editor/viewer instead
# of round-tripping through an external OS app (with all the sandboxing/
# multi-tab/save-detection unreliability that comes with that). Kept
# deliberately small and honest: Qt's own QPlainTextEdit/QPixmap already
# handle these formats natively with zero extra dependencies, so there's
# no reason to hand them off to an external app at all. Formats that
# genuinely need a real editor (video, audio, PDF layout, spreadsheets,
# databases...) still use the external-app path -- building bespoke
# in-app editors for those is real, dedicated software in its own right,
# not something to fake with a text box.
_INAPP_TEXT_PHENOTYPES = {"Plain Text"}
_INAPP_IMAGE_PHENOTYPES = {"PNG Image", "JPEG Image", "GIF Image", "BMP Image"}


def _is_inapp_text_phenotype(name: str) -> bool:
    return name in _INAPP_TEXT_PHENOTYPES


def _is_inapp_image_phenotype(name: str) -> bool:
    return name in _INAPP_IMAGE_PHENOTYPES


_LATERAL_EDGE_COLOR = "#a98ef0"
_DEFAULT_EDGE_COLOR = "#7f93bf"
_HEATMAP_LOW = "#e0524a"
_HEATMAP_HIGH = ACCENT
BRANCH_COLORS = ["#e08a3d", "#4c8bf5", "#4caf6e", "#e05252", "#c96fd6"]

# Lineage diff chunk-map colors -- matches Project_idea.txt's own framing
# ("red for deleted blocks, green for new code blocks"). CHANGED and NEW
# both read as green (a mutated position and a genuinely new/appended
# position are both "green" per the brief and per this project's own
# diff spec), but NEW gets the brighter shade so "the file grew here" is
# still visually distinguishable from "this existing position mutated"
# on hover/inspection, without contradicting the two-color brief.
_DIFF_UNCHANGED_COLOR = "#3a3d4a"
_DIFF_CHANGED_COLOR = "#4caf6e"
_DIFF_NEW_COLOR = "#8ee6a8"
_DIFF_DELETED_COLOR = "#e05252"

# The single source of truth for "how visible should a normal, non-dimmed
# edge be" -- EdgeItem's own resting opacity, the appearance-animation's
# end value, and the search/trace "on" states all read from this ONE
# constant instead of each hardcoding their own number. That drift is
# exactly what caused a real bug: the appearance animation used to end at
# 0.55 while the item's own resting opacity was a separately-hardcoded
# 0.75 -- any newly-created edge (every Duplicate, every Graft, every new
# write) silently ended up MORE faint than an edge that was never
# animated at all, which is what "some links are so very faint I can't
# see them" turned out to be.
EDGE_REST_OPACITY = 0.94


def _color_for_phenotype(name: str) -> QColor:
    for keyword, color in _COLOR_RULES:
        if keyword.lower() in name.lower():
            return QColor(color)
    return QColor(_UNKNOWN_COLOR)


def _heatmap_color(dedup_fraction: float) -> QColor:
    dedup_fraction = max(0.0, min(1.0, dedup_fraction))
    low, high = QColor(_HEATMAP_LOW), QColor(_HEATMAP_HIGH)
    r = low.red() + (high.red() - low.red()) * dedup_fraction
    g = low.green() + (high.green() - low.green()) * dedup_fraction
    b = low.blue() + (high.blue() - low.blue()) * dedup_fraction
    return QColor(int(r), int(g), int(b))


NODE_MIN_RADIUS = 9.0
NODE_MAX_RADIUS = 36.0
LAYOUT_SCALE = 900.0
SIMILARITY_LAYOUT_THRESHOLD = 0.60
TREE_LEVEL_SPACING = 130.0
TREE_SIBLING_SPACING = 85.0
CLADE_HEIGHT_SCALE = 700.0
WEB_EDGE_REST_LENGTH = 220.0
LATERAL_EDGE_REST_LENGTH = 200.0

# Deliberately NOT system /tmp: strictly-confined Snap apps (e.g. Ubuntu's
# default VLC) get their own private per-snap /tmp via mount namespacing and
# genuinely cannot see anything under the real /tmp -- opening a video for
# Edit/View would silently fail with "input can't be opened" no matter what
# this app does. Paths under $HOME are visible to sandboxed apps through the
# standard 'home' interface/portal, which is why XDG's own cache convention
# points here for exactly this kind of interop.
EDIT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "pfs_gui_edit")

# Light theme -- a real second palette, not just an afterthought toggle.
# Node/edge colors (phenotype hues, branch colors, heatmap gradient) are
# deliberately left theme-INDEPENDENT: they're medium-saturation colors
# chosen to read clearly on either a near-black or near-white canvas, so
# swapping the theme doesn't require re-deriving the whole data-driven
# palette, only the UI CHROME and the canvas background/grid.
LIGHT_ACCENT = "#0d9488"
LIGHT_ACCENT_DIM = "#99f2e4"
LIGHT_BG = "#f3f4f6"
LIGHT_PANEL_BG = "#ffffff"
LIGHT_INPUT_BG = "#eef0f3"
LIGHT_BORDER = "#d6dae1"
LIGHT_TEXT = "#1a1d24"
LIGHT_TEXT_DIM = "#5b6270"


def _build_stylesheet(accent, accent_dim, bg, panel_bg, input_bg, border, text, text_dim, hover_bg):
    return f"""
QMainWindow, QWidget {{ background: {bg}; color: {text}; }}
QToolBar {{ background: {panel_bg}; border: none; padding: 8px; spacing: 6px; }}
QToolBar QToolButton {{
    background: transparent; color: {text}; border: none; border-radius: 7px;
    padding: 6px 10px; font-size: 12px;
}}
QToolBar QToolButton:hover {{ background: {hover_bg}; }}
QToolBar QToolButton:checked {{ background: {accent_dim}; color: {panel_bg}; }}
QLineEdit {{
    background: {input_bg}; color: {text}; border: 1px solid {border};
    border-radius: 8px; padding: 6px 12px; font-size: 12px;
}}
QLineEdit:focus {{ border: 1px solid {accent}; }}
QDockWidget {{ color: {text_dim}; font-weight: 600; font-size: 12px; }}
QDockWidget::title {{ background: {panel_bg}; padding: 10px; }}
QTextEdit {{ background: {panel_bg}; color: {text}; border: none; padding: 12px; font-family: monospace; }}
QStatusBar {{ background: {panel_bg}; color: {text_dim}; border-top: 1px solid {border}; }}
QStatusBar QLabel {{ color: {text_dim}; font-size: 11px; }}
QSlider::groove:horizontal {{ background: {border}; height: 4px; border-radius: 2px; }}
QSlider::handle:horizontal {{
    background: {accent}; width: 14px; height: 14px; margin: -6px 0; border-radius: 7px;
}}
QPushButton {{
    background: {input_bg}; border: 1px solid {border}; border-radius: 6px;
    color: {text}; padding: 4px 10px; font-size: 12px;
}}
QPushButton:checked {{ background: {accent}; color: {bg}; border: 1px solid {accent}; }}
QMenu {{ background: {input_bg}; color: {text}; border: 1px solid {border}; padding: 4px; }}
QMenu::item {{ padding: 6px 20px; border-radius: 4px; }}
QMenu::item:selected {{ background: {accent_dim}; }}
QMessageBox, QInputDialog {{ background: {panel_bg}; }}
QTableWidget {{ background: {panel_bg}; color: {text}; gridline-color: {border}; border: none; font-size: 12px; }}
QTableWidget::item {{ padding: 4px; }}
QTableWidget::item:selected {{ background: {accent_dim}; color: {panel_bg}; }}
QHeaderView::section {{ background: {input_bg}; color: {text}; padding: 6px; border: none;
    border-bottom: 2px solid {border}; font-weight: 600; }}
QHeaderView::section:hover {{ background: {accent_dim}; }}
"""


STYLESHEET = _build_stylesheet(ACCENT, ACCENT_DIM, BG, PANEL_BG, INPUT_BG, BORDER, TEXT, TEXT_DIM, "#1f2129")
LIGHT_STYLESHEET = _build_stylesheet(LIGHT_ACCENT, LIGHT_ACCENT_DIM, LIGHT_BG, LIGHT_PANEL_BG, LIGHT_INPUT_BG,
                                      LIGHT_BORDER, LIGHT_TEXT, LIGHT_TEXT_DIM, "#e4e7eb")


# ---------- graph items ----------

class NodeItem(QGraphicsEllipseItem):
    """A file (web/clade-tree leaf) or one generation (lineage tree).
    Position IS scene position. `pinned` is True only while the user is
    actively dragging it -- the live physics simulation reads a pinned
    node's position (so neighbors still react to it) but never writes
    to it, handing full control back the moment the mouse is released."""

    def __init__(self, radius: float, display_text: str, base_color: QColor, glyph: str = ""):
        super().__init__(QRectF(-radius, -radius, radius * 2, radius * 2))
        self.radius = radius
        self.edges = []
        self.vx = 0.0
        self.vy = 0.0
        self.pinned = False
        self._base_color = base_color
        self._pulsing = False
        self._hovering = False

        self.setFlags(
            QGraphicsItem.ItemIsSelectable
            | QGraphicsItem.ItemIsMovable
            | QGraphicsItem.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setZValue(2)

        self.halo = QGraphicsEllipseItem(QRectF(-radius * 1.6, -radius * 1.6, radius * 3.2, radius * 3.2), self)
        self.halo.setBrush(QBrush(QColor(ACCENT + "33")))
        self.halo.setPen(QPen(Qt.NoPen))
        self.halo.setZValue(1.5)
        self.halo.setVisible(False)

        self._apply_color(base_color)

        # A faint, ALWAYS-visible type glyph (unlike the label, which is
        # hover-only) -- lets similarly-colored file types be told apart
        # at a glance without needing to hover each one.
        self.glyph_item = None
        if glyph:
            self.glyph_item = QGraphicsSimpleTextItem(glyph, self)
            self.glyph_item.setFont(QFont("Sans", max(7, int(radius * 0.6))))
            self.glyph_item.setBrush(QBrush(QColor(255, 255, 255, 150)))
            gr = self.glyph_item.boundingRect()
            self.glyph_item.setPos(-gr.width() / 2, -gr.height() / 2 - 1)
            self.glyph_item.setZValue(2.1)

        self.label_bg = QGraphicsRectItem(self)
        self.label_bg.setBrush(QBrush(QColor(12, 14, 20, 235)))
        self.label_bg.setPen(QPen(Qt.NoPen))
        self.label_text = QGraphicsSimpleTextItem(display_text, self)
        self.label_text.setBrush(QBrush(QColor(TEXT)))
        self.label_text.setFont(QFont("Sans", 8))
        lr = self.label_text.boundingRect()
        self.label_text.setPos(-lr.width() / 2, radius + 8)
        self.label_bg.setRect(lr.translated(-lr.width() / 2, radius + 8).adjusted(-5, -3, 5, 3))
        self.label_bg.setZValue(2.5)
        self.label_text.setZValue(2.6)
        self.label_bg.setVisible(False)
        self.label_text.setVisible(False)

    def _apply_color(self, base_color: QColor):
        gradient = QRadialGradient(0, 0, self.radius)
        gradient.setColorAt(0.0, base_color.lighter(150))
        gradient.setColorAt(1.0, base_color.darker(115))
        self.setBrush(QBrush(gradient))
        self._pen_normal = QPen(base_color.lighter(140), 1.4)
        self._pen_hover = QPen(QColor(ACCENT), 2.6)
        if not self._hovering:
            self.setPen(self._pen_normal)

    def set_focus_dim(self, dimmed: bool):
        """The 'depth of field' effect for search/ancestry-trace: not
        just a lower opacity (which the Time Machine and search already
        used, and still layers with this), but a real desaturation
        toward gray, so out-of-focus nodes read as 'defocused,' closer
        to a camera depth-of-field blur than a plain disabled/greyed-out
        state. A true Gaussian blur (QGraphicsBlurEffect) was considered
        and rejected: applying a blur effect per-item is a real
        per-frame cost when dozens of nodes could be dimmed at once
        under the continuously-running physics simulation -- this gets
        the same VISUAL intent for negligible cost."""
        if dimmed:
            hsv = self._base_color.toHsv()
            desat = QColor.fromHsv(hsv.hue(), int(hsv.saturation() * 0.12), hsv.value())
            self._apply_color(desat)
        else:
            self._apply_color(self._base_color)

    def mark_pulsing(self, pulsing: bool):
        """Just tracks whether a pulse animation currently owns this
        node's halo -- the animation ITSELF is created and owned by the
        window (see VaultGraphWindow._start_node_pulse), parented to the
        window's own QObject lifetime and tracked in _active_animations
        so _rebuild() stops it before scene.clear() destroys this item.
        An untracked, infinitely-looping (setLoopCount(-1)) animation
        owned by the item itself would hit the exact same dangling-C++-
        reference crash already found and fixed for the grow-in
        animation -- this keeps pulse animations on the SAME safe,
        already-proven lifecycle instead of a second, separately-managed
        one."""
        self._pulsing = pulsing
        if not pulsing and not self._hovering:
            self.halo.setVisible(False)
            self.halo.setOpacity(1.0)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self.edges:
                edge.sync_position()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self._hovering = True
        self.setPen(self._pen_hover)
        self.halo.setVisible(True)
        self.halo.setOpacity(1.0)
        self.label_bg.setVisible(True)
        self.label_text.setVisible(True)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hovering = False
        self.setPen(self._pen_normal)
        self.label_bg.setVisible(False)
        self.label_text.setVisible(False)
        if not self._pulsing:
            self.halo.setVisible(False)
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):
        self.pinned = True
        self.vx = self.vy = 0.0
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.pinned = False
        super().mouseReleaseEvent(event)

    def set_radius_live(self, radius: float):
        self.setRect(QRectF(-radius, -radius, radius * 2, radius * 2))
        self.halo.setRect(QRectF(-radius * 1.6, -radius * 1.6, radius * 3.2, radius * 3.2))


class EdgeItem(QGraphicsLineItem):
    """A relationship between two nodes, drawn as a directed arrow (from
    parent -> child, showing which way the edit/derivation flows) with a
    COSMETIC pen -- setCosmetic(True) means the stroke width is specified
    in constant SCREEN pixels rather than scene units, so it stays
    visible at any zoom level instead of shrinking toward invisibility
    when zoomed out (a real bug found via direct feedback: at low zoom
    the previous non-cosmetic 1.3px scene-unit pen could render as a
    fraction of a device pixel)."""

    ARROW_LENGTH = 8.0
    ARROW_WIDTH = 6.0

    def __init__(self, node_a: NodeItem, node_b: NodeItem, dashed: bool, color: QColor,
                 rest_length: float = WEB_EDGE_REST_LENGTH, vertical_bias: bool = False):
        super().__init__()
        self.node_a = node_a
        self.node_b = node_b
        self.rest_length = rest_length
        self.vertical_bias = vertical_bias
        node_a.edges.append(self)
        node_b.edges.append(self)

        pen = QPen(color)
        pen.setWidthF(3.0 if (not dashed and color != QColor(_DEFAULT_EDGE_COLOR)) else 2.6)
        pen.setCosmetic(True)
        pen.setCapStyle(Qt.RoundCap)
        if dashed:
            pen.setStyle(Qt.DashLine)
            pen.setDashPattern([4.0, 2.5])  # denser than Qt's default dash -- a sparse dash reads as faint
        self.setPen(pen)
        self.setOpacity(EDGE_REST_OPACITY)
        self.setZValue(0)
        self._originally_dashed = dashed
        self.flow_active = False
        self.sync_position()

    def sync_position(self):
        self.setLine(QLineF(self.node_a.scenePos(), self.node_b.scenePos()))

    def set_flow_active(self, active: bool):
        """A slow animated dash-offset ('marching ants,' but gentle) on
        edges touching a recently-edited node -- suggests lineage
        actively flowing parent -> child, distinct from the static
        directed arrowhead which just shows WHICH way, not that
        something recently moved through it."""
        self.flow_active = active
        pen = self.pen()
        if active:
            pen.setStyle(Qt.CustomDashLine)
            pen.setDashPattern([2.5, 3.5])
        elif self._originally_dashed:
            pen.setStyle(Qt.CustomDashLine)
            pen.setDashPattern([4.0, 2.5])  # match the denser resting dash set in __init__
        else:
            pen.setStyle(Qt.SolidLine)
            pen.setDashOffset(0.0)
        self.setPen(pen)

    def advance_flow(self, delta: float):
        if not self.flow_active:
            return
        pen = self.pen()
        pen.setDashOffset(pen.dashOffset() + delta)
        self.setPen(pen)

    def paint(self, painter, option, widget=None):
        super().paint(painter, option, widget)
        p1, p2 = self.line().p1(), self.line().p2()
        dx, dy = p2.x() - p1.x(), p2.y() - p1.y()
        length = math.hypot(dx, dy)
        if length < 1.0:
            return
        ux, uy = dx / length, dy / length
        # Pulled back off node_b's own edge so the arrowhead sits next to
        # it rather than being swallowed underneath the node's fill.
        pullback = self.node_b.radius + 5
        if pullback >= length:
            return
        tip = QPointF(p2.x() - ux * pullback, p2.y() - uy * pullback)
        px, py = -uy, ux
        base_x = tip.x() - ux * self.ARROW_LENGTH
        base_y = tip.y() - uy * self.ARROW_LENGTH
        left = QPointF(base_x + px * self.ARROW_WIDTH * 0.5, base_y + py * self.ARROW_WIDTH * 0.5)
        right = QPointF(base_x - px * self.ARROW_WIDTH * 0.5, base_y - py * self.ARROW_WIDTH * 0.5)
        painter.setBrush(QBrush(self.pen().color()))
        painter.setPen(Qt.NoPen)
        painter.drawPolygon(QPolygonF([tip, left, right]))


class BraidEdgeItem(EdgeItem):
    """The real 'branch braid' renderer: a divergent branch's edge drawn
    as a curved strand (quadratic bezier) instead of a straight line, so
    multiple branch heads open from the same fork point visually
    separate into distinct interlocking paths rather than overlapping
    straight lines. curve_offset alternates sign/magnitude per branch
    (assigned by _compute_branch_visuals) so N simultaneous branches fan
    out distinctly instead of colliding. Physics (spring/repulsion)
    still treats the underlying node pair the same as any other edge --
    only the DRAWN path is curved, not the simulated attraction."""

    def __init__(self, node_a, node_b, color, curve_offset, rest_length, vertical_bias):
        super().__init__(node_a, node_b, dashed=False, color=color,
                          rest_length=rest_length, vertical_bias=vertical_bias)
        self.curve_offset = curve_offset
        pen = self.pen()
        pen.setWidthF(2.8)
        self.setPen(pen)

    def _control_point(self):
        p1, p2 = self.line().p1(), self.line().p2()
        mx, my = (p1.x() + p2.x()) / 2, (p1.y() + p2.y()) / 2
        dx, dy = p2.x() - p1.x(), p2.y() - p1.y()
        length = math.hypot(dx, dy) or 1.0
        px, py = -dy / length, dx / length
        return QPointF(mx + px * self.curve_offset, my + py * self.curve_offset)

    def boundingRect(self):
        p1, p2 = self.line().p1(), self.line().p2()
        cp = self._control_point()
        xs, ys = (p1.x(), p2.x(), cp.x()), (p1.y(), p2.y(), cp.y())
        pad = self.ARROW_LENGTH + 8
        return QRectF(min(xs) - pad, min(ys) - pad, max(xs) - min(xs) + 2 * pad, max(ys) - min(ys) + 2 * pad)

    def paint(self, painter, option, widget=None):
        # Deliberately does NOT call EdgeItem.paint (which draws a
        # straight line) -- draws its own curved path + arrowhead instead.
        p1, p2 = self.line().p1(), self.line().p2()
        cp = self._control_point()
        path = QPainterPath()
        path.moveTo(p1)
        path.quadTo(cp, p2)
        painter.setPen(self.pen())
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)

        # Arrowhead tangent to the curve's own end direction (control
        # point -> p2 for a quadratic bezier), not the straight p1->p2
        # chord, so it visually matches the curve it's attached to.
        dx, dy = p2.x() - cp.x(), p2.y() - cp.y()
        length = math.hypot(dx, dy)
        if length < 1.0:
            return
        ux, uy = dx / length, dy / length
        pullback = self.node_b.radius + 5
        tip = QPointF(p2.x() - ux * pullback, p2.y() - uy * pullback)
        px, py = -uy, ux
        base_x = tip.x() - ux * self.ARROW_LENGTH
        base_y = tip.y() - uy * self.ARROW_LENGTH
        left = QPointF(base_x + px * self.ARROW_WIDTH * 0.5, base_y + py * self.ARROW_WIDTH * 0.5)
        right = QPointF(base_x - px * self.ARROW_WIDTH * 0.5, base_y - py * self.ARROW_WIDTH * 0.5)
        painter.setBrush(QBrush(self.pen().color()))
        painter.setPen(Qt.NoPen)
        painter.drawPolygon(QPolygonF([tip, left, right]))


class CanvasView(QGraphicsView):
    """Owns pan/drag/zoom/drop. NoDrag mode + manual panning (rather than
    ScrollHandDrag) is what lets a click on empty canvas pan while a click
    on a NODE moves it. Right-click is handled directly in
    mousePressEvent (not via contextMenuEvent, which proved unreliable in
    practice) so the menu fires every time."""

    # Deliberately far outside any normal fit-to-view scale -- see the
    # module docstring / manual.txt for why a tighter bound here was a
    # real bug (it sat ABOVE the natural fit scale, freezing zoom-out).
    MIN_SCALE = 0.0008
    MAX_SCALE = 20.0

    zoomChanged = Signal(float)
    nodeContextMenuRequested = Signal(object, QPoint)  # (node, LOCAL viewport pos)
    filesDropped = Signal(list)
    viewChanged = Signal()
    nodeDoubleClicked = Signal(object)

    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.bg_color = QColor(BG)
        self.grid_dot_color = QColor(255, 255, 255, 12)
        self.setBackgroundBrush(QBrush(self.bg_color))
        self.setMouseTracking(True)
        self.setAcceptDrops(True)
        self.locked = False
        self._panning = False
        self._pan_last = None
        self._drag_active = False
        # valueChanged emits the new int value; viewChanged takes none --
        # connecting directly to .emit mismatches arg counts (PySide6
        # reports this as a TypeError printed to stderr on every single
        # pan/scroll rather than raising, so it's easy to miss without
        # actually watching the console -- confirmed via a real headless
        # test run, not just code review).
        self.horizontalScrollBar().valueChanged.connect(lambda _v: self.viewChanged.emit())
        self.verticalScrollBar().valueChanged.connect(lambda _v: self.viewChanged.emit())

    def apply_theme(self, bg_hex: str, grid_dot_rgba: tuple):
        self.bg_color = QColor(bg_hex)
        self.grid_dot_color = QColor(*grid_dot_rgba)
        self.setBackgroundBrush(QBrush(self.bg_color))
        self.viewport().update()

    def drawBackground(self, painter, rect):
        super().drawBackground(painter, rect)

        # Subtle vignette -- a radial gradient over the CURRENT VIEWPORT
        # (mapped to scene coords, not the full scene), so it reads as a
        # camera lens effect that stays anchored to the window rather
        # than a fixed spot on the canvas that scrolls away.
        viewport_rect = self.mapToScene(self.viewport().rect()).boundingRect()
        vignette = QRadialGradient(viewport_rect.center(), viewport_rect.width() * 0.75)
        edge_color = QColor(self.bg_color)
        edge_color.setAlpha(90)
        transparent = QColor(self.bg_color)
        transparent.setAlpha(0)
        vignette.setColorAt(0.0, transparent)
        vignette.setColorAt(1.0, edge_color)
        painter.fillRect(rect, QBrush(vignette))

        painter.setPen(QPen(self.grid_dot_color, 1))
        spacing = 60
        left = int(rect.left()) - (int(rect.left()) % spacing)
        top = int(rect.top()) - (int(rect.top()) % spacing)
        y = top
        while y < rect.bottom():
            x = left
            while x < rect.right():
                painter.drawPoint(x, y)
                x += spacing
            y += spacing

    def drawForeground(self, painter, rect):
        super().drawForeground(painter, rect)
        if self._drag_active:
            # A visible drop-zone highlight the instant an OS-level drag
            # enters the canvas -- gives immediate, unambiguous
            # confirmation the app registered the drag at the Qt/Wayland
            # protocol level, independent of whatever happens after the
            # drop itself. If this never appears while dragging a file
            # over the window, the drag isn't reaching Qt at all (a
            # compositor/desktop-environment matter, not something this
            # app's own drop handling can fix); if it DOES appear but
            # nothing happens on release, that narrows the problem to
            # the drop handler specifically.
            pen = QPen(QColor(ACCENT))
            pen.setWidth(4)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(rect.adjusted(4, 4, -4, -4))

    def wheelEvent(self, event):
        pixel_delta = event.pixelDelta()
        delta = pixel_delta.y() if not pixel_delta.isNull() else event.angleDelta().y()
        if delta == 0:
            return
        current = self.transform().m11()
        factor = math.exp(max(-300, min(300, delta)) * 0.001)
        target = max(self.MIN_SCALE, min(self.MAX_SCALE, current * factor))
        applied = target / current
        if abs(applied - 1.0) < 1e-6:
            return
        self.scale(applied, applied)
        self.zoomChanged.emit(target)
        self.viewChanged.emit()

    def _apply_zoom_factor(self, factor: float):
        current = self.transform().m11()
        target = max(self.MIN_SCALE, min(self.MAX_SCALE, current * factor))
        applied = target / current
        if abs(applied - 1.0) < 1e-6:
            return
        self.scale(applied, applied)
        self.zoomChanged.emit(target)
        self.viewChanged.emit()

    def event(self, evt):
        # A real trackpad's native PINCH gesture (the natural, expected
        # way most people zoom on a touchpad -- distinct from a two-
        # finger vertical SCROLL, which wheelEvent above already
        # handles) arrives as QEvent.NativeGesture, a completely
        # different event type that wheelEvent alone never sees. Without
        # this, pinch-to-zoom does nothing at all in this app regardless
        # of how well wheelEvent is tuned -- found by reasoning through
        # what "still can't zoom easily with my touchpad" most likely
        # meant after the wheel-delta fix, not by direct observation.
        if evt.type() == QEvent.NativeGesture and evt.gestureType() == Qt.ZoomNativeGesture:
            self._apply_zoom_factor(1.0 + evt.value())
            return True
        return super().event(evt)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            item = self.itemAt(event.pos())
            node = item
            while node is not None and not isinstance(node, NodeItem):
                node = node.parentItem()
            if node is not None:
                self.nodeDoubleClicked.emit(node)
                event.accept()
                return
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.RightButton:
            item = self.itemAt(event.pos())
            node = item
            while node is not None and not isinstance(node, NodeItem):
                node = node.parentItem()
            if node is not None:
                self.nodeContextMenuRequested.emit(node, event.pos())
            event.accept()
            return
        if event.button() == Qt.LeftButton:
            item = self.itemAt(event.pos())
            if item is None or self.locked:
                self._panning = True
                self._pan_last = event.position()
                self.setCursor(Qt.ClosedHandCursor)
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._panning:
            pos = event.position()
            delta = pos - self._pan_last
            self._pan_last = pos
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - int(delta.x()))
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - int(delta.y()))
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._panning and event.button() == Qt.LeftButton:
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._drag_active = True
            self.viewport().update()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dragLeaveEvent(self, event):
        self._drag_active = False
        self.viewport().update()
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        self._drag_active = False
        self.viewport().update()
        if event.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile() and u.toLocalFile()]
            if paths:
                self.filesDropped.emit(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class MinimapView(QGraphicsView):
    """A small always-visible overview sharing the SAME QGraphicsScene as
    the main view (Qt supports multiple views on one scene natively --
    no separate copy of the graph to keep in sync). drawForeground paints
    a rectangle showing the main view's current visible region."""

    def __init__(self, scene, main_view: CanvasView, parent=None):
        super().__init__(scene, parent)
        self.main_view = main_view
        self.setRenderHint(QPainter.Antialiasing)
        self.setFixedSize(220, 150)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setInteractive(False)
        self.setStyleSheet(f"border: 1px solid {BORDER}; background: {BG};")
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def refresh_extent(self):
        rect = self.scene().itemsBoundingRect()
        if not rect.isEmpty():
            self.fitInView(rect.adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)
        self.viewport().update()

    def drawForeground(self, painter, rect):
        super().drawForeground(painter, rect)
        visible = self.main_view.mapToScene(self.main_view.viewport().rect()).boundingRect()
        pen = QPen(QColor(ACCENT))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawRect(visible)


# ---------- command palette ("Lineage Shell") ----------
# Every command below routes to a real VaultSession call or an existing
# window method -- there is no separate, unreviewed command-only code
# path. Handlers take (window, *args); a wrong argument count raises
# TypeError, which the palette turns into a usage hint rather than a
# traceback.

def _cmd_write(window, label=None):
    path, _ = QFileDialog.getOpenFileName(window, "Choose a file to add")
    if not path:
        return
    label = label or window._unique_label_from_path(path)
    window._perform_write_and_animate(lambda: window.engine.commit_write(label, path))
    window._toast(f"Added '{label}'")


def _cmd_delete(window, label):
    window._delete_label(label)


def _cmd_rename(window, old, new):
    window._rename_label_direct(old, new)


def _cmd_duplicate(window, label, new_label):
    window._duplicate_label_direct(label, new_label)


def _cmd_fork(window, label, generation):
    window._fork_from_generation_action(label, int(generation))


def _cmd_merge(window, label):
    window._merge_action_for_label(label)


def _cmd_graft(window, label_a, label_b, new_label):
    window._perform_write_and_animate(
        lambda: window.engine.graft(label_a, label_b, new_label)
    )
    window._toast(f"Grafted '{label_a}' + '{label_b}' -> '{new_label}'")


def _parse_tag_value(raw):
    """'true'/'false'/'yes'/'no'/'1'/'0' (case-insensitive) become real
    booleans -- matching pfs_cli.py's own _parse_tag_value exactly, and
    necessary for cross-engine consistency: Python's own 'protected'/
    'no_graft_source' enforcement checks a tag's truthiness (a non-empty
    STRING "true" would already count), but the C++ engine's enforcement
    checks for a real boolean specifically -- passing the bare string
    through would silently fail to protect a label on the C++ engine
    while appearing to work on the Python one."""
    if not isinstance(raw, str):
        return raw
    lowered = raw.lower()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    return raw


def _cmd_tag(window, label, key, value="true"):
    window.engine.set_tag(label, key, _parse_tag_value(value))
    window._toast(f"Tagged '{label}': {key}={value}")
    window._rebuild()


def _cmd_untag(window, label, key):
    window.engine.remove_tag(label, key)
    window._toast(f"Untagged '{label}': {key}")
    window._rebuild()


def _cmd_prune(window, label, generation):
    window._prune_generation_action(label, int(generation))


def _cmd_checkout(window, label, generation):
    window._checkout_generation(label, int(generation))


def _cmd_edit(window, label):
    window._edit_label(label)


def _cmd_view(window, label):
    window._view_label(label)


def _cmd_edit_inapp(window, label):
    window._edit_label_inapp(label)


def _cmd_view_image(window, label):
    window._view_image_inapp(label)


def _cmd_search(window, *text_parts):
    window.search_box.setText(" ".join(text_parts))


def _cmd_focus(window):
    window._fit_to_view()


def _cmd_web(window):
    window._set_mode("web")


def _cmd_tree(window):
    window._set_mode("tree")


def _cmd_cladetree(window):
    window._set_mode("cladetree")


def _cmd_upgma(window):
    window._set_clade_algorithm("upgma")


def _cmd_nj(window):
    window._set_clade_algorithm("nj")


def _cmd_export(window):
    window._export_canvas()


def _cmd_sort(window, *_args):
    window.list_action.setChecked(True)
    window.list_table.setFocus()


COMMAND_REGISTRY = {
    "write": ("[label]", _cmd_write),
    "delete": ("<label>", _cmd_delete),
    "rename": ("<old> <new>", _cmd_rename),
    "duplicate": ("<label> <new_label>", _cmd_duplicate),
    "fork": ("<label> <generation>", _cmd_fork),
    "merge": ("<label>", _cmd_merge),
    "graft": ("<label_a> <label_b> <new_label>", _cmd_graft),
    "tag": ("<label> <key> [value]", _cmd_tag),
    "untag": ("<label> <key>", _cmd_untag),
    "prune": ("<label> <generation>", _cmd_prune),
    "checkout": ("<label> <generation>", _cmd_checkout),
    "edit": ("<label>", _cmd_edit),
    "view": ("<label>", _cmd_view),
    "editinapp": ("<label>", _cmd_edit_inapp),
    "viewimage": ("<label>", _cmd_view_image),
    "search": ("<text>", _cmd_search),
    "focus": ("", _cmd_focus),
    "web": ("", _cmd_web),
    "tree": ("", _cmd_tree),
    "cladetree": ("", _cmd_cladetree),
    "upgma": ("", _cmd_upgma),
    "nj": ("", _cmd_nj),
    "export": ("", _cmd_export),
    "sort": ("", _cmd_sort),
}


class CommandPalette(QDialog):
    """The real 'Lineage Shell': Ctrl+K opens a typed-command box over
    the canvas. Every command name filters as you type; Enter runs the
    top/selected suggestion's underlying handler against the real
    VaultSession -- no separate simulation of what the CLI does."""

    def __init__(self, window):
        super().__init__(window, Qt.Popup)
        self.window = window
        self.setStyleSheet(
            f"QDialog {{ background: {INPUT_BG}; border: 1px solid {ACCENT}; border-radius: 10px; }}"
            f"QListWidget {{ background: {INPUT_BG}; color: {TEXT}; border: none; }}"
            f"QListWidget::item:selected {{ background: {ACCENT_DIM}; }}"
        )
        self.setFixedWidth(560)
        layout = QVBoxLayout(self)
        self.input = QLineEdit(self)
        self.input.setPlaceholderText(
            "Type a command: write, delete, rename, duplicate, fork, merge, graft, tag, "
            "prune, checkout, edit, search, focus, web, tree, cladetree, upgma, nj, export, sort"
        )
        self.input.textChanged.connect(self._update_suggestions)
        self.input.returnPressed.connect(self._execute)
        layout.addWidget(self.input)
        self.suggestions = QListWidget(self)
        self.suggestions.setMaximumHeight(240)
        layout.addWidget(self.suggestions)
        self._update_suggestions("")

    def _update_suggestions(self, text):
        self.suggestions.clear()
        cmd = text.split()[0].lower() if text.split() else ""
        for name, (usage, _fn) in sorted(COMMAND_REGISTRY.items()):
            if not cmd or name.startswith(cmd):
                self.suggestions.addItem(f"{name}  {usage}".strip())

    def _execute(self):
        text = self.input.text().strip()
        self.close()
        if not text:
            return
        parts = text.split()
        cmd, args = parts[0].lower(), parts[1:]
        entry = COMMAND_REGISTRY.get(cmd)
        if entry is None:
            self.window._toast(f"Unknown command: '{cmd}' (Ctrl+K to see the list)")
            return
        usage, fn = entry
        try:
            fn(self.window, *args)
        except TypeError:
            self.window._toast(f"Usage: {cmd} {usage}")
        except (KeyError, ValueError) as e:
            self.window._toast(f"'{cmd}' failed: {e}")


# ---------- in-app editors (real-time, no external process/watcher/poll) ----------

class InAppTextEditorDialog(QDialog):
    """A genuine in-process editor: Save writes straight through
    on_save_callback (which calls commit_write directly, in the same
    Python process, no temp-file watcher, no polling, no external app at
    all) -- so the canvas update is exactly as fast as any other write
    action already is, closing the whole class of external-editor
    reliability problems (Snap sandboxing, multi-tab tracking, save
    detection lag) for the single most common case: plain text.
    Non-modal (persists after Save) so you can keep editing and save
    again -- each Save is its own new generation, same as saving
    multiple times in any real editor."""

    def __init__(self, parent, label: str, initial_text: str, on_save_callback):
        super().__init__(parent)
        self.setWindowTitle(f"Edit -- {label}")
        self.resize(760, 600)
        self._on_save_callback = on_save_callback
        self._label = label

        layout = QVBoxLayout(self)
        self.editor = QPlainTextEdit(self)
        self.editor.setPlainText(initial_text)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.TypeWriter)
        mono.setPointSize(11)
        self.editor.setFont(mono)
        layout.addWidget(self.editor)

        button_row = QHBoxLayout()
        self.status_label = QLabel("", self)
        button_row.addWidget(self.status_label)
        button_row.addStretch(1)
        save_button = QPushButton("Save  (Ctrl+S)", self)
        save_button.clicked.connect(self._save)
        button_row.addWidget(save_button)
        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)
        button_row.addWidget(close_button)
        layout.addLayout(button_row)

        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self._save)

    def _save(self):
        text = self.editor.toPlainText()
        try:
            self._on_save_callback(text)
            self.status_label.setText("Saved -- new generation created")
        except Exception as e:
            self.status_label.setText(f"Save failed: {e}")


class ImageViewerDialog(QDialog):
    """Read-only, in-app, instant -- no external app, no temp-file
    lifecycle to manage at all beyond the one reconstruction that
    already happened before this dialog was created."""

    def __init__(self, parent, label: str, image_bytes: bytes):
        super().__init__(parent)
        self.setWindowTitle(f"View -- {label}")
        self.resize(820, 640)
        layout = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        content = QLabel(self)
        content.setAlignment(Qt.AlignCenter)
        pixmap = QPixmap()
        if pixmap.loadFromData(image_bytes):
            content.setPixmap(pixmap)
        else:
            content.setText("Couldn't decode this image's content.")
        scroll.setWidget(content)
        layout.addWidget(scroll)
        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)


class ChunkMapWidget(QWidget):
    """The universal, always-correct visualization for a lineage diff:
    one colored cell per chunk POSITION, ordered exactly like the real
    manifests (green = new/mutated since the older generation, red =
    present in the older generation but gone from the newer one, gray =
    unchanged) -- works for ANY content type, including binary, unlike
    a text-line diff which only makes sense for text. Sized
    proportionally to the widget's own width; segments thinner than a
    pixel are simply merged visually (still painted, just not
    individually distinguishable), which is the correct degradation for
    a file with thousands of chunks."""

    def __init__(self, positions, parent=None):
        super().__init__(parent)
        self.positions = positions
        self.setMinimumHeight(46)
        self.setMouseTracking(True)
        self._last_hover_index = None

    def _color_for(self, status):
        return {
            lineage_diff.UNCHANGED: _DIFF_UNCHANGED_COLOR,
            lineage_diff.CHANGED: _DIFF_CHANGED_COLOR,
            lineage_diff.NEW: _DIFF_NEW_COLOR,
            lineage_diff.DELETED: _DIFF_DELETED_COLOR,
        }[status]

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)
        w, h = self.width(), self.height()
        n = len(self.positions)
        if n == 0:
            painter.fillRect(0, 0, w, h, QColor(_DIFF_UNCHANGED_COLOR))
            painter.end()
            return
        cell_w = w / n
        for pos in self.positions:
            x0 = pos.index * cell_w
            x1 = (pos.index + 1) * cell_w
            painter.fillRect(QRectF(x0, 0, max(x1 - x0, 1.0), h), QColor(self._color_for(pos.status)))
        painter.end()

    def mouseMoveEvent(self, event):
        n = len(self.positions)
        if n == 0 or self.width() <= 0:
            return
        index = int(event.position().x() / self.width() * n)
        index = max(0, min(n - 1, index))
        if index != self._last_hover_index:
            self._last_hover_index = index
            pos = self.positions[index]
            old_hex = pos.old_hash.hex()[:12] + "..." if pos.old_hash else "(absent)"
            new_hex = pos.new_hash.hex()[:12] + "..." if pos.new_hash else "(absent)"
            QToolTip.showText(event.globalPosition().toPoint(),
                               f"chunk {index}: {pos.status}\nold: {old_hex}\nnew: {new_hex}", self)

    def leaveEvent(self, event):
        self._last_hover_index = None
        QToolTip.hideText()


class LineageDiffDialog(QDialog):
    """Renders a real lineage diff between two generations of the SAME
    label -- the chunk-map (always shown, correct for any content type)
    plus, as a bonus when both generations decode as text, a real
    difflib line-level diff. Deliberately a separate dialog/code path
    from the existing clade-similarity comparison panel
    (_show_diff_between's _render_cards call) -- see lineage_diff.py's
    module docstring for why the two must not be conflated."""

    def __init__(self, parent, result: "lineage_diff.LineageDiffResult", theme_colors: dict,
                 text_diff_lines=None):
        super().__init__(parent)
        self.result = result  # kept for tests/callers that want the structured result, not just the rendering
        self.setWindowTitle(f"Lineage diff -- '{result.label}' gen {result.generation_old} -> "
                             f"gen {result.generation_new}")
        self.resize(880, 620)
        c = theme_colors
        layout = QVBoxLayout(self)

        summary = QLabel(
            f"'{result.label}': generation {result.generation_old} → generation {result.generation_new}"
            f"  --  {result.total_old} → {result.total_new} chunks", self)
        summary.setStyleSheet(f"color:{c['text']}; font-size:13px; font-weight:600;")
        layout.addWidget(summary)

        if result.identical:
            legend_text = "No mutation between these two generations -- every chunk position is identical."
        else:
            legend_text = (f"<span style='color:{_DIFF_CHANGED_COLOR};'>■ mutated</span> &nbsp; "
                            f"<span style='color:{_DIFF_NEW_COLOR};'>■ new</span> &nbsp; "
                            f"<span style='color:{_DIFF_DELETED_COLOR};'>■ deleted</span> &nbsp; "
                            f"<span style='color:{_DIFF_UNCHANGED_COLOR};'>■ unchanged</span> &nbsp;&nbsp; "
                            f"{result.changed_count} mutated, {result.new_count} new, "
                            f"{result.deleted_count} deleted, {result.unchanged_count} unchanged")
        legend = QLabel(legend_text, self)
        legend.setTextFormat(Qt.RichText)
        legend.setStyleSheet(f"color:{c['dim']}; font-size:11px;")
        layout.addWidget(legend)

        chunk_map = ChunkMapWidget(result.positions, self)
        chunk_map.setStyleSheet(f"background:{c['panel']}; border:1px solid {c['border']}; border-radius:6px;")
        layout.addWidget(chunk_map)

        if text_diff_lines is not None:
            text_label = QLabel("Line-level diff (bonus -- both generations decode as text):", self)
            text_label.setStyleSheet(f"color:{c['dim']}; font-size:11px; margin-top:6px;")
            layout.addWidget(text_label)
            text_view = QTextEdit(self)
            text_view.setReadOnly(True)
            text_view.setStyleSheet(f"font-family: monospace; font-size:12px; background:{c['panel']}; "
                                     f"color:{c['text']}; border:1px solid {c['border']};")
            html_lines = []
            for line in text_diff_lines:
                escaped = (line.rstrip("\n").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
                if line.startswith("+") and not line.startswith("+++"):
                    html_lines.append(f'<div style="color:{_DIFF_CHANGED_COLOR};">{escaped}</div>')
                elif line.startswith("-") and not line.startswith("---"):
                    html_lines.append(f'<div style="color:{_DIFF_DELETED_COLOR};">{escaped}</div>')
                elif line.startswith("@@"):
                    html_lines.append(f'<div style="color:{c["accent"]};">{escaped}</div>')
                else:
                    html_lines.append(f'<div style="color:{c["dim"]};">{escaped}</div>')
            text_view.setHtml("".join(html_lines) if html_lines else "(no line-level differences)")
            layout.addWidget(text_view, stretch=1)

        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)


# ---------- main window ----------

class VaultGraphWindow(QMainWindow):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.engine.start_clade_worker()
        self._clade_version_drawn = None
        self.setWindowTitle("Phylogenetic File System")
        self.resize(1440, 940)
        self.setAcceptDrops(True)  # defensive: drops are handled by self.view, but some
        # compositors key drop-target advertisement off the TOPLEVEL surface's own flag too

        self._mode = "web"
        self._clade_algorithm = "upgma"
        self._node_items = {}
        self._edge_items = []
        self._clade_blob_items = []
        self._clade_membership = {}     # label -> clade_key, only for multi-member (drawn) clades
        self._clade_leash_radius = {}   # clade_key -> containment radius
        self._empty_state_item = None
        self._time_bounds = None
        self._time_cutoff = None
        self._time_machine_histories = {}
        self._syncing_zoom = False
        self._active_animations = []
        self._pending_timers = []  # delayed one-shot timers not yet fired (e.g. staggered particle starts)
        # label -> list of {"path", "watcher", "last_mtime"} -- a LIST, not a
        # single session, because re-clicking Edit on an already-open label
        # (a second temp file/editor tab) used to silently orphan the first
        # one from tracking; if the user then saved in that first tab, it
        # vanished with no error and no toast. Now every open session for a
        # label stays tracked until its temp file's gone, so any of them
        # being saved -- even an "old" tab the user went back to -- still
        # lands as a new generation.
        self._edit_sessions = {}
        self._active_dialogs = []  # keeps non-modal in-app editor/viewer dialogs alive (Qt parenting alone isn't enough to stop Python GC of the wrapper)

        self.scene = QGraphicsScene(self)
        self.scene.selectionChanged.connect(self._on_selection_changed)
        self.view = CanvasView(self.scene, self)
        self.view.zoomChanged.connect(self._on_view_zoom_changed)
        self.view.nodeContextMenuRequested.connect(self._show_node_context_menu)
        self.view.filesDropped.connect(self._on_files_dropped)
        self.view.viewChanged.connect(self._on_main_view_changed)
        self.view.nodeDoubleClicked.connect(self._zoom_to_node)
        self.setCentralWidget(self.view)

        self._build_toolbar()
        self._build_dock()
        self._build_list_dock()
        self._build_statusbar()
        self._build_time_bar()
        self._build_minimap()
        self._build_toast()

        palette_action = QAction("Command Palette", self)
        palette_action.setShortcut(QKeySequence("Ctrl+K"))
        palette_action.triggered.connect(self._open_command_palette)
        self.addAction(palette_action)

        self._physics_paused = False
        self._tick_times = []

        self._physics_timer = QTimer(self)
        self._physics_timer.timeout.connect(self._physics_tick)
        self._physics_timer.start(33)

        self._edit_poll_timer = QTimer(self)
        self._edit_poll_timer.timeout.connect(self._poll_edited_files)
        self._edit_poll_timer.start(1500)
        # Redraw the clade outlines when the background clade worker
        # publishes a newer partition (e.g. a recompute that finished
        # after the last redraw).
        self._clade_poll_timer = QTimer(self)
        self._clade_poll_timer.timeout.connect(self._poll_clade_updates)
        self._clade_poll_timer.start(700)

        self._rebuild()
        self._maybe_show_tour()

    # ---------- chrome ----------

    def _build_toolbar(self):
        toolbar = QToolBar("View", self)
        toolbar.setMovable(False)

        focus_action = QAction("⌂  Focus", self)
        focus_action.setToolTip("Reset pan/zoom to fit every node on screen (Home)")
        focus_action.setShortcut(QKeySequence(Qt.Key_Home))
        focus_action.triggered.connect(self._fit_to_view_animated)
        toolbar.addAction(focus_action)
        toolbar.addSeparator()

        self.web_action = QAction("◎  Web", self, checkable=True)
        self.tree_action = QAction("⑂  Tree", self, checkable=True)
        self.cladetree_action = QAction("🧬  Clade Tree", self, checkable=True)
        self.web_action.setToolTip("Cosmic Web: one node per file, clustered by similarity")
        self.tree_action.setToolTip("Lineage Tree: every generation of every file, real genealogy")
        self.cladetree_action.setToolTip("Clade Tree: a real UPGMA/NJ dendrogram over your files")
        self.web_action.setChecked(True)
        mode_group = QActionGroup(self)
        for a in (self.web_action, self.tree_action, self.cladetree_action):
            mode_group.addAction(a)
        mode_group.setExclusive(True)
        self.web_action.triggered.connect(lambda: self._set_mode("web"))
        self.tree_action.triggered.connect(lambda: self._set_mode("tree"))
        self.cladetree_action.triggered.connect(lambda: self._set_mode("cladetree"))
        toolbar.addAction(self.web_action)
        toolbar.addAction(self.tree_action)
        toolbar.addAction(self.cladetree_action)
        toolbar.addSeparator()

        self.upgma_action = QAction("UPGMA", self, checkable=True)
        self.nj_action = QAction("NJ", self, checkable=True)
        self.upgma_action.setToolTip("Cluster assuming a constant mutation rate (ultrametric tree)")
        self.nj_action.setToolTip("Cluster WITHOUT assuming a constant rate -- watch the shape change")
        self.upgma_action.setChecked(True)
        algo_group = QActionGroup(self)
        algo_group.addAction(self.upgma_action)
        algo_group.addAction(self.nj_action)
        algo_group.setExclusive(True)
        self.upgma_action.triggered.connect(lambda: self._set_clade_algorithm("upgma"))
        self.nj_action.triggered.connect(lambda: self._set_clade_algorithm("nj"))
        toolbar.addAction(self.upgma_action)
        toolbar.addAction(self.nj_action)
        toolbar.addSeparator()

        self.clade_action = QAction("⬡  Outline", self, checkable=True)
        self.clade_action.setToolTip("Outline detected clades (web mode) and list their members")
        self.clade_action.toggled.connect(self._on_clade_toggle)
        toolbar.addAction(self.clade_action)

        self.swirl_action = QAction("🌌  Swirl", self, checkable=True)
        self.swirl_action.setChecked(True)
        self.swirl_action.setToolTip("Slow galaxy-like rotation of the whole layout (web mode only)")
        toolbar.addAction(self.swirl_action)

        self.heatmap_action = QAction("🔥  Dedup Heat", self, checkable=True)
        self.heatmap_action.setToolTip("Recolor nodes by shared vs. genuinely unique content")
        self.heatmap_action.toggled.connect(lambda _checked: self._rebuild())
        toolbar.addAction(self.heatmap_action)
        toolbar.addSeparator()

        self.search_box = QLineEdit(self)
        self.search_box.setPlaceholderText("Search by label...")
        self.search_box.setFixedWidth(180)
        self.search_box.textChanged.connect(self._apply_search_filter)
        toolbar.addWidget(self.search_box)
        toolbar.addSeparator()

        new_file_action = QAction("＋ New File(s)", self)
        new_file_action.setToolTip("Write one or more files from disk into the vault (or drop them on the canvas)")
        new_file_action.triggered.connect(self._new_file_dialog)
        toolbar.addAction(new_file_action)

        export_action = QAction("⭳ Export PNG", self)
        export_action.setToolTip("Save the current canvas as an image")
        export_action.triggered.connect(self._export_canvas)
        toolbar.addAction(export_action)
        toolbar.addSeparator()

        self.list_action = QAction("☰  Sort/List", self, checkable=True)
        self.list_action.setToolTip("Toggle a sortable table of every file -- click a column header to sort")
        self.list_action.toggled.connect(lambda checked: self.list_dock.setVisible(checked))
        toolbar.addAction(self.list_action)

        palette_toolbar_action = QAction("⌘ Palette", self)
        palette_toolbar_action.setToolTip("Command palette (Ctrl+K) -- type any command: write, delete, "
                                           "rename, duplicate, fork, merge, graft, tag, prune, checkout, edit...")
        palette_toolbar_action.triggered.connect(self._open_command_palette)
        toolbar.addAction(palette_toolbar_action)

        self.theme_action = QAction("☀  Light", self, checkable=True)
        self.theme_action.setToolTip("Switch between dark and light theme")
        self.theme_action.toggled.connect(self._on_theme_toggled)
        toolbar.addAction(self.theme_action)

        self.addToolBar(toolbar)

    def _build_dock(self):
        self.info_panel = QTextEdit(self)
        self.info_panel.setReadOnly(True)
        self.info_panel.setFixedWidth(340)
        dock = QDockWidget("Details", self)
        dock.setWidget(self.info_panel)
        dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

    def _build_list_dock(self):
        container = QWidget(self)  # background comes from the app-wide QWidget rule -- re-themes automatically
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        hint = QLabel("💡 Click a column header to sort (click again to reverse). Click a row to find it on the canvas.", self)
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {ACCENT}; font-size: 11px; padding: 4px;")
        layout.addWidget(hint)

        self.list_table = QTableWidget(0, 5, self)
        self.list_table.setHorizontalHeaderLabels(["Label", "Type", "Size", "Dedup %", "Generations"])
        self.list_table.setSortingEnabled(True)
        self.list_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.list_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.list_table.itemSelectionChanged.connect(self._on_list_selection_changed)
        header = self.list_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for col in (1, 2, 3, 4):
            header.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        header.setSortIndicatorShown(True)
        header.setCursor(Qt.PointingHandCursor)
        # Styling comes from the app-wide stylesheet (_build_stylesheet's
        # QTableWidget/QHeaderView rules) rather than a local override
        # here, specifically so the Sort/List view re-themes correctly
        # when Light/Dark is toggled instead of staying stuck dark.
        layout.addWidget(self.list_table)

        self.list_dock = QDockWidget("Files -- Sort View", self)
        self.list_dock.setWidget(container)
        self.list_dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.list_dock.setMinimumWidth(340)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.list_dock)
        self.list_dock.setVisible(False)

    def _build_statusbar(self):
        self.status = QStatusBar(self)
        self.setStatusBar(self.status)

        self.stats_label = QLabel("", self)
        self.status.addWidget(self.stats_label)

        self.zoom_slider = QSlider(Qt.Horizontal, self)
        self.zoom_slider.setFixedWidth(140)
        self.zoom_slider.setRange(0, 1000)
        self.zoom_slider.setValue(self._scale_to_slider(1.0))
        self.zoom_slider.valueChanged.connect(self._on_slider_changed)

        self.lock_button = QPushButton("🔓", self)
        self.lock_button.setCheckable(True)
        self.lock_button.setFixedWidth(34)
        self.lock_button.setToolTip("Lock node positions -- disables dragging, every drag pans instead")
        self.lock_button.toggled.connect(self._on_lock_toggled)

        self.physics_pause_button = QPushButton("⏸", self)
        self.physics_pause_button.setCheckable(True)
        self.physics_pause_button.setFixedWidth(34)
        self.physics_pause_button.setToolTip("Pause the live physics simulation (repulsion/springs/orbit/containment)")
        self.physics_pause_button.toggled.connect(self._on_physics_pause_toggled)

        self.perf_label = QLabel("", self)
        self.perf_label.setToolTip(
            "Cost of one _physics_tick() call, averaged over the last 30 ticks -- "
            "useful for spotting what to profile before the C/C++ rewrite"
        )

        self.status.addPermanentWidget(self.perf_label)
        self.status.addPermanentWidget(QLabel("Zoom", self))
        self.status.addPermanentWidget(self.zoom_slider)
        self.status.addPermanentWidget(self.lock_button)
        self.status.addPermanentWidget(self.physics_pause_button)

    def _build_time_bar(self):
        time_bar = QToolBar("Time Machine", self)
        time_bar.setMovable(False)
        time_bar.addWidget(QLabel("⏱  Time Machine:", self))
        self.time_slider = QSlider(Qt.Horizontal, self)
        self.time_slider.setRange(0, 1000)
        self.time_slider.setValue(1000)
        self.time_slider.setFixedWidth(320)
        self.time_slider.valueChanged.connect(self._on_time_slider_changed)
        time_bar.addWidget(self.time_slider)
        self.time_label = QLabel("now", self)
        self.time_label.setMinimumWidth(170)
        time_bar.addWidget(self.time_label)
        self.addToolBar(Qt.BottomToolBarArea, time_bar)

    def _build_minimap(self):
        self.minimap = MinimapView(self.scene, self.view, self.view)
        self.minimap.move(12, 12)
        self.minimap.raise_()

    def _build_toast(self):
        self.toast_label = QLabel("", self.view)
        self.toast_label.setStyleSheet(
            f"background: {INPUT_BG}; color: {TEXT}; border: 1px solid {ACCENT}; "
            f"border-radius: 8px; padding: 8px 16px; font-size: 12px;"
        )
        self.toast_label.hide()
        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(self.toast_label.hide)

    def _toast(self, message: str):
        self.toast_label.setText(message)
        self.toast_label.adjustSize()
        x = max(8, (self.view.width() - self.toast_label.width()) // 2)
        y = max(8, self.view.height() - 76)
        self.toast_label.move(x, y)
        self.toast_label.show()
        self.toast_label.raise_()
        self._toast_timer.start(3000)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "toast_label") and self.toast_label.isVisible():
            x = max(8, (self.view.width() - self.toast_label.width()) // 2)
            y = max(8, self.view.height() - 76)
            self.toast_label.move(x, y)

    def _maybe_show_tour(self):
        """A dismissible first-launch overlay -- helps a first-time
        viewer (a portfolio reviewer, e.g.) understand the interface in
        seconds instead of hunting through toolbar tooltips. Shown once
        per VAULT (not once per app install), tracked via a small marker
        file alongside the vault's own housekeeping files
        (.fuse_scratch/, catalog.enc, etc.) -- deliberately not something
        that needs its own settings/config system."""
        marker_path = os.path.join(self.engine.storage_root, ".gui_tour_seen")
        if os.path.exists(marker_path):
            return

        overlay = QWidget(self.view)
        overlay.setAutoFillBackground(True)
        overlay.setStyleSheet(
            f"background: rgba(20, 22, 29, 245); border: 1px solid {ACCENT}; border-radius: 14px;"
        )
        layout = QVBoxLayout(overlay)
        layout.setContentsMargins(26, 22, 26, 20)
        layout.setSpacing(12)

        title = QLabel("Welcome to the Cosmic Web", overlay)
        title.setStyleSheet(f"color: {ACCENT}; font-size: 17px; font-weight: 700; background: transparent;")
        layout.addWidget(title)

        for tip in [
            "⌂ Focus resets the view; double-click any node to zoom in on it",
            "◎ Web / ⑂ Tree / 🧬 Clade Tree -- three ways to see the same vault",
            "Right-click a node for actions: Edit, Rename, Duplicate, Merge...",
            "Drag a node to move it -- its neighbors react in real time",
            "⌘K (or the Palette button) opens the command line for everything",
            "The bottom slider is a real Time Machine, not just a filter",
        ]:
            lbl = QLabel(tip, overlay)
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color: {TEXT}; font-size: 13px; background: transparent; padding: 3px 0;")
            layout.addWidget(lbl)

        button = QPushButton("Got it", overlay)
        button.setFixedWidth(100)
        button.setFixedHeight(30)

        def dismiss():
            try:
                with open(marker_path, "w") as f:
                    f.write("seen")
            except OSError:
                pass
            overlay.deleteLater()

        button.clicked.connect(dismiss)
        layout.addSpacing(4)
        layout.addWidget(button, alignment=Qt.AlignRight)

        overlay.setFixedWidth(460)
        overlay.adjustSize()
        overlay.move(24, 24)
        overlay.show()
        overlay.raise_()

    def _on_main_view_changed(self):
        if hasattr(self, "minimap"):
            self.minimap.viewport().update()

    # ---------- zoom slider <-> view sync ----------

    def _scale_to_slider(self, scale: float) -> int:
        scale = max(CanvasView.MIN_SCALE, min(CanvasView.MAX_SCALE, scale))
        ratio = math.log(scale / CanvasView.MIN_SCALE) / math.log(CanvasView.MAX_SCALE / CanvasView.MIN_SCALE)
        return int(ratio * 1000)

    def _slider_to_scale(self, value: int) -> float:
        ratio = value / 1000
        return CanvasView.MIN_SCALE * (CanvasView.MAX_SCALE / CanvasView.MIN_SCALE) ** ratio

    def _on_view_zoom_changed(self, scale: float):
        self._syncing_zoom = True
        self.zoom_slider.setValue(self._scale_to_slider(scale))
        self._syncing_zoom = False

    def _on_slider_changed(self, value: int):
        if self._syncing_zoom:
            return
        current = self.view.transform().m11()
        if current <= 0:
            return
        target = self._slider_to_scale(value)
        self.view.scale(target / current, target / current)
        self.view.viewChanged.emit()

    def _on_lock_toggled(self, checked: bool):
        self.view.locked = checked
        self.lock_button.setText("🔒" if checked else "🔓")

    def _on_physics_pause_toggled(self, checked: bool):
        self._physics_paused = checked
        self.physics_pause_button.setText("▶" if checked else "⏸")
        if checked:
            self.perf_label.setText("physics paused")

    def _on_theme_toggled(self, checked: bool):
        app = QApplication.instance()
        self._light_theme = checked
        if checked:
            app.setStyleSheet(LIGHT_STYLESHEET)
            self.view.apply_theme(LIGHT_BG, (0, 0, 0, 18))
            self.theme_action.setText("🌙  Dark")
        else:
            app.setStyleSheet(STYLESHEET)
            self.view.apply_theme(BG, (255, 255, 255, 12))
            self.theme_action.setText("☀  Light")
        self.minimap.refresh_extent()
        self._refresh_details_panel_theme()

    def _theme_colors(self):
        if getattr(self, "_light_theme", False):
            return {"panel": LIGHT_INPUT_BG, "border": LIGHT_BORDER, "text": LIGHT_TEXT,
                     "dim": LIGHT_TEXT_DIM, "accent": LIGHT_ACCENT}
        return {"panel": INPUT_BG, "border": BORDER, "text": TEXT, "dim": TEXT_DIM, "accent": ACCENT}

    def _render_cards(self, title, cards):
        """Renders the Details panel as a stack of visually distinct
        rounded 'cards' (a heading + a small key/value table each)
        instead of a flat wall of plain text -- an inspector-panel look
        closer to Figma/Blender's properties sidebar. `cards` is a list
        of {"heading": str, "rows": [(key, value), ...], "note": str?}."""
        c = self._theme_colors()
        parts = [f'<div style="font-family: sans-serif; color:{c["text"]};">']
        parts.append(f'<div style="font-size:14px; font-weight:600; margin-bottom:12px; '
                      f'color:{c["accent"]};">{title}</div>')
        for card in cards:
            parts.append(f'<div style="background:{c["panel"]}; border:1px solid {c["border"]}; '
                          f'border-radius:8px; padding:10px 12px; margin-bottom:10px;">')
            parts.append(f'<div style="font-size:10px; font-weight:700; color:{c["dim"]}; '
                          f'letter-spacing:0.5px; margin-bottom:6px;">{card["heading"].upper()}</div>')
            rows = card.get("rows", [])
            if rows:
                parts.append('<table width="100%" cellspacing="0" cellpadding="2">')
                for key, value in rows:
                    parts.append(f'<tr><td style="font-size:12px; color:{c["dim"]};">{key}</td>'
                                  f'<td align="right" style="font-size:12px; color:{c["text"]};">{value}</td></tr>')
                parts.append('</table>')
            if card.get("note"):
                parts.append(f'<div style="font-size:11px; color:{c["dim"]}; margin-top:4px;">{card["note"]}</div>')
            parts.append('</div>')
        parts.append('</div>')
        self.info_panel.setHtml("".join(parts))

    def _refresh_details_panel_theme(self):
        """Re-render whatever's currently selected so a theme toggle
        doesn't leave stale colors in the details panel until the next
        click."""
        selected = self.scene.selectedItems()
        if selected:
            self._on_selection_changed()

    def _fit_to_view(self):
        """Instant -- used right after a rebuild (mode switch, search,
        most write actions), where an animated fly-to would be
        distracting rather than polished since the scene just changed
        out from under the user anyway."""
        target = self.scene.itemsBoundingRect()
        if target.isEmpty():
            return
        self.view.fitInView(target.adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)
        self._on_view_zoom_changed(self.view.transform().m11())
        self.view.viewChanged.emit()

    def _fit_to_view_animated(self):
        """The Focus button's own version -- a deliberate user action,
        where a smooth fly-to reads as polish rather than distraction."""
        target = self.scene.itemsBoundingRect()
        if target.isEmpty():
            return
        self._animate_view_to(target.adjusted(-60, -60, 60, 60))

    def _animate_view_to(self, target_rect, duration=320):
        """Smoothly interpolates BOTH zoom scale and view center toward
        target_rect over `duration` ms, instead of jumping instantly the
        way fitInView()/centerOn() do on their own -- used for Focus,
        double-click-to-zoom, Reveal in Tree, and list-row selection, so
        camera moves feel like part of the same animation language as
        the grow-in/toast polish elsewhere rather than a jarring cut."""
        if target_rect.isEmpty():
            return
        viewport_size = self.view.viewport().size()
        if viewport_size.width() <= 0 or viewport_size.height() <= 0:
            return
        end_scale = min(viewport_size.width() / target_rect.width(),
                         viewport_size.height() / target_rect.height())
        end_scale = max(CanvasView.MIN_SCALE, min(CanvasView.MAX_SCALE, end_scale))
        end_center = target_rect.center()
        start_scale = self.view.transform().m11()
        start_center = self.view.mapToScene(self.view.viewport().rect().center())

        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.InOutCubic)

        def step(t):
            t = float(t)
            scale = start_scale + (end_scale - start_scale) * t
            cx = start_center.x() + (end_center.x() - start_center.x()) * t
            cy = start_center.y() + (end_center.y() - start_center.y()) * t
            current = self.view.transform().m11()
            if current > 0:
                factor = scale / current
                self.view.scale(factor, factor)
            self.view.centerOn(QPointF(cx, cy))
            self._on_view_zoom_changed(self.view.transform().m11())
            self.view.viewChanged.emit()

        anim.valueChanged.connect(step)
        self._track_animation(anim)
        anim.start()

    def _zoom_to_node(self, node):
        """Double-click a node -> fly to a close-up view of it AND its
        immediate neighbors (not a blind fixed zoom level), so the
        result is actually useful context, not just 'now everything is
        bigger'."""
        self.scene.clearSelection()
        node.setSelected(True)
        rect = QRectF(node.scenePos().x() - node.radius, node.scenePos().y() - node.radius,
                       node.radius * 2, node.radius * 2)
        for edge in node.edges:
            other = edge.node_b if edge.node_a is node else edge.node_a
            other_rect = QRectF(other.scenePos().x() - other.radius, other.scenePos().y() - other.radius,
                                 other.radius * 2, other.radius * 2)
            rect = rect.united(other_rect)
        self._animate_view_to(rect.adjusted(-90, -90, 90, 90))

    # ---------- mode switching ----------

    def _set_mode(self, mode: str):
        if mode == self._mode:
            return
        self._mode = mode
        # Keep the toolbar's exclusive Web/Tree/Clade-Tree button group in
        # sync -- callers that switch mode programmatically (command
        # palette, Reveal in Tree, auto-jump-after-edit) used to leave the
        # OLD button looking active while the canvas had already moved on.
        if mode == "web":
            self.web_action.setChecked(True)
        elif mode == "tree":
            self.tree_action.setChecked(True)
        elif mode == "cladetree":
            self.cladetree_action.setChecked(True)
        self._rebuild()

    def _set_clade_algorithm(self, algo: str):
        self._clade_algorithm = algo
        if self._mode != "cladetree":
            self.cladetree_action.setChecked(True)
            self._mode = "cladetree"
        self._rebuild()

    def _rebuild(self):
        for anim in list(self._active_animations):
            anim.stop()
        self._active_animations = []
        # A running QVariantAnimation stopped via _active_animations
        # above does NOT cancel a separate QTimer.singleShot that's
        # merely waiting to CALL .start() on it later (e.g. the
        # particle trail's staggered start delays) -- confirmed via a
        # real rapid-fire-writes test that reproduced exactly this:
        # crashed with "libshiboken: Internal C++ object already
        # deleted" when an earlier write's delayed particle-start timer
        # fired after a LATER write's rebuild had already destroyed that
        # particle's scene item. Stopping pending timers here closes
        # that gap the same way _active_animations already closes it
        # for animations already in flight.
        for t in list(self._pending_timers):
            t.stop()
        self._pending_timers = []
        self.scene.clear()
        self._node_items = {}
        self._edge_items = []
        self._clade_blob_items = []
        self._empty_state_item = None
        self._time_bounds = None

        if self._mode == "web":
            self._build_web_graph()
        elif self._mode == "tree":
            self._build_tree_graph()
        else:
            self._build_clade_tree_graph()

        self._refresh_list_table()
        self._fit_to_view()
        self._apply_search_filter(self.search_box.text())
        self._configure_time_bar()
        if self._mode == "web" and self.clade_action.isChecked():
            self._draw_clade_blobs()
        if hasattr(self, "minimap"):
            self.minimap.refresh_extent()
        self._update_pulsing_nodes()

    PULSE_RECENCY_SECONDS = 300  # nodes touched in the last 5 minutes get the ambient heartbeat

    def _update_pulsing_nodes(self):
        # Real wall-clock time, not the vault's own max timestamp --
        # using the latter would make whichever node is newest ALWAYS
        # pulse regardless of how long ago that actually was.
        now = time.time()
        recent_nodes = set()
        for node in self._node_items.values():
            ts = node.data(2)
            if ts is not None and (now - ts) <= self.PULSE_RECENCY_SECONDS:
                if not node._pulsing:
                    self._start_node_pulse(node)
                recent_nodes.add(node)
        for edge in self._edge_items:
            edge.set_flow_active(edge.node_a in recent_nodes or edge.node_b in recent_nodes)

    def _start_node_pulse(self, node):
        node.halo.setVisible(True)
        node.mark_pulsing(True)
        anim = QVariantAnimation(self)
        anim.setDuration(1600)
        anim.setLoopCount(-1)
        anim.setEasingCurve(QEasingCurve.InOutSine)
        anim.setKeyValueAt(0.0, 0.10)
        anim.setKeyValueAt(0.5, 0.42)
        anim.setKeyValueAt(1.0, 0.10)
        anim.valueChanged.connect(lambda v, n=node: n.halo.setOpacity(float(v)))
        self._track_animation(anim)
        anim.start()

    # ---------- shared node/edge creation ----------

    def _make_node(self, key, x, y, radius, color, display_text, owner_label=None, birth_ts=None, glyph=""):
        node = NodeItem(radius, display_text, color, glyph=glyph)
        node.setPos(x, y)
        node.setData(0, key)
        node.setData(1, owner_label if owner_label is not None else key)
        node.setData(2, birth_ts)
        node.setToolTip(display_text)
        self.scene.addItem(node)
        self._node_items[key] = node
        return node

    def _make_edge(self, node_a, node_b, dashed, color_override=None, rest_length=None,
                    vertical_bias=False, curve_offset=None):
        if rest_length is None:
            rest_length = LATERAL_EDGE_REST_LENGTH if dashed else WEB_EDGE_REST_LENGTH
        if curve_offset is not None:
            color = color_override if color_override is not None else QColor(_DEFAULT_EDGE_COLOR)
            edge = BraidEdgeItem(node_a, node_b, color, curve_offset, rest_length, vertical_bias)
        else:
            color = color_override if color_override is not None else \
                (QColor(_LATERAL_EDGE_COLOR) if dashed else QColor(_DEFAULT_EDGE_COLOR))
            edge = EdgeItem(node_a, node_b, dashed, color, rest_length=rest_length, vertical_bias=vertical_bias)
        self.scene.addItem(edge)
        self._edge_items.append(edge)
        return edge

    def _node_fill_color(self, phenotype_name, shared_count, total_count):
        if self.heatmap_action.isChecked():
            return _heatmap_color((shared_count or 0) / (total_count or 1))
        return _color_for_phenotype(phenotype_name)

    def _show_empty_state(self, message: str):
        text = self.scene.addText("Your vault is empty.\nDrop a file here, or click ＋ New File(s).")
        text.setDefaultTextColor(QColor(TEXT_DIM))
        font = QFont("Sans", 14)
        text.setFont(font)
        br = text.boundingRect()
        text.setPos(-br.width() / 2, -br.height() / 2)
        self._empty_state_item = text
        self.scene.setSceneRect(-400, -300, 800, 600)
        self.status.showMessage(message)
        self.stats_label.setText("")

    # ---------- data gathering ----------

    def _gather(self):
        meta_by_label = {}
        fingerprints = {}
        for label in self.engine.labels():
            meta = self.engine.get_metadata(label)
            if meta is None:
                continue
            meta_by_label[label] = meta
            fp = meta.get("similarity_fingerprint")
            if fp:
                fingerprints[label] = fp
        histories = {label: self.engine.get_history(label) for label in meta_by_label}
        return list(meta_by_label.keys()), meta_by_label, fingerprints, histories

    def _update_stats_hud(self, meta_by_label):
        total_size = sum(m.get("original_size", 0) for m in meta_by_label.values())
        total_blocks = sum(m.get("total_blocks", 0) for m in meta_by_label.values())
        total_dup = sum(m.get("duplicate_chunks_found", 0) for m in meta_by_label.values())
        dedup_pct = (100 * total_dup / total_blocks) if total_blocks else 0
        container_path = self.engine.container_path
        container_size = os.path.getsize(container_path) if os.path.exists(container_path) else 0
        unresolved = sum(
            1 for label in meta_by_label
            if len(self.engine.get_heads(label)) > 1
        )
        branch_hint = f" · ⑂ {unresolved} unresolved branch(es)" if unresolved else ""
        self.stats_label.setText(
            f"{len(meta_by_label)} file(s) · {total_size:,}B logical · "
            f"{container_size:,}B on disk · {dedup_pct:.0f}% deduped{branch_hint}"
        )

    def _refresh_list_table(self):
        _labels, meta_by_label, _fp, histories = self._gather()
        self.list_table.setSortingEnabled(False)
        self.list_table.setRowCount(len(meta_by_label))
        for row, (label, meta) in enumerate(meta_by_label.items()):
            total = meta.get("total_blocks", 0) or 1
            dedup_pct = round(100 * meta.get("duplicate_chunks_found", 0) / total, 1)
            gens = len(histories.get(label, []))

            self.list_table.setItem(row, 0, QTableWidgetItem(label))
            self.list_table.setItem(row, 1, QTableWidgetItem(meta.get("phenotype_name", "Unknown")))

            size_item = QTableWidgetItem()
            size_item.setData(Qt.DisplayRole, meta.get("original_size", 0))
            self.list_table.setItem(row, 2, size_item)

            dedup_item = QTableWidgetItem()
            dedup_item.setData(Qt.DisplayRole, dedup_pct)
            self.list_table.setItem(row, 3, dedup_item)

            gens_item = QTableWidgetItem()
            gens_item.setData(Qt.DisplayRole, gens)
            self.list_table.setItem(row, 4, gens_item)
        self.list_table.setSortingEnabled(True)

    def _on_list_selection_changed(self):
        """Finds the right canvas node for the clicked label REGARDLESS
        of view mode. This used to only work in Web mode -- self._node_items
        is keyed by LABEL there, but by node_uuid in Tree mode (one entry
        per generation, not per label) and by a freshly-random per-build
        node_uuid in Clade Tree mode, so a plain `label in self._node_items`
        check silently found nothing in either of those two modes."""
        items = self.list_table.selectedItems()
        if not items:
            return
        row = items[0].row()
        label_item = self.list_table.item(row, 0)
        if label_item is None:
            return
        label = label_item.text()

        target_node = None
        if self._mode == "web":
            target_node = self._node_items.get(label)
        elif self._mode == "tree":
            history = self.engine.get_history(label)
            if history:
                target_node = self._node_items.get(history[-1].node_uuid)
        else:  # cladetree -- nodes are keyed by a fresh-per-build uuid, but
            # every leaf node's data(1) is set to its real label at creation
            target_node = next((n for n in self._node_items.values() if n.data(1) == label), None)

        if target_node is not None:
            self.scene.clearSelection()
            target_node.setSelected(True)
            self._animate_view_to(QRectF(target_node.scenePos().x() - 160,
                                          target_node.scenePos().y() - 160, 320, 320))

    def _layout(self, labels, fingerprints):
        graph = nx.Graph()
        graph.add_nodes_from(labels)
        analyzer = PhylogeneticAnalyzer()
        fp_labels = list(fingerprints.keys())
        for i in range(len(fp_labels)):
            for j in range(i + 1, len(fp_labels)):
                a, b = fp_labels[i], fp_labels[j]
                distance = analyzer.calculate_distance(fingerprints[a], fingerprints[b])
                similarity = 1.0 - distance
                if similarity >= SIMILARITY_LAYOUT_THRESHOLD:
                    graph.add_edge(a, b, weight=similarity * 3.0 + 0.1)

        if len(labels) <= 1:
            return {label: (0.0, 0.0) for label in labels}
        pos = nx.spring_layout(graph, weight="weight", seed=7, k=None)
        return {label: (float(x) * LAYOUT_SCALE, float(y) * LAYOUT_SCALE) for label, (x, y) in pos.items()}

    def _lineage_forest_layout(self, histories):
        all_nodes = {}
        for label, history in histories.items():
            for node in history:
                all_nodes[node.node_uuid] = (label, node)

        children = {uuid: [] for uuid in all_nodes}
        roots = []
        for uuid, (_label, node) in all_nodes.items():
            if node.parent_uuid and node.parent_uuid in all_nodes:
                children[node.parent_uuid].append(uuid)
            else:
                roots.append(uuid)

        positions = {}
        next_x = [0.0]

        def layout_subtree(uuid, depth):
            kids = children[uuid]
            if not kids:
                x = next_x[0]
                next_x[0] += TREE_SIBLING_SPACING
            else:
                child_xs = [layout_subtree(k, depth + 1) for k in kids]
                x = sum(child_xs) / len(child_xs)
            positions[uuid] = (x, depth * TREE_LEVEL_SPACING)
            return x

        for root in roots:
            layout_subtree(root, 0)

        if positions:
            mean_x = sum(x for x, _y in positions.values()) / len(positions)
            positions = {k: (x - mean_x, y) for k, (x, y) in positions.items()}

        return positions, all_nodes

    def _clade_tree_layout(self, all_nodes):
        by_uuid = {n.node_uuid: n for n in all_nodes}
        children = {n.node_uuid: [] for n in all_nodes}
        roots = []
        for n in all_nodes:
            if n.parent_uuid and n.parent_uuid in by_uuid:
                children[n.parent_uuid].append(n.node_uuid)
            else:
                roots.append(n.node_uuid)

        depth = {}

        def compute_depth(uid, accumulated):
            depth[uid] = accumulated
            for child_uuid in children[uid]:
                compute_depth(child_uuid, accumulated + by_uuid[child_uuid].branch_length)

        for r in roots:
            compute_depth(r, 0.0)

        positions = {}
        next_x = [0.0]

        def layout_subtree(uid):
            kids = children[uid]
            if not kids:
                x = next_x[0]
                next_x[0] += TREE_SIBLING_SPACING
            else:
                xs = [layout_subtree(k) for k in kids]
                x = sum(xs) / len(xs)
            positions[uid] = (x, depth[uid] * CLADE_HEIGHT_SCALE)
            return x

        for r in roots:
            layout_subtree(r)

        if positions:
            mean_x = sum(x for x, _y in positions.values()) / len(positions)
            positions = {k: (x - mean_x, y) for k, (x, y) in positions.items()}

        return positions, by_uuid

    def _compute_branch_visuals(self, histories):
        """{node_uuid: (color, curve_offset)} for edges on a SPECIFIC
        divergent branch's path (fork point to head) -- the "branch
        braid": each simultaneously-open branch gets both a distinct
        color AND a distinct curve direction/magnitude (alternating
        sign, growing with branch index), so forks read as visibly
        separate strands rather than overlapping straight lines."""
        visuals = {}
        for label, history in histories.items():
            heads = self.engine.get_heads(label)
            if len(heads) <= 1:
                continue
            by_uuid = {n.node_uuid: n for n in history}
            for i, head in enumerate(heads):
                color = QColor(BRANCH_COLORS[i % len(BRANCH_COLORS)])
                sign = 1 if i % 2 == 0 else -1
                offset = sign * (26.0 + 18.0 * (i // 2))
                node = head
                while node is not None and node.node_uuid not in visuals:
                    visuals[node.node_uuid] = (color, offset)
                    node = by_uuid.get(node.parent_uuid) if node.parent_uuid else None
        return visuals

    # ---------- web mode ----------

    def _build_web_graph(self):
        labels, meta_by_label, fingerprints, histories = self._gather()
        self._update_stats_hud(meta_by_label)
        self._time_machine_histories = histories  # used by _apply_point_in_time_web
        if not labels:
            self._show_empty_state("Vault is empty -- write something, or drop a file onto the canvas.")
            return

        timestamps = [n.birth_timestamp for h in histories.values() for n in h]
        self._time_bounds = (min(timestamps), max(timestamps)) if timestamps else None

        positions = self._layout(labels, fingerprints)
        max_blocks = max((meta_by_label[l].get("total_blocks", 1) or 1) for l in labels) or 1

        for label in labels:
            meta = meta_by_label[label]
            x, y = positions[label]
            blocks = meta.get("total_blocks", 1) or 1
            radius = NODE_MIN_RADIUS + (NODE_MAX_RADIUS - NODE_MIN_RADIUS) * math.sqrt(blocks / max_blocks)
            phenotype_name = meta.get("phenotype_name", "Unknown Binary")
            color = self._node_fill_color(phenotype_name, meta.get("duplicate_chunks_found", 0), blocks)
            birth_ts = histories[label][0].birth_timestamp if histories.get(label) else None
            self._make_node(label, x, y, radius, color, label, birth_ts=birth_ts,
                             glyph=_glyph_for_phenotype(phenotype_name))

        uuid_to_label = {}
        for label, history in histories.items():
            for node in history:
                uuid_to_label[node.node_uuid] = label

        edges_drawn = 0
        for label, history in histories.items():
            for node in history:
                if node.parent_uuid and node.parent_uuid in uuid_to_label:
                    parent_label = uuid_to_label[node.parent_uuid]
                    if parent_label != label and parent_label in self._node_items:
                        self._make_edge(self._node_items[parent_label], self._node_items[label], dashed=False)
                        edges_drawn += 1
                for lateral_uuid in node.lateral_parent_uuids:
                    lateral_label = uuid_to_label.get(lateral_uuid)
                    if lateral_label and lateral_label != label and lateral_label in self._node_items:
                        self._make_edge(self._node_items[lateral_label], self._node_items[label], dashed=True)
                        edges_drawn += 1

        self.status.showMessage(
            f"{len(labels)} file(s), {edges_drawn} cross-label edge(s), {len(fingerprints)} fingerprinted "
            f"-- drag empty space to pan, drag a node to move it, right-click for actions."
        )

    # ---------- lineage tree mode ----------

    def _build_tree_graph(self):
        _labels, meta_by_label, _fp, histories = self._gather()
        self._update_stats_hud(meta_by_label)

        timestamps = [n.birth_timestamp for h in histories.values() for n in h]
        self._time_bounds = (min(timestamps), max(timestamps)) if timestamps else None

        positions, all_nodes = self._lineage_forest_layout(histories)
        if not positions:
            self._show_empty_state("No lineage history yet -- write something first.")
            return

        branch_visuals = self._compute_branch_visuals(histories)
        max_chunks = max((node.total_chunks or 1) for _label, node in all_nodes.values()) or 1
        uuid_to_item = {}
        for uuid, (label, node) in all_nodes.items():
            x, y = positions[uuid]
            radius = NODE_MIN_RADIUS + (NODE_MAX_RADIUS - NODE_MIN_RADIUS) * \
                math.sqrt((node.total_chunks or 1) / max_chunks) * 0.7
            phenotype_name = meta_by_label.get(label, {}).get("phenotype_name", "Unknown Binary")
            shared = (node.total_chunks or 0) - (node.new_chunks or 0)
            color = self._node_fill_color(phenotype_name, shared, node.total_chunks)
            pruned = " (pruned)" if node.pruned else ""
            text = f"{label} · gen {node.generation_index}{pruned}"
            uuid_to_item[uuid] = self._make_node(uuid, x, y, radius, color, text, owner_label=label,
                                                  birth_ts=node.birth_timestamp,
                                                  glyph=_glyph_for_phenotype(phenotype_name))

        edges_drawn = 0
        for uuid, (_label, node) in all_nodes.items():
            if node.parent_uuid and node.parent_uuid in uuid_to_item:
                visual = branch_visuals.get(uuid)
                branch_color, curve_offset = visual if visual else (None, None)
                self._make_edge(uuid_to_item[node.parent_uuid], uuid_to_item[uuid], dashed=False,
                                 color_override=branch_color, curve_offset=curve_offset,
                                 rest_length=TREE_LEVEL_SPACING, vertical_bias=True)
                edges_drawn += 1
            for lateral in node.lateral_parent_uuids:
                if lateral in uuid_to_item:
                    self._make_edge(uuid_to_item[lateral], uuid_to_item[uuid], dashed=True)
                    edges_drawn += 1

        self.status.showMessage(
            f"Lineage tree: {len(all_nodes)} generation(s) across {len(meta_by_label)} label(s), "
            f"{edges_drawn} edge(s) -- the real, full genealogy, not just current tips."
        )

    # ---------- clade tree mode (UPGMA / NJ) ----------

    def _build_clade_tree_graph(self):
        _labels, meta_by_label, fingerprints, _hist = self._gather()
        self._update_stats_hud(meta_by_label)
        if len(fingerprints) < 2:
            self._show_empty_state("Need at least 2 fingerprinted files to build a clade tree.")
            return

        analyzer = PhylogeneticAnalyzer()
        tc = TreeConstructor(analyzer)
        if self._clade_algorithm == "nj":
            all_nodes = tc.build_tree_nj_from_traits(fingerprints)
        else:
            all_nodes = tc.build_tree_upgma_from_traits(fingerprints)

        positions, by_uuid = self._clade_tree_layout(all_nodes)
        max_leaf_count = max((n.leaf_count or 1) for n in all_nodes) or 1

        uuid_to_item = {}
        for n in all_nodes:
            x, y = positions[n.node_uuid]
            is_leaf = n.metadata_name is not None
            glyph = ""
            if is_leaf:
                meta = meta_by_label.get(n.metadata_name, {})
                phenotype_name = meta.get("phenotype_name", "Unknown Binary")
                radius = NODE_MIN_RADIUS + (NODE_MAX_RADIUS - NODE_MIN_RADIUS) * 0.55
                color = self._node_fill_color(phenotype_name, meta.get("duplicate_chunks_found", 0),
                                               meta.get("total_blocks", 1))
                glyph = _glyph_for_phenotype(phenotype_name)
                text = n.metadata_name
                owner = n.metadata_name
            else:
                radius = 4.0 + 10.0 * math.sqrt((n.leaf_count or 1) / max_leaf_count)
                color = QColor("#3a3d4a")
                text = f"cluster ({n.leaf_count})"
                owner = None
            uuid_to_item[n.node_uuid] = self._make_node(n.node_uuid, x, y, radius, color, text,
                                                          owner_label=owner, glyph=glyph)

        edges_drawn = 0
        for n in all_nodes:
            if n.parent_uuid and n.parent_uuid in uuid_to_item:
                rest = max(50.0, n.branch_length * CLADE_HEIGHT_SCALE)
                self._make_edge(uuid_to_item[n.parent_uuid], uuid_to_item[n.node_uuid],
                                 dashed=False, rest_length=rest, vertical_bias=True)
                edges_drawn += 1

        algo_name = "Neighbor-Joining" if self._clade_algorithm == "nj" else "UPGMA"
        leaf_count = sum(1 for n in all_nodes if n.metadata_name)
        self.status.showMessage(
            f"{algo_name} clade tree: {leaf_count} file(s), {len(all_nodes) - leaf_count} cluster node(s), "
            f"{edges_drawn} edge(s) -- toggle UPGMA/NJ to watch the SAME files regroup differently."
        )

    # ---------- clade outline overlay (web mode) ----------

    def _clear_clade_blobs(self):
        for item in self._clade_blob_items:
            if item.scene() is not None:
                self.scene.removeItem(item)
        self._clade_blob_items = []
        self._clade_membership = {}
        self._clade_leash_radius = {}

    def _draw_clade_blobs(self):
        self._clear_clade_blobs()
        if self._mode != "web":
            return
        # Short wait: answers from a fresh partition after a change made a
        # moment ago, without ever stalling the UI on a long recompute
        # (_poll_clade_updates redraws once that lands).
        clades, _label_to_clade, self._clade_version_drawn = self.engine.clades(wait=0.5)
        clade_cards = []
        if clades:
            idx = 0
            for clade_name, members in clades.items():
                if len(members) < 2:
                    continue
                positions = [self._node_items[m].pos() for m in members if m in self._node_items]
                if not positions:
                    continue
                color = QColor(BRANCH_COLORS[idx % len(BRANCH_COLORS)])
                idx += 1
                cx = sum(p.x() for p in positions) / len(positions)
                cy = sum(p.y() for p in positions) / len(positions)
                max_r = max(math.hypot(p.x() - cx, p.y() - cy) for p in positions) + NODE_MAX_RADIUS + 24

                # Local-coordinate rect + setPos (like NodeItem itself),
                # NOT an absolute-coordinate rect -- this is what lets
                # the blob be repositioned by just changing .pos(), which
                # the orbital swirl and (were the centroid to drift)
                # future containment updates both rely on. The
                # constellation label is a CHILD of the blob for the same
                # reason: it then moves/rotates for free with its parent.
                blob = QGraphicsEllipseItem(-max_r, -max_r, max_r * 2, max_r * 2)
                blob.setPos(cx, cy)
                blob.setBrush(QBrush(QColor(color.red(), color.green(), color.blue(), 30)))
                blob.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 130), 1.5, Qt.DashLine))
                blob.setZValue(-1)
                self.scene.addItem(blob)
                self._clade_blob_items.append(blob)

                label_item = QGraphicsSimpleTextItem(clade_name, blob)
                label_item.setFont(QFont("Sans", 9, QFont.DemiBold))
                label_item.setBrush(QBrush(QColor(color.red(), color.green(), color.blue(), 190)))
                lr = label_item.boundingRect()
                label_item.setPos(-lr.width() / 2, -max_r + 10)
                label_item.setZValue(0.2)

                for member in members:
                    self._clade_membership[member] = clade_name
                self._clade_leash_radius[clade_name] = max_r

                clade_cards.append({"heading": clade_name, "rows": [], "note": ", ".join(sorted(members))})

        # Every node gets SOME outline, even one with no close relatives --
        # a monotypic (single-member) clade is still a real clade
        # biologically. Drawn dim/uncolored and unlabeled so it doesn't
        # visually compete with real multi-member clusters, but it
        # closes the "why is this node floating outside every circle"
        # gap -- nothing is left uncontained.
        solo_color = QColor(TEXT_DIM)
        for label, node in self._node_items.items():
            if label in self._clade_membership:
                continue
            cx, cy = node.pos().x(), node.pos().y()
            max_r = NODE_MAX_RADIUS + 20
            clade_key = f"__solo__{label}"
            blob = QGraphicsEllipseItem(-max_r, -max_r, max_r * 2, max_r * 2)
            blob.setPos(cx, cy)
            blob.setBrush(QBrush(QColor(solo_color.red(), solo_color.green(), solo_color.blue(), 14)))
            blob.setPen(QPen(QColor(solo_color.red(), solo_color.green(), solo_color.blue(), 70), 1, Qt.DotLine))
            blob.setZValue(-1)
            self.scene.addItem(blob)
            self._clade_blob_items.append(blob)
            self._clade_membership[label] = clade_key
            self._clade_leash_radius[clade_key] = max_r

        if not clade_cards:
            clade_cards.append({"heading": "No shared clades yet", "rows": [],
                                 "note": "Need 2+ files sharing 80%+ content -- every file still "
                                         "has its own faint individual outline."})
        self._render_cards("Clades", clade_cards)

    def closeEvent(self, event):
        self._clade_poll_timer.stop()
        super().closeEvent(event)

    def _poll_clade_updates(self):
        if self._mode != "web" or not self.clade_action.isChecked():
            return
        if self.engine.clade_version() != self._clade_version_drawn:
            self._draw_clade_blobs()

    def _on_clade_toggle(self, checked: bool):
        if checked:
            self._draw_clade_blobs()
        else:
            self._clear_clade_blobs()

    # ---------- search ----------

    def _apply_search_filter(self, text: str):
        text = text.strip().lower()
        for node in self._node_items.values():
            owner = node.data(1) or ""
            match = (not text) or (text in owner.lower())
            node.setOpacity(1.0 if match else 0.35)
            node.set_focus_dim(not match and bool(text))
        for edge in self._edge_items:
            edge.setOpacity(EDGE_REST_OPACITY if not text else 0.10)

    # ---------- time machine ----------

    def _configure_time_bar(self):
        has_bounds = self._time_bounds is not None
        self.time_slider.setEnabled(has_bounds)
        self.time_slider.blockSignals(True)
        self.time_slider.setValue(1000)
        self.time_slider.blockSignals(False)
        self._on_time_slider_changed(1000)

    def _on_time_slider_changed(self, value: int):
        if self._time_bounds is None:
            self.time_label.setText("(no data)")
            return
        min_ts, max_ts = self._time_bounds
        cutoff = max_ts if max_ts <= min_ts else min_ts + (value / 1000) * (max_ts - min_ts)
        self._time_cutoff = cutoff

        if self._mode == "web" and self._time_machine_histories:
            self._apply_point_in_time_web(cutoff)
        else:
            # Tree/Clade-Tree modes: each generation is already its own
            # node, so existence-based fading (did this specific version
            # exist yet?) already IS the correct point-in-time view --
            # no separate reconstruction needed there.
            for node in self._node_items.values():
                ts = node.data(2)
                node.setVisible(ts is None or ts <= cutoff)
            for edge in self._edge_items:
                edge.setVisible(edge.node_a.isVisible() and edge.node_b.isVisible())

        label = "now" if value >= 1000 else datetime.fromtimestamp(cutoff).strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.setText(label)

    def _historical_generation_for(self, label, cutoff):
        """The generation that WAS this label's current tip at the given
        moment -- the last recorded generation with birth_timestamp <=
        cutoff, or None if the label didn't exist yet. LineageStore
        appends in chronological order, so a linear scan keeping the
        last match is correct without needing to sort anything."""
        candidate = None
        for node in self._time_machine_histories.get(label, []):
            if node.birth_timestamp <= cutoff:
                candidate = node
            else:
                break
        return candidate

    def _apply_point_in_time_web(self, cutoff):
        """The real 'point-in-time content reconstruction': not just
        fading a node in/out by whether it existed yet, but resizing
        (and, with Dedup Heat on, recoloring) it to match whichever
        GENERATION was actually current at that moment -- using each
        LineageNode's own already-recorded total_chunks/new_chunks, no
        extra decryption needed since that's real data the write path
        stored at commit time, not something reconstructed just for
        this view."""
        generation_by_label = {}
        max_chunks_at_cutoff = 1
        for label in self._node_items:
            node = self._historical_generation_for(label, cutoff)
            generation_by_label[label] = node
            if node is not None:
                max_chunks_at_cutoff = max(max_chunks_at_cutoff, node.total_chunks or 1)

        for label, item in self._node_items.items():
            node = generation_by_label.get(label)
            if node is None:
                item.setVisible(False)
                continue
            item.setVisible(True)
            radius = NODE_MIN_RADIUS + (NODE_MAX_RADIUS - NODE_MIN_RADIUS) * \
                math.sqrt((node.total_chunks or 1) / max_chunks_at_cutoff)
            item.set_radius_live(radius)
            if self.heatmap_action.isChecked():
                shared = (node.total_chunks or 0) - (node.new_chunks or 0)
                item._apply_color(_heatmap_color(shared / (node.total_chunks or 1)))
            item.setToolTip(f"{label} (as of generation {node.generation_index})")

        for edge in self._edge_items:
            edge.setVisible(edge.node_a.isVisible() and edge.node_b.isVisible())

    # ---------- selection / details ----------

    def _on_selection_changed(self):
        selected = self.scene.selectedItems()
        if not selected:
            return
        if len(selected) == 2 and self._mode == "web":
            self._show_diff_between(selected[0].data(0), selected[1].data(0))
            return
        if len(selected) == 2 and self._mode == "tree":
            # Tree mode's counterpart to Web mode's two-selection diff
            # above -- but a REAL lineage diff (two generations of the
            # SAME label's real edit history), not a clade/similarity
            # comparison, since here each node is a real generation, not
            # a label's current tip.
            self._show_lineage_diff_between_nodes(selected[0].data(0), selected[1].data(0))
            return
        node = selected[0]
        key = node.data(0)
        if key is None:
            return
        if self._mode == "web":
            self._show_details_for_label(key)
        elif self._mode == "tree":
            self._show_details_for_generation(key)
        else:
            self._show_details_for_clade_node(key)

    def _show_details_for_label(self, label):
        meta = self.engine.get_metadata(label)
        if meta is None:
            return
        manifest_filename = meta["manifest_filename"]
        history = self.engine.get_history(label)
        tags = self.engine.get_tags(label)
        heads = self.engine.get_heads(label)

        total = meta.get("total_blocks", 0) or 1
        dedup_pct = 100 * meta.get("duplicate_chunks_found", 0) / total
        branch_note = f"{len(heads)} branch head(s)" + (" -- diverged, see Tree view" if len(heads) > 1 else "")

        # Labels sharing this EXACT manifest -- true storage aliases (e.g.
        # from Duplicate), not just similar content. The file's own Size
        # above is its real logical content size (what you get if you
        # open/read it) -- this row is what actually answers "does this
        # cost extra space": no, every byte is already stored under the
        # other label(s) listed here.
        sharing_labels = sorted(
            other for other in self.engine.labels()
            if other != label and (other_meta := self.engine.get_metadata(other))
            and other_meta["manifest_filename"] == manifest_filename
        )
        file_rows = [
            ("Type", meta.get("phenotype_name", "Unknown")),
            ("Size", f"{meta.get('original_size', 0):,} bytes"),
            ("Chunks", meta.get("total_blocks", 0)),
            ("Dedup", f"{dedup_pct:.1f}%"),
        ]
        if sharing_labels:
            file_rows.append(("Storage", f"shared with {', '.join(sharing_labels)} (0 new bytes)"))

        cards = [
            {"heading": "File", "rows": file_rows},
            {"heading": "Lineage", "rows": [
                ("Generations", len(history)),
                ("Branches", len(heads)),
            ], "note": branch_note if len(heads) > 1 else None},
            {"heading": "Tags", "rows": [(k, v) for k, v in tags.items()] if tags else [("(none)", "")]},
        ]
        self._render_cards(label, cards)

    def _show_details_for_generation(self, node_uuid):
        found = self.engine.find_node_by_uuid(node_uuid)
        if found is None:
            return
        _label, node = found
        owning_label = self._node_items[node_uuid].data(1)
        tags = self.engine.get_node_tags(node_uuid)
        cards = [
            {"heading": "Generation", "rows": [
                ("Born", datetime.fromtimestamp(node.birth_timestamp).strftime("%Y-%m-%d %H:%M:%S")),
                ("New chunks", node.new_chunks),
                ("Total chunks", node.total_chunks),
                ("Pruned", "yes" if node.pruned else "no"),
                ("Lateral parents", node.lateral_parent_count),
            ]},
            {"heading": "Tags (inherited forward)", "rows": [(k, v) for k, v in tags.items()] if tags else [("(none)", "")]},
        ]
        self._render_cards(f"{owning_label} · gen {node.generation_index}", cards)

    def _show_details_for_clade_node(self, node_uuid):
        owner = self._node_items[node_uuid].data(1)
        if owner:
            self._show_details_for_label(owner)
        else:
            self._render_cards("Cluster node", [
                {"heading": "Synthetic cluster", "rows": [], "note": "Not a real file -- a computed grouping."},
            ])

    def _show_diff_between(self, label_a, label_b):
        _labels, meta_by_label, fingerprints, _hist = self._gather()
        fp_a, fp_b = fingerprints.get(label_a), fingerprints.get(label_b)
        if fp_a is None or fp_b is None:
            cards = [{"heading": "Comparison", "rows": [],
                      "note": "One or both files aren't fingerprinted yet."}]
        else:
            analyzer = PhylogeneticAnalyzer()
            distance = analyzer.calculate_distance(fp_a, fp_b)
            cards = [{"heading": "Comparison", "rows": [
                ("Similarity", f"{(1 - distance) * 100:.1f}%"),
                ("Shared traits", len(fp_a & fp_b)),
                (f"'{label_a}' unique", len(fp_a - fp_b)),
                (f"'{label_b}' unique", len(fp_b - fp_a)),
            ]}]
        self._render_cards(f"{label_a} vs {label_b}", cards)

    def _show_lineage_diff_between_nodes(self, node_uuid_a, node_uuid_b):
        """Tree mode's two-selection counterpart to _show_diff_between
        above -- but a REAL lineage diff (chunk-position diff between
        two generations of the SAME label's real edit history), not a
        clade/similarity comparison. See lineage_diff.py's module
        docstring for why these stay separate code paths."""
        found_a = self.engine.find_node_by_uuid(node_uuid_a)
        found_b = self.engine.find_node_by_uuid(node_uuid_b)
        if found_a is None or found_b is None:
            return
        label_a, node_a = found_a
        label_b, node_b = found_b
        if label_a != label_b:
            self._render_cards("Lineage diff", [{"heading": "Comparison", "rows": [], "note":
                f"'{label_a}' and '{label_b}' are different labels -- a lineage diff only applies "
                f"within one label's own real edit history. To compare two DIFFERENT files' "
                f"similarity instead, select two nodes in Web mode."}])
            return
        gen_old, gen_new = sorted([node_a.generation_index, node_b.generation_index])
        self._run_lineage_diff(label_a, gen_old, gen_new)

    def _diff_against_parent(self, owning_label, node_uuid):
        """Context-menu entry point: diffs a single generation against
        its own PRIMARY parent -- the most common lineage-diff use case
        (what mutated in this one edit), needing only a single
        right-click rather than a two-node multi-select."""
        found = self.engine.find_node_by_uuid(node_uuid)
        if found is None:
            return
        _owner, node = found
        if not node.parent_uuid:
            self._toast(f"Generation {node.generation_index} of '{owning_label}' is a root generation "
                        f"-- no parent to diff against.")
            return
        parent_found = self.engine.find_node_by_uuid(node.parent_uuid)
        if parent_found is None:
            return
        _powner, parent_node = parent_found
        self._run_lineage_diff(owning_label, parent_node.generation_index, node.generation_index)

    def _try_text_diff(self, label, generation_old, generation_new):
        """Bonus, nice-to-have on top of the always-correct chunk map:
        if both generations' full content decodes as UTF-8 text, a real
        difflib line-level diff. Returns None on ANY failure (binary
        content, a decode error, a checkout error) -- explicitly a
        bonus, never allowed to block the core chunk-map result."""
        path_a = path_b = None
        try:
            fd_a, path_a = tempfile.mkstemp(prefix="pfs_lineage_diff_")
            os.close(fd_a)
            fd_b, path_b = tempfile.mkstemp(prefix="pfs_lineage_diff_")
            os.close(fd_b)
            self.engine.checkout(label, generation_old, path_a)
            self.engine.checkout(label, generation_new, path_b)
            with open(path_a, "rb") as f:
                text_a = f.read().decode("utf-8")
            with open(path_b, "rb") as f:
                text_b = f.read().decode("utf-8")
        except Exception:
            return None
        finally:
            for p in (path_a, path_b):
                if p and os.path.exists(p):
                    os.remove(p)
        return list(difflib.unified_diff(text_a.splitlines(keepends=True), text_b.splitlines(keepends=True),
                                          fromfile=f"gen {generation_old}", tofile=f"gen {generation_new}"))

    def _run_lineage_diff(self, label, generation_old, generation_new):
        """The real entry point every lineage-diff trigger (Tree mode's
        two-node select, 'Diff against parent') funnels through: runs
        the chunk-position diff primitive (lineage_diff.diff_generations,
        engine-agnostic via self.engine's adapter), optionally attempts
        the bonus text diff, and renders LineageDiffDialog."""
        try:
            result = lineage_diff.diff_generations(self.engine, label, generation_old, generation_new)
        except Exception as e:
            QMessageBox.warning(self, "Lineage diff", str(e))
            return

        text_diff_lines = None if result.identical else self._try_text_diff(label, generation_old, generation_new)

        dlg = LineageDiffDialog(self, result, self._theme_colors(), text_diff_lines)
        self._active_dialogs.append(dlg)
        dlg.finished.connect(lambda _r=None: self._active_dialogs.remove(dlg) if dlg in self._active_dialogs else None)
        dlg.show()

    # ---------- write actions ----------

    def _show_node_context_menu(self, node: NodeItem, local_pos: QPoint):
        global_pos = self.view.viewport().mapToGlobal(local_pos)
        menu = QMenu(self)
        if self._mode == "web":
            label = node.data(0)
            meta = self.engine.get_metadata(label)
            phenotype_name = meta.get("phenotype_name", "") if meta else ""

            menu.addAction("Info", lambda: self._show_details_for_label(label))
            if _is_inapp_text_phenotype(phenotype_name):
                menu.addAction("Edit (in-app, real-time)", lambda: self._edit_label_inapp(label))
            elif _is_inapp_image_phenotype(phenotype_name):
                menu.addAction("View Image", lambda: self._view_image_inapp(label))
            menu.addAction("View (read-only, external)", lambda: self._view_label(label))
            menu.addAction("Edit externally...", lambda: self._edit_label(label))
            menu.addAction("Rename...", lambda: self._rename_label(label))
            menu.addAction("Duplicate (zero-cost alias)...", lambda: self._duplicate_label(label))
            menu.addAction("Trace ancestry", lambda: self._trace_ancestry(label))
            menu.addAction("Reveal in Tree", lambda: self._reveal_in_tree(label))
            menu.addSeparator()
            menu.addAction("Delete...", lambda: self._delete_label(label))
        elif self._mode == "tree":
            node_uuid = node.data(0)
            owning_label = node.data(1)
            found = self.engine.find_node_by_uuid(node_uuid)
            if found is None:
                return
            _owner, lineage_node = found
            history = self.engine.get_history(owning_label)
            heads = self.engine.get_heads(owning_label)
            is_tip = bool(history) and history[-1].node_uuid == node_uuid
            menu.addAction("Info", lambda: self._show_details_for_generation(node_uuid))
            menu.addAction("Checkout to file...",
                            lambda: self._checkout_generation(owning_label, lineage_node.generation_index))
            menu.addAction("Fork from here...",
                            lambda: self._fork_from_generation_action(owning_label, lineage_node.generation_index))
            if lineage_node.parent_uuid:
                menu.addAction("Diff against parent", lambda: self._diff_against_parent(owning_label, node_uuid))
            if not is_tip and not lineage_node.pruned:
                menu.addAction("Prune this generation...",
                                lambda: self._prune_generation_action(owning_label, lineage_node.generation_index))
            if len(heads) > 1:
                menu.addSeparator()
                menu.addAction("Merge branches...", lambda: self._merge_action_for_label(owning_label))
        else:
            key = node.data(0)
            owner = node.data(1)
            menu.addAction("Info", lambda: self._show_details_for_clade_node(key))
            if owner:
                menu.addAction("Reveal in Tree", lambda: self._reveal_in_tree(owner))
        menu.exec(global_pos)

    def _rename_label_direct(self, label, new_label):
        """No-prompt core -- used by both the interactive right-click
        flow and the command palette's 'rename' command."""
        if not self.engine.has_label(label):
            raise KeyError(f"No such label: '{label}'")
        if self.engine.has_label(new_label):
            raise ValueError(f"'{new_label}' already exists")
        self.engine.rename_label(label, new_label)
        self._toast(f"Renamed '{label}' -> '{new_label}'")
        self._rebuild()

    def _rename_label(self, label):
        new_label, ok = QInputDialog.getText(self, "Rename", f"New name for '{label}':", text=label)
        if not ok or not new_label.strip() or new_label.strip() == label:
            return
        try:
            self._rename_label_direct(label, new_label.strip())
        except ValueError as e:
            QMessageBox.warning(self, "Rename", str(e))

    def _duplicate_label_direct(self, label, new_label):
        """A duplicate is recorded as a real lineage child of the source
        label -- lateral_parent_labels=[label] links the new label's
        generation 0 back to the source's current tip, so the graph
        shows where it came from (Web mode draws this as a dashed
        cross-label edge, same as a graft) instead of a disconnected
        fresh root. It's still effectively zero-cost: the reconstructed
        content is byte-identical, so FastCDC's content-defined chunking
        produces the exact same chunk hashes and commit_write's dedup
        index finds them already in the global pool -- no new chunk data
        is actually written, only a new manifest + lineage record."""
        if not self.engine.has_label(label):
            raise KeyError(f"No such label: '{label}'")
        if self.engine.has_label(new_label):
            raise ValueError(f"'{new_label}' already exists")

        self._perform_write_and_animate(lambda: self.engine.duplicate_label(label, new_label))
        self._toast(f"Duplicated '{label}' -> '{new_label}' (zero-cost content alias, linked back to '{label}')")

    def _duplicate_label(self, label):
        new_label, ok = QInputDialog.getText(self, "Duplicate", f"New label for a copy of '{label}':")
        if not ok or not new_label.strip():
            return
        try:
            self._duplicate_label_direct(label, new_label.strip())
        except ValueError as e:
            QMessageBox.warning(self, "Duplicate", str(e))

    def _delete_label(self, label):
        confirm = QMessageBox.question(
            self, "Delete", f"Delete '{label}' and its full history? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.engine.delete_label(label)
        except PermissionError as e:
            QMessageBox.warning(self, "Delete refused", str(e))
            return
        self._toast(f"Deleted '{label}'")
        self._rebuild()

    def _trace_ancestry(self, label):
        _labels, _meta, _fp, histories = self._gather()
        uuid_to_label = {}
        for lbl, hist in histories.items():
            for node in hist:
                uuid_to_label[node.node_uuid] = lbl
        chain = {label}
        current_label = label
        guard = set()
        while True:
            hist = histories.get(current_label, [])
            if not hist:
                break
            parent_uuid = hist[0].parent_uuid
            if not parent_uuid or parent_uuid not in uuid_to_label:
                break
            parent_label = uuid_to_label[parent_uuid]
            if parent_label in guard:
                break
            guard.add(parent_label)
            chain.add(parent_label)
            current_label = parent_label
        for node in self._node_items.values():
            on_chain = node.data(1) in chain
            node.setOpacity(1.0 if on_chain else 0.30)
            node.set_focus_dim(not on_chain)
        for edge in self._edge_items:
            on_path = edge.node_a.opacity() == 1.0 and edge.node_b.opacity() == 1.0
            edge.setOpacity(EDGE_REST_OPACITY if on_path else 0.08)
        self._toast(f"Highlighting ancestry of '{label}' ({len(chain)} label(s)) -- clear the search box to reset")

    def _reveal_in_tree(self, label):
        self._set_mode("tree")
        history = self.engine.get_history(label)
        if not history:
            return
        tip_uuid = history[-1].node_uuid
        node = self._node_items.get(tip_uuid)
        if node:
            self.scene.clearSelection()
            node.setSelected(True)
            self._animate_view_to(QRectF(node.scenePos().x() - 160, node.scenePos().y() - 160, 320, 320))

    def _checkout_generation(self, label, generation_index):
        path, _ = QFileDialog.getSaveFileName(self, f"Checkout {label} gen {generation_index} to...")
        if not path:
            return
        try:
            self.engine.checkout(label, generation_index, path)
        except ValueError as e:
            QMessageBox.warning(self, "Checkout", str(e))
            return
        self._toast(f"Saved {label} gen {generation_index} to {path}")

    def _prune_generation_action(self, label, generation_index):
        confirm = QMessageBox.question(
            self, "Prune",
            f"Prune '{label}' generation {generation_index}? This frees its storage (if nothing else "
            f"references it) but keeps the history record.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.engine.prune_generation(label, generation_index)
            self._toast(f"Pruned '{label}' generation {generation_index}")
            self._rebuild()
        except (ValueError, PermissionError) as e:
            QMessageBox.warning(self, "Prune failed", str(e))

    def _fork_from_generation_action(self, label, generation_index):
        path, _ = QFileDialog.getOpenFileName(self, f"Fork '{label}' generation {generation_index} with...")
        if not path:
            return
        self._perform_write_and_animate(
            lambda: self.engine.commit_write(label, path, fork_from_generation=generation_index)
        )
        self._toast(f"Forked '{label}' from generation {generation_index}")

    def _merge_action_for_label(self, label):
        heads = self.engine.get_heads(label)
        if len(heads) < 2:
            return
        choices = [f"gen {h.generation_index}" for h in heads]
        choice_a, ok = QInputDialog.getItem(self, "Merge", "First branch:", choices, editable=False)
        if not ok:
            return
        remaining = [c for c in choices if c != choice_a]
        choice_b, ok = QInputDialog.getItem(self, "Merge", "Second branch:", remaining, editable=False)
        if not ok:
            return
        head_a = heads[choices.index(choice_a)]
        head_b = heads[choices.index(choice_b)]
        try:
            self._perform_write_and_animate(
                lambda: self.engine.merge_branches(label, head_a.generation_index, head_b.generation_index)
            )
            self._toast(f"Merged '{label}' generations {head_a.generation_index} and {head_b.generation_index}")
        except MutationConflictError as e:
            QMessageBox.warning(
                self, "Mutation Conflict",
                f"These branches changed the same content differently and can't be auto-merged.\n\n{e}",
            )
        except ValueError as e:
            QMessageBox.warning(self, "Merge failed", str(e))

    def _new_file_dialog(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose one or more files to add to the vault")
        if paths:
            self._add_files(paths)

    def _on_files_dropped(self, paths):
        real_paths = [p for p in paths if os.path.isfile(p)]
        if real_paths:
            self._add_files(real_paths)
        elif paths:
            self._toast("Drop didn't include any readable file path -- try + New File(s) instead")

    def _unique_label_from_path(self, path: str) -> str:
        base = os.path.basename(path)
        if not self.engine.has_label(base):
            return base
        stem, ext = os.path.splitext(base)
        i = 2
        while self.engine.has_label(f"{stem}_{i}{ext}"):
            i += 1
        return f"{stem}_{i}{ext}"

    def _add_files(self, paths):
        """No per-file label prompt -- a modal dialog after each dropped
        file is easy to lose track of (especially with several files at
        once), and was a real risk of making a successful drop LOOK like
        it did nothing. Label defaults to the filename (de-duplicated
        with a numeric suffix if that label's already taken); rename
        afterward via right-click if you want something else."""
        added = []
        for path in paths:
            label = self._unique_label_from_path(path)
            self._perform_write_and_animate(lambda p=path, l=label: self.engine.commit_write(l, p))
            added.append(label)
        if len(added) == 1:
            self._toast(f"Added '{added[0]}'")
        elif added:
            self._toast(f"Added {len(added)} file(s): {', '.join(added)}")

    def _add_file(self, path):
        """Single-file convenience wrapper around _add_files."""
        self._add_files([path])

    # ---------- edit-in-place (open in the OS default app, auto-sync back) ----------

    def _edit_label(self, label):
        """Reconstructs the label's current content to a temp file (with
        an extension HINT derived from its detected phenotype -- purely
        for the OS's own file-association system, so 'open with the
        right app' has its best chance of working; the vault itself
        never stores or needs an extension), opens it in the platform's
        default app via QDesktopServices, then watches that path --
        saving in your editor auto-commits a new generation.

        Two independent detection paths run at once, because inotify-based
        QFileSystemWatcher signals are genuinely unreliable across editors
        in practice, not just in theory: many editors (gedit, VS Code,
        LibreOffice...) save via write-a-new-temp-file-then-rename-over,
        which silently drops the OS-level watch on the ORIGINAL inode --
        sometimes the very first save never fires fileChanged at all, not
        just subsequent ones. So alongside the watcher (fast path, fires
        instantly when it works), _poll_edited_files() checks this file's
        mtime every 1.5s as a backstop that doesn't depend on inotify
        semantics at all -- whichever path notices the change first wins;
        _check_and_commit_edit's mtime gate makes the other one's later,
        redundant check a harmless no-op.

        Re-clicking Edit on a label that's already open does NOT tear down
        the previous session -- it adds a SECOND tracked session alongside
        it. Every open session for a label stays tracked until you save it
        (or its temp file disappears), so switching back to an earlier
        editor tab and saving THERE still lands as a real generation
        instead of silently vanishing. (If you genuinely edit two open
        sessions for the same label independently, whichever commits
        second overwrites the first's changes with its own -- there's no
        merge here, same as saving over someone else's edit in any
        non-locking editor.)"""
        meta = self.engine.get_metadata(label)
        if meta is None:
            return
        ext = _extension_for_phenotype(meta.get("phenotype_name", ""))

        os.makedirs(EDIT_CACHE_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_edit_", suffix=ext, dir=EDIT_CACHE_DIR)
        os.close(fd)
        self.engine.reconstruct_current(label, tmp_path)

        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(tmp_path))
        if not opened:
            QMessageBox.warning(self, "Edit", f"Couldn't find a default app to open this file type.\n"
                                               f"The content is at: {tmp_path}")
            return

        watcher = QFileSystemWatcher([tmp_path], self)
        watcher.fileChanged.connect(lambda path, lbl=label: self._on_edited_file_changed(lbl, path))
        session = {"path": tmp_path, "watcher": watcher, "last_mtime": os.path.getmtime(tmp_path)}
        self._edit_sessions.setdefault(label, []).append(session)
        self._toast(f"Opened '{label}' in your default app -- saving there auto-updates the vault")

    def _view_label(self, label):
        """Read-only open -- same reconstruction as Edit, opened in the
        same default app, but never watched for changes. For when you
        just want to look at something without committing a new
        generation, and so a viewer app's own incidental temp writes
        (playback position caches, etc.) never get mistaken for a real
        edit."""
        meta = self.engine.get_metadata(label)
        if meta is None:
            return
        ext = _extension_for_phenotype(meta.get("phenotype_name", ""))

        os.makedirs(EDIT_CACHE_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_view_", suffix=ext, dir=EDIT_CACHE_DIR)
        os.close(fd)
        self.engine.reconstruct_current(label, tmp_path)

        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(tmp_path))
        if not opened:
            QMessageBox.warning(self, "View", f"Couldn't find a default app to open this file type.\n"
                                               f"The content is at: {tmp_path}")
            return
        self._toast(f"Opened '{label}' read-only -- changes there won't be saved back")

    def _edit_label_inapp(self, label):
        """The real-time path for text content: reconstructs once,
        opens an in-process editor, and Save calls commit_write directly
        -- no temp-file watcher, no polling, no external app, so there's
        no detection lag or sandboxing risk to begin with."""
        if not self.engine.has_label(label):
            return
        os.makedirs(EDIT_CACHE_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_inapp_", suffix=".txt", dir=EDIT_CACHE_DIR)
        os.close(fd)
        self.engine.reconstruct_current(label, tmp_path)
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            initial_text = f.read()

        def on_save(new_text):
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(new_text)
            self._perform_write_and_animate(lambda: self.engine.commit_write(label, tmp_path))
            # Same reasoning as the external-editor auto-sync path: Web
            # mode collapses a label to one node, so the new generation
            # needs Tree mode to actually be visible as a new node.
            self._reveal_in_tree(label)

        dlg = InAppTextEditorDialog(self, label, initial_text, on_save)
        self._active_dialogs.append(dlg)

        def cleanup(_result=None):
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if dlg in self._active_dialogs:
                self._active_dialogs.remove(dlg)

        dlg.finished.connect(cleanup)
        dlg.show()

    def _view_image_inapp(self, label):
        """In-app, read-only, instant -- no external app round trip at
        all for the common raster formats Qt already decodes natively."""
        if not self.engine.has_label(label):
            return
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_imgview_")
        os.close(fd)
        try:
            self.engine.reconstruct_current(label, tmp_path)
            with open(tmp_path, "rb") as f:
                image_bytes = f.read()
        finally:
            os.remove(tmp_path)
        dlg = ImageViewerDialog(self, label, image_bytes)
        self._active_dialogs.append(dlg)
        dlg.finished.connect(lambda _r=None: self._active_dialogs.remove(dlg) if dlg in self._active_dialogs else None)
        dlg.show()

    def _on_edited_file_changed(self, label, path):
        self._check_and_commit_edit(label, path)
        for session in self._edit_sessions.get(label, []):
            if session["path"] == path:
                watcher = session["watcher"]
                if path not in watcher.files() and os.path.exists(path):
                    watcher.addPath(path)  # re-arm after an editor's atomic write-then-rename save
                break

    def _check_and_commit_edit(self, label, path):
        session = next((s for s in self._edit_sessions.get(label, []) if s["path"] == path), None)
        if session is None or not os.path.exists(path):
            return  # some editors briefly remove-then-recreate mid-save; ignore the transient gap
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if mtime <= session["last_mtime"]:
            return  # already committed this exact save (or nothing changed yet)
        session["last_mtime"] = mtime
        try:
            self._perform_write_and_animate(lambda: self.engine.commit_write(label, path))
            self._toast(f"'{label}' updated from your edit -- new generation created")
            # Web mode only ever shows one node per label (its current
            # tip) -- a new generation updates that node in place rather
            # than making anything new appear, which read as "nothing
            # happened" even though the delta-only generation WAS
            # created correctly. Tree mode is where a generation is
            # genuinely its own visible node, so that's what an edit
            # should actually show you.
            self._reveal_in_tree(label)
        except Exception as e:
            self._toast(f"Auto-sync for '{label}' failed: {e}")

    def _poll_edited_files(self):
        """Backstop for _edit_label's watcher -- see its docstring. Ticks
        every 1.5s so a missed inotify event still surfaces within a
        couple seconds instead of silently never syncing. Walks EVERY
        open session for every label, not just the newest one."""
        for label, sessions in list(self._edit_sessions.items()):
            for session in list(sessions):
                path = session["path"]
                self._check_and_commit_edit(label, path)
                watcher = session["watcher"]
                if os.path.exists(path) and path not in watcher.files():
                    watcher.addPath(path)

    def _export_canvas(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export canvas", "pfs_cosmic_web.png", "PNG Images (*.png)")
        if not path:
            return
        rect = self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40)
        if rect.isEmpty():
            return
        image = QImage(rect.size().toSize(), QImage.Format_ARGB32)
        image.fill(QColor(BG))
        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing)
        self.scene.render(painter, target=QRectF(image.rect()), source=rect)
        painter.end()
        image.save(path)
        self._toast(f"Exported canvas to {path}")

    def _cycle_selection(self, direction: int):
        keys = list(self._node_items.keys())
        if not keys:
            return
        selected = self.scene.selectedItems()
        if selected:
            current_key = selected[0].data(0)
            idx = keys.index(current_key) if current_key in keys else -1
        else:
            idx = -1
        new_idx = (idx + direction) % len(keys)
        self.scene.clearSelection()
        target = self._node_items[keys[new_idx]]
        target.setSelected(True)
        self.view.centerOn(target)

    def _open_command_palette(self):
        dlg = CommandPalette(self)
        center = self.view.mapToGlobal(self.view.rect().center())
        dlg.move(center.x() - dlg.width() // 2, max(40, center.y() - 200))
        dlg.show()
        dlg.input.setFocus()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Tab:
            self._cycle_selection(1)
            return
        if event.key() == Qt.Key_Backtab:
            self._cycle_selection(-1)
            return
        if event.key() == Qt.Key_Delete and self._mode == "web":
            selected = self.scene.selectedItems()
            if selected:
                label = selected[0].data(0)
                if label:
                    self._delete_label(label)
                    return
        super().keyPressEvent(event)

    # ---------- speciation-on-write animation ----------

    def _snapshot_keys(self):
        if self._mode == "web":
            return set(self.engine.labels())
        keys = set()
        for label in self.engine.all_labels():
            for node in self.engine.get_history(label):
                keys.add(node.node_uuid)
        return keys

    def _perform_write_and_animate(self, write_fn):
        before = self._snapshot_keys()
        write_fn()
        self._rebuild()
        after = self._snapshot_keys()
        for key in after - before:
            node = self._node_items.get(key)
            if node is None:
                continue
            self._animate_node_appearance(node)
            for edge in list(node.edges):
                self._animate_edge_appearance(edge)
                self._spawn_particle_trail(edge)

    def _track_animation(self, anim):
        self._active_animations.append(anim)
        anim.finished.connect(lambda: self._active_animations.remove(anim) if anim in self._active_animations else None)

    def _track_pending_timer(self, timer):
        """Like _track_animation but for a delayed one-shot QTimer (no
        .finished signal -- uses .timeout instead), so _rebuild() can
        cancel a still-waiting timer the same way it stops an
        already-running animation."""
        self._pending_timers.append(timer)
        timer.timeout.connect(lambda: self._pending_timers.remove(timer) if timer in self._pending_timers else None)

    def _animate_node_appearance(self, node: NodeItem):
        target_radius = node.radius
        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(target_radius)
        anim.setDuration(450)
        anim.setEasingCurve(QEasingCurve.OutBack)
        anim.valueChanged.connect(lambda v: node.set_radius_live(float(v)))
        self._track_animation(anim)
        anim.start()

    def _animate_edge_appearance(self, edge: EdgeItem):
        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(EDGE_REST_OPACITY)
        anim.setDuration(450)
        anim.valueChanged.connect(lambda v: edge.setOpacity(float(v)))
        self._track_animation(anim)
        anim.start()

    def _spawn_particle_trail(self, edge: EdgeItem):
        """A handful of small glowing particles drifting from parent to
        child along the new edge, fading in then out -- sells 'this
        literally came FROM that one' harder than the size-pulse alone.
        Purely decorative scene items; each particle's own animation is
        tracked the same way as everything else (_track_animation), so
        a rebuild mid-flight stops them cleanly instead of leaving a
        dangling reference the way an untracked one would."""
        parent_pos, child_pos = edge.node_a.scenePos(), edge.node_b.scenePos()
        for i in range(4):
            particle = QGraphicsEllipseItem(-3, -3, 6, 6)
            particle.setBrush(QBrush(QColor(ACCENT)))
            particle.setPen(QPen(Qt.NoPen))
            particle.setZValue(1.8)
            particle.setPos(parent_pos)
            particle.setOpacity(0.0)
            self.scene.addItem(particle)

            anim = QVariantAnimation(self)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.setDuration(550)
            anim.setEasingCurve(QEasingCurve.InOutQuad)

            def step(t, particle=particle, parent_pos=parent_pos, child_pos=child_pos):
                t = float(t)
                x = parent_pos.x() + (child_pos.x() - parent_pos.x()) * t
                y = parent_pos.y() + (child_pos.y() - parent_pos.y()) * t
                particle.setPos(x, y)
                particle.setOpacity(math.sin(t * math.pi))

            def cleanup(particle=particle):
                if particle.scene() is not None:
                    self.scene.removeItem(particle)

            anim.valueChanged.connect(step)
            anim.finished.connect(cleanup)
            self._track_animation(anim)

            # A real, OWNED QTimer instead of the QTimer.singleShot
            # static helper -- the static form gives back no handle to
            # cancel, so a still-pending staggered start from an EARLIER
            # write could fire anim.start() after a LATER write's
            # _rebuild() already destroyed this particle's scene item.
            # Tracking it the same way animations are tracked closes
            # that gap (confirmed by reproducing the crash with a rapid-
            # fire-writes stress test before this fix, and confirming it
            # stops after).
            delay_timer = QTimer(self)
            delay_timer.setSingleShot(True)
            delay_timer.timeout.connect(anim.start)
            self._track_pending_timer(delay_timer)
            delay_timer.start(i * 90)

    # ---------- live physics ("organic hydra" behavior) ----------

    def _physics_tick(self):
        if self._physics_paused:
            return
        started = time.perf_counter()
        self._physics_tick_body()
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self._tick_times.append(elapsed_ms)
        if len(self._tick_times) > 30:
            self._tick_times.pop(0)
        if len(self._tick_times) == 30:
            avg_ms = sum(self._tick_times) / len(self._tick_times)
            frame_budget_ms = 33.3
            achievable_fps = min(30.0, 1000.0 / avg_ms) if avg_ms > 0 else 30.0
            self.perf_label.setText(
                f"{len(self._node_items)}n/{len(self._edge_items)}e  "
                f"tick {avg_ms:.2f}ms  ~{achievable_fps:.0f}fps"
            )
            if avg_ms > frame_budget_ms:
                self.perf_label.setStyleSheet(f"color: {ACCENT};")
            else:
                self.perf_label.setStyleSheet("")

    def _physics_tick_body(self):
        for edge in self._edge_items:
            edge.advance_flow(0.6)

        nodes = list(self._node_items.values())
        if len(nodes) < 2:
            return
        REPULSION = 9000.0
        SPRING_K = 0.02
        VERTICAL_K = 0.01
        DAMPING = 0.82
        CENTER_K = 0.0015
        MAX_SPEED = 40.0

        fx = {n: 0.0 for n in nodes}
        fy = {n: 0.0 for n in nodes}

        # Repulsion via a uniform spatial grid instead of all-pairs: at
        # REPULSION=9000, force at 400px is already only 0.056 -- smaller
        # than typical spring/centering forces -- so nodes farther apart
        # than CUTOFF contribute nothing worth computing. All-pairs was
        # measured to be genuinely O(n^2): 100 nodes = 21.8ms/tick (fine),
        # 1000 nodes = 1446ms/tick (unusable, 66x slower for 10x the
        # nodes). Bucketing nodes into CUTOFF-sized cells and only
        # comparing each node against its own + neighboring cells keeps
        # cost roughly proportional to n for any reasonably-spread-out
        # layout, since node DENSITY per cell stays roughly constant as
        # the vault grows rather than every node comparing against every
        # other one regardless of distance.
        CUTOFF = 400.0
        CUTOFF_SQ = CUTOFF * CUTOFF
        grid = {}
        for n in nodes:
            cell = (int(n.pos().x() // CUTOFF), int(n.pos().y() // CUTOFF))
            grid.setdefault(cell, []).append(n)

        # Each unordered pair of cells within touching distance is visited
        # exactly once: (0,0) covers pairs WITHIN a cell, the other four
        # offsets cover each neighboring cell-pair in only one direction.
        NEIGHBOR_OFFSETS = ((0, 0), (1, 0), (0, 1), (1, 1), (-1, 1))
        for (cx, cy), cell_nodes in grid.items():
            for dcx, dcy in NEIGHBOR_OFFSETS:
                other_nodes = grid.get((cx + dcx, cy + dcy))
                if other_nodes is None:
                    continue
                same_cell = dcx == 0 and dcy == 0
                for i, a in enumerate(cell_nodes):
                    ax, ay = a.pos().x(), a.pos().y()
                    others = cell_nodes[i + 1:] if same_cell else other_nodes
                    for b in others:
                        dx = ax - b.pos().x()
                        dy = ay - b.pos().y()
                        dist_sq = dx * dx + dy * dy
                        if dist_sq > CUTOFF_SQ:
                            continue
                        if dist_sq < 1.0:
                            dist_sq = 1.0
                        dist = math.sqrt(dist_sq)
                        force = REPULSION / dist_sq
                        fxi, fyi = (dx / dist) * force, (dy / dist) * force
                        fx[a] += fxi
                        fy[a] += fyi
                        fx[b] -= fxi
                        fy[b] -= fyi

        for edge in self._edge_items:
            a, b = edge.node_a, edge.node_b
            dx = b.pos().x() - a.pos().x()
            dy = b.pos().y() - a.pos().y()
            dist = math.hypot(dx, dy) or 0.01
            stretch = dist - edge.rest_length
            sfx, sfy = (dx / dist) * stretch * SPRING_K, (dy / dist) * stretch * SPRING_K
            fx[a] += sfx
            fy[a] += sfy
            fx[b] -= sfx
            fy[b] -= sfy
            if edge.vertical_bias:
                target_y = a.pos().y() + edge.rest_length
                fy[b] += (target_y - b.pos().y()) * VERTICAL_K

        for n in nodes:
            fx[n] -= n.pos().x() * CENTER_K
            fy[n] -= n.pos().y() * CENTER_K

        # Clade containment ("Outline" mode, web only): a soft leash, not
        # a hard wall -- no force at all inside the leash radius, a
        # gentle pull back in once past it. The centroid is recomputed
        # from CURRENT member positions every tick (not a fixed point
        # frozen when the blob was drawn), so the group can drift or
        # orbit together without the leash fighting that drift -- it
        # only resists a member actually SEPARATING from its own group.
        # A dragged-and-released node re-enters this same force loop the
        # next tick once it's no longer pinned, which is what makes it
        # drift back on its own instead of needing a special-cased snap.
        if self._mode == "web" and self.clade_action.isChecked() and self._clade_membership:
            CONTAINMENT_K = 0.12
            LEASH_FRACTION = 0.7
            groups = {}
            for n in nodes:
                clade_key = self._clade_membership.get(n.data(1))
                if clade_key:
                    groups.setdefault(clade_key, []).append(n)
            for clade_key, members in groups.items():
                if len(members) < 2:
                    continue
                ccx = sum(m.pos().x() for m in members) / len(members)
                ccy = sum(m.pos().y() for m in members) / len(members)
                leash = self._clade_leash_radius.get(clade_key, 150.0) * LEASH_FRACTION
                for m in members:
                    dx = m.pos().x() - ccx
                    dy = m.pos().y() - ccy
                    dist = math.hypot(dx, dy)
                    if dist > leash and dist > 0.01:
                        pull = (dist - leash) * CONTAINMENT_K
                        fx[m] -= (dx / dist) * pull
                        fy[m] -= (dy / dist) * pull

        for n in nodes:
            if n.pinned:
                n.vx = n.vy = 0.0
                continue
            n.vx = (n.vx + fx[n]) * DAMPING
            n.vy = (n.vy + fy[n]) * DAMPING
            speed = math.hypot(n.vx, n.vy)
            if speed > MAX_SPEED:
                n.vx = n.vx / speed * MAX_SPEED
                n.vy = n.vy / speed * MAX_SPEED
            if abs(n.vx) > 0.02 or abs(n.vy) > 0.02:
                n.setPos(n.pos().x() + n.vx, n.pos().y() + n.vy)

        # Slow "galaxy" swirl (web mode only, per explicit request --
        # NOT tree/clade-tree, where a rotating genealogy would just be
        # confusing). Implemented as a RIGID rotation of every unpinned
        # node (and, so they stay visually attached to their contents,
        # every clade blob) around the origin by a small fixed angle
        # each tick. A rigid rotation preserves every pairwise distance
        # exactly, so it doesn't fight repulsion/spring/containment at
        # all -- those forces reach the same equilibrium SHAPE, which
        # then just slowly turns. ~0.0012 rad/tick at 30fps is one full
        # revolution in about 3 minutes -- deliberately slow, not "spinny."
        if self._mode == "web" and self.swirl_action.isChecked():
            ORBIT_ANGULAR_SPEED = 0.0012
            cos_a, sin_a = math.cos(ORBIT_ANGULAR_SPEED), math.sin(ORBIT_ANGULAR_SPEED)
            for n in nodes:
                if n.pinned:
                    continue
                x, y = n.pos().x(), n.pos().y()
                n.setPos(x * cos_a - y * sin_a, x * sin_a + y * cos_a)
            for blob in self._clade_blob_items:
                x, y = blob.pos().x(), blob.pos().y()
                blob.setPos(x * cos_a - y * sin_a, x * sin_a + y * cos_a)


def _existing_vault_engine(storage_root: str):
    """Returns 'python', 'cpp', or None -- same check pfs_cli.py's
    CppPFSShell/PFSShell use before either engine touches a directory.
    Necessary because the two engines' data_container.bin and
    global_index.db use the SAME filenames despite incompatible
    formats -- only the catalog/keyring filenames actually differ."""
    from vault_session import CATALOG_FILENAME
    from gearhash.keyring import KEYRING_FILENAME
    is_python = os.path.exists(os.path.join(storage_root, CATALOG_FILENAME)) or \
        os.path.exists(os.path.join(storage_root, KEYRING_FILENAME))
    is_cpp = os.path.exists(os.path.join(storage_root, "catalog.pfsc")) or \
        os.path.exists(os.path.join(storage_root, "keyring.pfsk"))
    if is_python:
        return "python"
    if is_cpp:
        return "cpp"
    return None


def _open_python_engine(storage_root: str):
    existing = _existing_vault_engine(storage_root)
    if existing == "cpp":
        QMessageBox.critical(None, "Wrong Engine", f"'{storage_root}' is a C++-engine vault "
                              f"(catalog.pfsc/keyring.pfsk present). Relaunch with --engine cpp.")
        return None

    session = VaultSession(storage_root)

    def get_new_passphrase():
        pw1, ok1 = QInputDialog.getText(None, "New Vault", "Set a new vault passphrase:", QLineEdit.Password)
        if not ok1:
            sys.exit(0)
        pw2, ok2 = QInputDialog.getText(None, "New Vault", "Confirm passphrase:", QLineEdit.Password)
        if not ok2:
            sys.exit(0)
        return pw1, pw2

    def get_existing_passphrase():
        pw, ok = QInputDialog.getText(None, "Unlock Vault", f"Passphrase for {storage_root}:", QLineEdit.Password)
        if not ok:
            sys.exit(0)
        return pw

    def confirm_reset():
        result = QMessageBox.warning(
            None, "Vault Mismatch",
            "This vault's other files don't decrypt under this key. Discard them and start fresh?",
            QMessageBox.Yes | QMessageBox.No,
        )
        return result == QMessageBox.Yes

    try:
        session.unlock_or_create(get_new_passphrase, get_existing_passphrase, confirm_reset)
    except VaultUnlockError as e:
        QMessageBox.critical(None, "Unlock Failed", str(e))
        return None
    return PythonEngineAdapter(session)


def _open_cpp_engine(storage_root: str):
    from gearhash.master_key_store import create_new_vault_key, load_vault_key, WrongPassphraseError, MASTER_KEY_FILENAME
    from pfs_engine_binding import CppVaultSession, PfsEngineError

    existing = _existing_vault_engine(storage_root)
    if existing == "python":
        QMessageBox.critical(None, "Wrong Engine", f"'{storage_root}' is a Python-engine vault "
                              f"(catalog.enc/keyring.enc present). Relaunch without --engine cpp.")
        return None

    os.makedirs(storage_root, exist_ok=True)
    key_path = os.path.join(storage_root, MASTER_KEY_FILENAME)
    vault_existed = os.path.exists(key_path)

    if not vault_existed:
        pw1, ok1 = QInputDialog.getText(None, "New C++ Vault", "Set a new vault passphrase:", QLineEdit.Password)
        if not ok1:
            sys.exit(0)
        pw2, ok2 = QInputDialog.getText(None, "New C++ Vault", "Confirm passphrase:", QLineEdit.Password)
        if not ok2:
            sys.exit(0)
        if pw1 != pw2:
            QMessageBox.critical(None, "Unlock Failed", "Passphrases didn't match.")
            return None
        kek = create_new_vault_key(storage_root, pw1)
    else:
        pw, ok = QInputDialog.getText(None, "Unlock C++ Vault", f"Passphrase for {storage_root}:", QLineEdit.Password)
        if not ok:
            sys.exit(0)
        try:
            kek = load_vault_key(storage_root, pw)
        except WrongPassphraseError:
            QMessageBox.critical(None, "Unlock Failed", "Wrong passphrase.")
            return None

    try:
        session = CppVaultSession(storage_root, kek)
    except PfsEngineError as e:
        QMessageBox.critical(None, "Unlock Failed", f"Couldn't open the C++ vault: {e}")
        return None
    return CppEngineAdapter(session)


def main():
    parser = argparse.ArgumentParser(description="PFS Cosmic Web GUI")
    parser.add_argument("storage_root", help="vault directory")
    parser.add_argument("--engine", choices=["python", "cpp"], default="python",
                         help="storage backend -- 'python' (default) or 'cpp' (the compiled "
                              "engine, same GUI feature set -- see manual.txt PART 10). A vault "
                              "belongs to the engine that created it; the other engine refuses "
                              "to open it.")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setApplicationName("PFS Cosmic Web")
    app.setStyleSheet(STYLESHEET)

    engine = _open_cpp_engine(args.storage_root) if args.engine == "cpp" else _open_python_engine(args.storage_root)
    if engine is None:
        sys.exit(1)

    window = VaultGraphWindow(engine)
    window.show()
    rc = app.exec()
    engine.stop_clade_worker()
    sys.exit(rc)


if __name__ == "__main__":
    main()
