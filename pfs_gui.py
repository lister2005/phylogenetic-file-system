"""
PFS Cosmic Web View: desktop GUI over a vault (either engine, through
pfs_engine_adapter), in the same process -- no IPC, no FUSE.

Views: Cosmic Web (one node per label, laid out by similarity), Lineage
Tree (every generation; branches colored and curved; merge from the
context menu) and Clade Tree (UPGMA or Neighbor-Joining dendrogram).
A force simulation runs continuously; dragging pins a node.

Overlays: search, Time Machine slider, clade outlines (background clade
worker), dedup heat, minimap, stats HUD. Writes go through the same
session methods as the CLI.
"""
import argparse
import sys
import os
import math
import tempfile
import time
import difflib
import html
import shlex
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QGraphicsView, QGraphicsScene,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsSimpleTextItem,
    QGraphicsRectItem, QGraphicsItem, QGraphicsTextItem,
    QInputDialog, QLineEdit, QMessageBox, QDockWidget, QTextEdit,
    QStatusBar, QToolBar, QSlider, QLabel, QPushButton, QMenu, QFileDialog,
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QTableWidget, QTableWidgetItem,
    QWidget, QHeaderView, QPlainTextEdit, QScrollArea, QToolTip, QComboBox, QCheckBox,
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
from gearhash.phenotype import detect as detect_phenotype, detect_from_file
from secret_store import SECRET_TAG, auto_lock_seconds, is_secret, masked_changes, summarize_variable
import restricted
from gearhash.master_key_store import UserError
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

# One hue per detected format.
_COLOR_RULES = [
    ("PDF", "#4c8bf5"), ("Text", "#5aa9e6"),
    ("PNG", "#e8a33d"), ("JPEG", "#f2b705"), ("GIF", "#f4d35e"), ("BMP", "#eec170"),
    ("MP3", "#8e5fd6"), ("MP4", "#a06cd5"), ("RIFF", "#c77dff"),
    ("ZIP", "#4caf6e"), ("GZIP", "#6fcf97"),
    ("ELF", "#e05252"), ("SQLite", "#2fb6b2"),
]
_UNKNOWN_COLOR = "#7a7a85"

# Extension hint for the temporary copy handed to an external app; the
# vault itself stores no extensions.
_PHENOTYPE_EXTENSION_RULES = [
    ("PDF", ".pdf"), ("PNG", ".png"), ("JPEG", ".jpg"), ("GIF", ".gif"), ("BMP", ".bmp"),
    ("MP3", ".mp3"), ("MP4", ".mp4"), ("RIFF", ".wav"), ("ZIP", ".zip"), ("GZIP", ".gz"),
    ("SQLite", ".sqlite"), ("ELF", ""), ("Text", ".txt"),
]


def _extension_for_phenotype(name: str) -> str:
    """Returns a file extension (such as '.pdf') matching a detected file type, or '' if unknown."""
    for keyword, ext in _PHENOTYPE_EXTENSION_RULES:
        if keyword.lower() in name.lower():
            return ext
    return ""


# Monochrome symbols, not emoji: color-emoji fonts ignore the item's brush.
_PHENOTYPE_GLYPH_RULES = [
    ("PDF", "▤"), ("Text", "▤"),
    ("PNG", "▧"), ("JPEG", "▧"), ("GIF", "▧"), ("BMP", "▧"),
    ("MP3", "♪"), ("MP4", "▶"), ("RIFF", "♪"),
    ("ZIP", "▦"), ("GZIP", "▦"),
    ("ELF", "⚙"), ("SQLite", "▥"),
]
_UNKNOWN_GLYPH = "◆"


def _glyph_for_phenotype(name: str) -> str:
    """Returns the small symbol drawn on a node for its file type."""
    for keyword, glyph in _PHENOTYPE_GLYPH_RULES:
        if keyword.lower() in name.lower():
            return glyph
    return _UNKNOWN_GLYPH


# Phenotypes opened in an in-app editor/viewer (Qt handles them natively);
# everything else goes to the OS default app.
_INAPP_TEXT_PHENOTYPES = {"Plain Text"}
_INAPP_IMAGE_PHENOTYPES = {"PNG Image", "JPEG Image", "GIF Image", "BMP Image"}


def _is_inapp_text_phenotype(name: str) -> bool:
    """True if files of this type can be edited in the app's text editor."""
    return name in _INAPP_TEXT_PHENOTYPES


def _is_inapp_image_phenotype(name: str) -> bool:
    """True if files of this type can be shown in the app's image viewer."""
    return name in _INAPP_IMAGE_PHENOTYPES


_LATERAL_EDGE_COLOR = "#a98ef0"
_DEFAULT_EDGE_COLOR = "#7f93bf"
_HEATMAP_LOW = "#e0524a"
_HEATMAP_HIGH = ACCENT
BRANCH_COLORS = ["#e08a3d", "#4c8bf5", "#4caf6e", "#e05252", "#c96fd6"]

# Lineage diff colors: red = removed, green = changed, brighter green = new.
_DIFF_UNCHANGED_COLOR = "#3a3d4a"
_DIFF_CHANGED_COLOR = "#4caf6e"
_DIFF_NEW_COLOR = "#8ee6a8"
_DIFF_DELETED_COLOR = "#e05252"

# Resting opacity of a normal edge; every edge state and animation reads this one value.
EDGE_REST_OPACITY = 0.94


def _color_for_phenotype(name: str) -> QColor:
    """Returns the node colour for a file type."""
    for keyword, color in _COLOR_RULES:
        if keyword.lower() in name.lower():
            return QColor(color)
    return QColor(_UNKNOWN_COLOR)


def _heatmap_color(dedup_fraction: float) -> QColor:
    """Blends from the 'mostly unique' to the 'mostly shared' colour for Dedup Heat."""
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

# Under $HOME, not /tmp: confined Snap apps get a private /tmp and
# couldn't open files placed there.
# Time Machine preview: shown this long after the slider stops; text files
# up to this size show their first lines.
TIME_PREVIEW_DELAY_MS = 400
TIME_PREVIEW_MAX_BYTES = 5 * 1024 * 1024
TIME_PREVIEW_LINES = 12
TIME_PREVIEW_LINE_CHARS = 120

# How long the Clade Tree view waits for the background tree before
# building it itself.
CLADE_TREE_WAIT_SECONDS = 5.0
EDIT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "pfs_gui_edit")

# Light theme. Data colors (phenotypes, branches, heat) are shared by both
# themes; only the chrome and canvas change.
LIGHT_ACCENT = "#0d9488"
LIGHT_ACCENT_DIM = "#99f2e4"
LIGHT_BG = "#f3f4f6"
LIGHT_PANEL_BG = "#ffffff"
LIGHT_INPUT_BG = "#eef0f3"
LIGHT_BORDER = "#d6dae1"
LIGHT_TEXT = "#1a1d24"
LIGHT_TEXT_DIM = "#5b6270"


def _build_stylesheet(accent, accent_dim, bg, panel_bg, input_bg, border, text, text_dim, hover_bg):
    """Builds the Qt stylesheet for a theme from its colours."""
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
    """A file (web / clade-tree leaf) or one generation (lineage tree).
    While `pinned` (being dragged) the simulation reads its position but
    doesn't move it.
    """

    def __init__(self, radius: float, display_text: str, base_color: QColor, glyph: str = ""):
        """Creates a node: its circle, hover halo and name label, ready for the physics simulation."""
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

        # Always-visible type glyph (the label shows only on hover).
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
        """Fills the node with a soft radial gradient of its colour."""
        gradient = QRadialGradient(0, 0, self.radius)
        gradient.setColorAt(0.0, base_color.lighter(150))
        gradient.setColorAt(1.0, base_color.darker(115))
        self.setBrush(QBrush(gradient))
        self._pen_normal = QPen(base_color.lighter(140), 1.4)
        self._pen_hover = QPen(QColor(ACCENT), 2.6)
        if not self._hovering:
            self.setPen(self._pen_normal)

    def set_focus_dim(self, dimmed: bool):
        """Out-of-focus look for search/trace: desaturate toward gray (a per-item blur would cost too much per frame)."""
        if dimmed:
            hsv = self._base_color.toHsv()
            desat = QColor.fromHsv(hsv.hue(), int(hsv.saturation() * 0.12), hsv.value())
            self._apply_color(desat)
        else:
            self._apply_color(self._base_color)

    def mark_pulsing(self, pulsing: bool):
        """Marks that a pulse animation owns this node's halo. The window owns
        and tracks the animation, so _rebuild() stops it before the item is
        destroyed.
        """
        self._pulsing = pulsing
        if not pulsing and not self._hovering:
            self.halo.setVisible(False)
            self.halo.setOpacity(1.0)

    def itemChange(self, change, value):
        """Keeps attached lines following the node when it moves."""
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self.edges:
                edge.sync_position()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        """Hover: highlights the node and shows its name."""
        self._hovering = True
        self.setPen(self._pen_hover)
        self.halo.setVisible(True)
        self.halo.setOpacity(1.0)
        self.label_bg.setVisible(True)
        self.label_text.setVisible(True)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        """Hover ends: hides the name and highlight."""
        self._hovering = False
        self.setPen(self._pen_normal)
        self.label_bg.setVisible(False)
        self.label_text.setVisible(False)
        if not self._pulsing:
            self.halo.setVisible(False)
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):
        """Pins the node while it is being dragged, so the simulation doesn't move it."""
        self.pinned = True
        self.vx = self.vy = 0.0
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """Releases the node back to the simulation after a drag."""
        self.pinned = False
        super().mouseReleaseEvent(event)

    def set_radius_live(self, radius: float):
        """Resizes the node and its halo while it is animating."""
        self.setRect(QRectF(-radius, -radius, radius * 2, radius * 2))
        self.halo.setRect(QRectF(-radius * 1.6, -radius * 1.6, radius * 3.2, radius * 3.2))


class EdgeItem(QGraphicsLineItem):
    """A directed edge (parent -> child) with a cosmetic pen, so its width is
    in screen pixels and it stays visible at any zoom.
    """

    ARROW_LENGTH = 8.0
    ARROW_WIDTH = 6.0

    def __init__(self, node_a: NodeItem, node_b: NodeItem, dashed: bool, color: QColor,
                 rest_length: float = WEB_EDGE_REST_LENGTH, vertical_bias: bool = False):
        """Creates a line between two nodes, with the spring length the simulation should keep."""
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
            pen.setDashPattern([4.0, 2.5])  # denser than Qt's default dash, which reads as faint
        self.setPen(pen)
        self.setOpacity(EDGE_REST_OPACITY)
        self.setZValue(0)
        self._originally_dashed = dashed
        self.flow_active = False
        self.sync_position()

    def sync_position(self):
        """Moves the line to follow its two nodes."""
        self.setLine(QLineF(self.node_a.scenePos(), self.node_b.scenePos()))

    def set_flow_active(self, active: bool):
        """Slow marching dashes on edges touching a recently edited node."""
        self.flow_active = active
        pen = self.pen()
        if active:
            pen.setStyle(Qt.CustomDashLine)
            pen.setDashPattern([2.5, 3.5])
        elif self._originally_dashed:
            pen.setStyle(Qt.CustomDashLine)
            pen.setDashPattern([4.0, 2.5])
        else:
            pen.setStyle(Qt.SolidLine)
            pen.setDashOffset(0.0)
        self.setPen(pen)

    def advance_flow(self, delta: float):
        """Moves the dash pattern along, so dashed lines appear to flow."""
        if not self.flow_active:
            return
        pen = self.pen()
        pen.setDashOffset(pen.dashOffset() + delta)
        self.setPen(pen)

    def paint(self, painter, option, widget=None):
        """Draws the line plus an arrowhead pointing from parent to child."""
        super().paint(painter, option, widget)
        p1, p2 = self.line().p1(), self.line().p2()
        dx, dy = p2.x() - p1.x(), p2.y() - p1.y()
        length = math.hypot(dx, dy)
        if length < 1.0:
            return
        ux, uy = dx / length, dy / length
        # Stop short of node_b so the arrowhead isn't hidden under it.
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
    """A branch edge drawn as a quadratic curve, so branches leaving the same
    fork fan out instead of overlapping. curve_offset comes from
    _compute_branch_visuals. Physics treats it like any other edge.
    """

    def __init__(self, node_a, node_b, color, curve_offset, rest_length, vertical_bias):
        """Creates a curved line, used for branches in the Tree view."""
        super().__init__(node_a, node_b, dashed=False, color=color,
                          rest_length=rest_length, vertical_bias=vertical_bias)
        self.curve_offset = curve_offset
        pen = self.pen()
        pen.setWidthF(2.8)
        self.setPen(pen)

    def _control_point(self):
        """Returns the control point that bends the curve to one side."""
        p1, p2 = self.line().p1(), self.line().p2()
        mx, my = (p1.x() + p2.x()) / 2, (p1.y() + p2.y()) / 2
        dx, dy = p2.x() - p1.x(), p2.y() - p1.y()
        length = math.hypot(dx, dy) or 1.0
        px, py = -dy / length, dx / length
        return QPointF(mx + px * self.curve_offset, my + py * self.curve_offset)

    def boundingRect(self):
        """Returns the area the curve and its arrowhead cover, for redrawing."""
        p1, p2 = self.line().p1(), self.line().p2()
        cp = self._control_point()
        xs, ys = (p1.x(), p2.x(), cp.x()), (p1.y(), p2.y(), cp.y())
        pad = self.ARROW_LENGTH + 8
        return QRectF(min(xs) - pad, min(ys) - pad, max(xs) - min(xs) + 2 * pad, max(ys) - min(ys) + 2 * pad)

    def paint(self, painter, option, widget=None):
        # Draws its own curve and arrowhead instead of EdgeItem's straight line.
        """Draws the curved line and its arrowhead."""
        p1, p2 = self.line().p1(), self.line().p2()
        cp = self._control_point()
        path = QPainterPath()
        path.moveTo(p1)
        path.quadTo(cp, p2)
        painter.setPen(self.pen())
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)

        # Arrowhead follows the curve's end tangent.
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
    """Pan, drag, zoom and drop. Manual panning (NoDrag) lets a click on empty
    canvas pan while a click on a node moves it. Right-click is handled in
    mousePressEvent because contextMenuEvent proved unreliable.
    """

    # Far below any fit-to-view scale, so zoom-out never freezes.
    MIN_SCALE = 0.0008
    MAX_SCALE = 20.0

    zoomChanged = Signal(float)
    nodeContextMenuRequested = Signal(object, QPoint)  # (node, LOCAL viewport pos)
    filesDropped = Signal(list)
    viewChanged = Signal()
    nodeDoubleClicked = Signal(object)

    def __init__(self, scene, parent=None):
        """Sets up the map view: smooth drawing, zoom under the mouse, drag and drop."""
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
        # Adapters: valueChanged passes an int, viewChanged takes none.
        self.horizontalScrollBar().valueChanged.connect(lambda _v: self.viewChanged.emit())
        self.verticalScrollBar().valueChanged.connect(lambda _v: self.viewChanged.emit())

    def apply_theme(self, bg_hex: str, grid_dot_rgba: tuple):
        """Applies a theme's background and grid-dot colours."""
        self.bg_color = QColor(bg_hex)
        self.grid_dot_color = QColor(*grid_dot_rgba)
        self.setBackgroundBrush(QBrush(self.bg_color))
        self.viewport().update()

    def drawBackground(self, painter, rect):
        """Draws the background: the dot grid and a soft vignette."""
        super().drawBackground(painter, rect)

        # Vignette over the current viewport, so it stays fixed to the window.
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
        """Draws the bright border shown while files are dragged over the map."""
        super().drawForeground(painter, rect)
        if self._drag_active:
            # Drop-zone highlight: shows the drag reached Qt at all.
            pen = QPen(QColor(ACCENT))
            pen.setWidth(4)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(rect.adjusted(4, 4, -4, -4))

    def wheelEvent(self, event):
        """Zooms with the mouse wheel or a two-finger scroll."""
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
        """Zooms by a factor, within the minimum and maximum zoom."""
        current = self.transform().m11()
        target = max(self.MIN_SCALE, min(self.MAX_SCALE, current * factor))
        applied = target / current
        if abs(applied - 1.0) < 1e-6:
            return
        self.scale(applied, applied)
        self.zoomChanged.emit(target)
        self.viewChanged.emit()

    def event(self, evt):
        # Trackpad pinch arrives as a NativeGesture, which wheelEvent never sees.
        """Handles touchpad pinch-to-zoom, which arrives as a separate gesture event."""
        if evt.type() == QEvent.NativeGesture and evt.gestureType() == Qt.ZoomNativeGesture:
            self._apply_zoom_factor(1.0 + evt.value())
            return True
        return super().event(evt)

    def mouseDoubleClickEvent(self, event):
        """Double-click on a node zooms in on it and its neighbours."""
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
        """Right-click opens a node's menu; left-click on empty space starts moving the view."""
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
        """Moves the view while dragging empty space."""
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
        """Stops moving the view when the mouse is released."""
        if self._panning and event.button() == Qt.LeftButton:
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def dragEnterEvent(self, event):
        """Accepts files dragged in from a file manager and shows the drop border."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._drag_active = True
            self.viewport().update()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        """Keeps accepting the drag while it moves over the map."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dragLeaveEvent(self, event):
        """Hides the drop border when the drag leaves the map."""
        self._drag_active = False
        self.viewport().update()
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        """Adds the dropped files to the vault."""
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
    """Overview sharing the main scene; drawForeground marks the visible region."""

    def __init__(self, scene, main_view: CanvasView, parent=None):
        """Sets up the small overview map in the corner."""
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
        """Fits the whole map into the overview."""
        rect = self.scene().itemsBoundingRect()
        if not rect.isEmpty():
            self.fitInView(rect.adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)
        self.viewport().update()

    def drawForeground(self, painter, rect):
        """Draws the rectangle showing which part of the map is on screen."""
        super().drawForeground(painter, rect)
        visible = self.main_view.mapToScene(self.main_view.viewport().rect()).boundingRect()
        pen = QPen(QColor(ACCENT))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawRect(visible)


# ---------- command palette ("Lineage Shell") ----------
# Handlers take (window, *args) and call real session/window methods; a
# wrong argument count shows a usage hint.

def _cmd_write(window, label=None):
    """Palette 'write': asks for a file and adds it, optionally under a given name."""
    path, _ = QFileDialog.getOpenFileName(window, "Choose a file to add")
    if not path:
        return
    label = label or window._unique_label_from_path(path)
    window._perform_write_and_animate(lambda: window.engine.commit_write(label, path))
    window._toast(f"Added '{label}'")


def _cmd_delete(window, label):
    """Palette 'delete': deletes a file (asks first)."""
    window._delete_label(label)


def _cmd_rename(window, old, new):
    """Palette 'rename'."""
    window._rename_label_direct(old, new)


def _cmd_duplicate(window, label, new_label):
    """Palette 'duplicate'."""
    window._duplicate_label_direct(label, new_label)


def _cmd_fork(window, label, generation):
    """Palette 'fork': starts a branch from an older generation."""
    window._fork_from_generation_action(label, int(generation))


def _cmd_merge(window, label):
    """Palette 'merge': merges two branches of a file."""
    window._merge_action_for_label(label)


def _cmd_graft(window, label_a, label_b, new_label):
    """Palette 'graft': makes a new file descended from two files."""
    window._perform_write_and_animate(
        lambda: window.engine.graft(label_a, label_b, new_label)
    )
    window._toast(f"Grafted '{label_a}' + '{label_b}' -> '{new_label}'")


def _parse_tag_value(raw):
    """true/false/yes/no/1/0 become booleans, as in pfs_cli.py -- the C++
    engine's 'protected' check needs a real boolean, not the string.
    """
    if not isinstance(raw, str):
        return raw
    lowered = raw.lower()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    return raw


def _cmd_tag(window, label, key, value="true"):
    """Palette 'tag': sets a tag (the value defaults to true)."""
    window.engine.set_tag(label, key, _parse_tag_value(value))
    window._toast(f"Tagged '{label}': {key}={value}")
    window._rebuild()


def _cmd_untag(window, label, key):
    """Palette 'untag': removes a tag."""
    window.engine.remove_tag(label, key)
    window._toast(f"Untagged '{label}': {key}")
    window._rebuild()


def _cmd_prune(window, label, generation):
    """Palette 'prune': frees an old generation's storage (asks first)."""
    window._prune_generation_action(label, int(generation))


def _cmd_checkout(window, label, generation):
    """Palette 'checkout': saves an old generation to a file."""
    window._checkout_generation(label, int(generation))


def _cmd_edit(window, label):
    """Palette 'edit': edits the file in the user's own program."""
    window._edit_label(label)


def _cmd_view(window, label):
    """Palette 'view': opens a read-only copy in the user's own program."""
    window._view_label(label)


def _cmd_view_generation(window, label, generation):
    """Palette 'viewgen': shows an old generation read-only."""
    window._view_generation(label, int(generation))


def _cmd_edit_inapp(window, label):
    """Palette 'editinapp': edits text inside the app."""
    window._edit_label_inapp(label)


def _cmd_view_image(window, label):
    """Palette 'viewimage': shows an image inside the app."""
    window._view_image_inapp(label)


def _cmd_search(window, *text_parts):
    """Palette 'search': fills in the search box."""
    window.search_box.setText(" ".join(text_parts))


def _cmd_focus(window):
    """Palette 'focus': fits everything on screen."""
    window._fit_to_view()


def _cmd_web(window):
    """Palette 'web': switches to the Web view."""
    window._set_mode("web")


def _cmd_tree(window):
    """Palette 'tree': switches to the Tree view."""
    window._set_mode("tree")


def _cmd_cladetree(window):
    """Palette 'cladetree': switches to the Clade Tree view."""
    window._set_mode("cladetree")


def _cmd_upgma(window):
    """Palette 'upgma': builds the Clade Tree with UPGMA."""
    window._set_clade_algorithm("upgma")


def _cmd_nj(window):
    """Palette 'nj': builds the Clade Tree with Neighbour-Joining."""
    window._set_clade_algorithm("nj")


def _cmd_export(window):
    """Palette 'export': saves the map as a PNG."""
    window._export_canvas()


def _cmd_sort(window, *_args):
    """Palette 'sort': opens the Sort/List table."""
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
    "viewgen": ("<label> <generation>", _cmd_view_generation),
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
    """Ctrl+K command box: filters as you type, Enter runs the top match."""

    def __init__(self, window):
        """Builds the palette popup: a text box and a list of matching commands."""
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
        """Shows the commands that match what has been typed so far."""
        self.suggestions.clear()
        cmd = text.split()[0].lower() if text.split() else ""
        for name, (usage, _fn) in sorted(COMMAND_REGISTRY.items()):
            if not cmd or name.startswith(cmd):
                self.suggestions.addItem(f"{name}  {usage}".strip())

    def _execute(self):
        """Runs the typed command, explaining mistakes (unknown command, wrong arguments, bad quotes)."""
        text = self.input.text().strip()
        self.close()
        if not text:
            return
        try:
            parts = shlex.split(text)  # quotes group words: rename "my file" "new name"
        except ValueError:
            self.window._toast("Couldn't read that command -- check your quotes")
            return
        if not parts:
            return
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
    """In-process text editor: Save commits a new generation directly. Stays
    open, so each Save is another generation.
    """

    def __init__(self, parent, label: str, initial_text: str, on_save_callback):
        """Builds the in-app text editor; on_save_callback stores each save as a new version."""
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
        """Saves the text as a new version and shows the result."""
        text = self.editor.toPlainText()
        try:
            self._on_save_callback(text)
            self.status_label.setText("Saved -- new generation created")
        except Exception as e:
            self.status_label.setText(f"Save failed: {e}")


class ConflictResolutionDialog(QDialog):
    """Lets the user settle each conflicting chunk position of a merge by
    choosing branch A's or branch B's version. Merge stays disabled until
    every position has a choice.
    """

    def __init__(self, parent, label, generation_a, generation_b, positions, describe):
        """Builds the window that lists each clashing piece with a choice of branch A or B."""
        super().__init__(parent)
        self.setWindowTitle(f"Resolve merge conflicts -- {label}")
        self.resize(640, 460)
        self.positions = list(positions)
        layout = QVBoxLayout(self)
        intro = QLabel(
            f"Generations {generation_a} (A) and {generation_b} (B) changed {len(self.positions)} "
            f"part(s) of '{label}' in different ways. Choose which version of each part to keep. "
            f"Nothing is saved until you press Merge.", self)
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.table = QTableWidget(len(self.positions), 2, self)
        self.table.setHorizontalHeaderLabels(["Part (chunk position)", "Keep"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.combos = []
        for row, pos in enumerate(self.positions):
            self.table.setItem(row, 0, QTableWidgetItem(str(pos)))
            combo = QComboBox(self.table)
            combo.addItem("Choose...", None)
            combo.addItem(f"A -- generation {generation_a} ({describe('a', pos)})", "a")
            combo.addItem(f"B -- generation {generation_b} ({describe('b', pos)})", "b")
            combo.currentIndexChanged.connect(self._update_merge_button)
            self.table.setCellWidget(row, 1, combo)
            self.combos.append(combo)
        layout.addWidget(self.table)

        buttons = QHBoxLayout()
        all_a = QPushButton(f"All from A (gen {generation_a})", self)
        all_a.clicked.connect(lambda: self.choose_all("a"))
        all_b = QPushButton(f"All from B (gen {generation_b})", self)
        all_b.clicked.connect(lambda: self.choose_all("b"))
        buttons.addWidget(all_a)
        buttons.addWidget(all_b)
        buttons.addStretch(1)
        self.merge_button = QPushButton("Merge", self)
        self.merge_button.clicked.connect(self.accept)
        cancel = QPushButton("Cancel", self)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(self.merge_button)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)
        self._update_merge_button()

    def choose_all(self, side):
        """Chooses the same branch for every clash."""
        for combo in self.combos:
            combo.setCurrentIndex(combo.findData(side))

    def resolutions(self):
        """{position: 'a' or 'b'} for every chosen row."""
        return {pos: combo.currentData() for pos, combo in zip(self.positions, self.combos)
                if combo.currentData() is not None}

    def _update_merge_button(self, *_):
        """Enables Merge only once every clash has a choice."""
        self.merge_button.setEnabled(len(self.resolutions()) == len(self.positions))


class LineConflictDialog(QDialog):
    """Lets the user settle each conflict of a line-by-line merge: keep
    branch A's lines, branch B's, or both (A's first). For a secret file the
    lines themselves are hidden. Merge stays disabled until every conflict
    has a choice.
    """

    def __init__(self, parent, label, generation_a, generation_b, conflicts, hide_lines=False):
        """Builds one row per conflict: where it is, both versions' lines, and a choice."""
        super().__init__(parent)
        self.setWindowTitle(f"Resolve merge conflicts -- {label}")
        self.resize(820, 600)
        self.conflicts = list(conflicts)
        layout = QVBoxLayout(self)
        intro = QLabel(
            f"Generations {generation_a} (A) and {generation_b} (B) changed the same lines of '{label}' in "
            f"different ways in {len(self.conflicts)} place(s). Everything else was merged automatically. "
            f"Choose what to keep in each place; nothing is saved until you press Merge.", self)
        intro.setWordWrap(True)
        layout.addWidget(intro)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        body = QWidget(scroll)
        body_layout = QVBoxLayout(body)
        self.combos = []
        for conflict in self.conflicts:
            heading = QLabel(f"<b>Conflict {conflict.index + 1}</b> -- {conflict.lines_description()}", body)
            body_layout.addWidget(heading)
            if hide_lines:
                note = QLabel(f"A: {len(conflict.a)} line(s), B: {len(conflict.b)} line(s). "
                              f"Hidden because this file is secret.", body)
                body_layout.addWidget(note)
            else:
                row = QHBoxLayout()
                for side, lines in (("A", conflict.a), ("B", conflict.b)):
                    column = QVBoxLayout()
                    column.addWidget(QLabel(f"{side} -- generation {generation_a if side == 'A' else generation_b}",
                                            body))
                    view = QPlainTextEdit(body)
                    view.setReadOnly(True)
                    view.setPlainText("".join(lines) if lines else "(these lines removed)")
                    view.setMaximumHeight(120)
                    column.addWidget(view)
                    row.addLayout(column)
                body_layout.addLayout(row)
            combo = QComboBox(body)
            combo.addItem("Choose...", None)
            combo.addItem(f"Keep A (generation {generation_a})", "a")
            combo.addItem(f"Keep B (generation {generation_b})", "b")
            combo.addItem("Keep both (A, then B)", "both")
            combo.currentIndexChanged.connect(self._update_merge_button)
            body_layout.addWidget(combo)
            self.combos.append(combo)
        body_layout.addStretch(1)
        scroll.setWidget(body)
        layout.addWidget(scroll, stretch=1)

        buttons = QHBoxLayout()
        for text, side in ((f"All from A (gen {generation_a})", "a"), (f"All from B (gen {generation_b})", "b"),
                           ("All: keep both", "both")):
            button = QPushButton(text, self)
            button.clicked.connect(lambda _checked=False, side=side: self.choose_all(side))
            buttons.addWidget(button)
        buttons.addStretch(1)
        self.merge_button = QPushButton("Merge", self)
        self.merge_button.clicked.connect(self.accept)
        cancel = QPushButton("Cancel", self)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(self.merge_button)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)
        self._update_merge_button()

    def choose_all(self, side):
        """Makes the same choice for every conflict."""
        for combo in self.combos:
            combo.setCurrentIndex(combo.findData(side))

    def choices(self):
        """{conflict index: 'a', 'b' or 'both'} for every conflict with a choice."""
        return {c.index: combo.currentData() for c, combo in zip(self.conflicts, self.combos)
                if combo.currentData() is not None}

    def _update_merge_button(self, *_):
        """Enables Merge only once every conflict has a choice."""
        self.merge_button.setEnabled(len(self.choices()) == len(self.conflicts))


class UsersDialog(QDialog):
    """Lists the people who can open the vault, and adds or removes them."""

    def __init__(self, parent, engine):
        """Builds the list with Add and Remove buttons."""
        super().__init__(parent)
        self.engine = engine
        self.setWindowTitle("Users")
        self.resize(420, 360)
        layout = QVBoxLayout(self)
        note = QLabel("Everyone here opens this vault with their own passphrase. Files restricted to some "
                      "users stay sealed for the others.", self)
        note.setWordWrap(True)
        layout.addWidget(note)
        self.list = QListWidget(self)
        layout.addWidget(self.list)
        buttons = QHBoxLayout()
        add = QPushButton("Add user...", self)
        add.clicked.connect(self._add)
        remove = QPushButton("Remove", self)
        remove.clicked.connect(self._remove)
        close = QPushButton("Close", self)
        close.clicked.connect(self.accept)
        for b in (add, remove):
            buttons.addWidget(b)
        buttons.addStretch(1)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self._fill()

    def _fill(self):
        """Shows the current users, marking you."""
        self.list.clear()
        me = self.engine.user.name if self.engine.user else None
        for name in self.engine.users():
            self.list.addItem(f"{name}  (you)" if name == me else name)

    def _add(self):
        """Asks for a name and a passphrase (twice), then adds the user."""
        name, ok = QInputDialog.getText(self, "Add user", "Name:")
        if not ok or not name.strip():
            return
        pw1, ok1 = QInputDialog.getText(self, "Add user", f"New passphrase for {name}:", QLineEdit.Password)
        if not ok1:
            return
        pw2, ok2 = QInputDialog.getText(self, "Add user", "Confirm it:", QLineEdit.Password)
        if not ok2 or pw1 != pw2 or not pw1:
            QMessageBox.warning(self, "Add user", "The passphrases didn't match (or were empty).")
            return
        try:
            self.engine.add_user(name.strip(), pw1)
        except UserError as e:
            QMessageBox.warning(self, "Add user", str(e))
        self._fill()

    def _remove(self):
        """Removes the selected user after asking."""
        item = self.list.currentItem()
        if item is None:
            return
        name = item.text().replace("  (you)", "")
        if QMessageBox.question(self, "Remove user", f"Remove '{name}'? Their passphrase will no longer open "
                                f"this vault.", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            self.engine.remove_user(name)
        except UserError as e:
            QMessageBox.warning(self, "Remove user", str(e))
        self._fill()


class RestrictDialog(QDialog):
    """Chooses the users who may read a file; you are always included."""

    def __init__(self, parent, label, users, me, current=None):
        """One checkbox per user; yours is ticked and can't be cleared."""
        super().__init__(parent)
        self.setWindowTitle(f"Restrict -- {label}")
        layout = QVBoxLayout(self)
        note = QLabel(f"Only the users you tick (and you) will be able to read '{label}'. Earlier versions "
                      f"stay readable by everyone until you shred them.", self)
        note.setWordWrap(True)
        layout.addWidget(note)
        self.boxes = {}
        for name in users:
            box = QCheckBox(f"{name} (you)" if name == me else name, self)
            box.setChecked(name == me or (current is not None and name in current))
            box.setEnabled(name != me)
            layout.addWidget(box)
            self.boxes[name] = box
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        ok = QPushButton("Restrict", self)
        ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancel", self)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(ok)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def chosen(self):
        """The ticked users."""
        return [name for name, box in self.boxes.items() if box.isChecked()]


class TextViewerDialog(QDialog):
    """Read-only in-app text viewer (past generations)."""

    def __init__(self, parent, title: str, text: str):
        """A read-only window showing text."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 600)
        layout = QVBoxLayout(self)
        view = QPlainTextEdit(self)
        view.setPlainText(text)
        view.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.TypeWriter)
        mono.setPointSize(11)
        view.setFont(mono)
        layout.addWidget(view)
        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)


class ImageViewerDialog(QDialog):
    """Read-only in-app viewer."""

    def __init__(self, parent, label: str, image_bytes: bytes):
        """A window showing an image, scaled to fit."""
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
    """Lineage diff as one cell per chunk position: green = new/changed, red =
    removed, gray = unchanged. Works for any content type.
    """

    def __init__(self, positions, parent=None):
        """A strip of coloured cells, one per chunk, showing how two versions differ."""
        super().__init__(parent)
        self.positions = positions
        self.setMinimumHeight(46)
        self.setMouseTracking(True)
        self._last_hover_index = None

    def _color_for(self, status):
        """Returns the cell colour for a chunk's status."""
        return {
            lineage_diff.UNCHANGED: _DIFF_UNCHANGED_COLOR,
            lineage_diff.CHANGED: _DIFF_CHANGED_COLOR,
            lineage_diff.NEW: _DIFF_NEW_COLOR,
            lineage_diff.DELETED: _DIFF_DELETED_COLOR,
        }[status]

    def paintEvent(self, event):
        """Draws one coloured cell per chunk."""
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
        """Shows a tooltip describing the chunk under the mouse."""
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
        """Hides the tooltip when the mouse leaves."""
        self._last_hover_index = None
        QToolTip.hideText()


class LineageDiffDialog(QDialog):
    """Lineage diff between two generations of the same label: the chunk map,
    plus a line diff when both decode as text. Separate from the clade
    similarity comparison (_show_diff_between).
    """

    def __init__(self, parent, result: "lineage_diff.LineageDiffResult", theme_colors: dict,
                 text_diff_lines=None, text_heading=None):
        """Builds the version-comparison window: the chunk strip, counts and, for text, the changed lines."""
        super().__init__(parent)
        self.result = result  # the structured result, for tests and callers
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
            text_label = QLabel(text_heading or "Line-level diff (bonus -- both generations decode as text):", self)
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
    """The main window: the map of the vault, its three views, toolbars, panels and every action."""
    def __init__(self, engine):
        """Builds the window for an open engine and draws the first view."""
        super().__init__()
        self.engine = engine
        self.engine.start_clade_worker()
        self._clade_version_drawn = None
        self.setWindowTitle("Phylogenetic File System")
        self.resize(1440, 940)
        self.setAcceptDrops(True)  # drops go to self.view, but some
        # compositors check the toplevel surface's flag

        self._mode = "web"
        self._clade_algorithm = "upgma"
        self._node_items = {}
        self._edge_items = []
        self._clade_blob_items = []
        self._clade_membership = {}  # label -> clade_key, for multi-member clades
        self._clade_leash_radius = {}
        self._clade_blob_by_key = {}  # clade_key -> its outline item
        self._scene_mode = None  # the mode the current scene was built for
        self._saved_positions = {}  # mode -> {node key: (x, y)}
        self._empty_state_item = None
        self._time_bounds = None
        self._time_cutoff = None
        self._time_machine_histories = {}
        self._syncing_zoom = False
        self._active_animations = []
        self._pending_timers = []  # pending one-shot timers (e.g. staggered particle starts)
        # label -> list of {"path", "watcher", "last_mtime"}: every open edit
        # session of a label stays tracked, so saving in any of them commits.
        self._edit_sessions = {}
        self._active_dialogs = []  # keeps non-modal dialogs alive (Qt parenting doesn't stop Python GC)

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
        # Redraw clade outlines when the worker publishes a newer partition.
        self._clade_poll_timer = QTimer(self)
        self._clade_poll_timer.timeout.connect(self._poll_clade_updates)
        self._clade_poll_timer.start(700)
        # Another program (the shell, a mounted folder) may change the vault too.
        self._vault_refresh_timer = QTimer(self)
        self._vault_refresh_timer.timeout.connect(self._poll_vault_changes)
        self._vault_refresh_timer.start(2000)
        # The Time Machine previews the selected file once the slider settles.
        self._time_preview_timer = QTimer(self)
        self._time_preview_timer.setSingleShot(True)
        self._time_preview_timer.timeout.connect(self._preview_selection_at_cutoff)
        self._time_preview_cache = {}  # (label, generation) -> (size, type, preview lines or None)

        # Auto-lock: any mouse or keyboard input restarts the idle timer.
        self._lock_overlay = None
        self._dialogs_hidden_by_lock = []
        self._idle_timer = QTimer(self)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.timeout.connect(self._lock_now)
        if auto_lock_seconds() > 0:
            self._idle_timer.start(int(auto_lock_seconds() * 1000))
            QApplication.instance().installEventFilter(self)

        self._rebuild()
        self._maybe_show_tour()

    # ---------- chrome ----------

    def _build_toolbar(self):
        """Builds the top toolbar: views, visual tools, adding files, export, list, palette and theme."""
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

        users_action = QAction("Users", self)
        users_action.setToolTip("The people who can open this vault, each with their own passphrase")
        users_action.triggered.connect(lambda: UsersDialog(self, self.engine).exec())
        toolbar.addAction(users_action)

        self.theme_action = QAction("☀  Light", self, checkable=True)
        self.theme_action.setToolTip("Switch between dark and light theme")
        self.theme_action.toggled.connect(self._on_theme_toggled)
        toolbar.addAction(self.theme_action)

        self.addToolBar(toolbar)

    def _build_dock(self):
        """Builds the Details panel on the right."""
        self.info_panel = QTextEdit(self)
        self.info_panel.setReadOnly(True)
        self.info_panel.setFixedWidth(340)
        dock = QDockWidget("Details", self)
        dock.setWidget(self.info_panel)
        dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

    def _build_list_dock(self):
        """Builds the Sort/List table panel."""
        container = QWidget(self)  # background from the app-wide stylesheet, so it re-themes
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
        # Styled by the app-wide stylesheet so it re-themes.
        layout.addWidget(self.list_table)

        self.list_dock = QDockWidget("Files -- Sort View", self)
        self.list_dock.setWidget(container)
        self.list_dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.list_dock.setMinimumWidth(340)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.list_dock)
        self.list_dock.setVisible(False)

    def _build_statusbar(self):
        """Builds the status bar: vault summary, speed readout, zoom slider, lock and pause."""
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
        """Builds the Time Machine slider bar at the bottom."""
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
        """Places the overview map in the top-left corner of the map."""
        self.minimap = MinimapView(self.scene, self.view, self.view)
        self.minimap.move(12, 12)
        self.minimap.raise_()

    def _build_toast(self):
        """Builds the short message label shown near the bottom of the map."""
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
        """Shows a short message near the bottom of the map that fades after a few seconds."""
        self.toast_label.setText(message)
        self.toast_label.adjustSize()
        x = max(8, (self.view.width() - self.toast_label.width()) // 2)
        y = max(8, self.view.height() - 76)
        self.toast_label.move(x, y)
        self.toast_label.show()
        self.toast_label.raise_()
        self._toast_timer.start(3000)

    _ACTIVITY_EVENTS = (QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel)

    def eventFilter(self, obj, event):
        """Restarts the auto-lock timer on any mouse or keyboard input."""
        if event.type() in self._ACTIVITY_EVENTS and self._lock_overlay is None and auto_lock_seconds() > 0:
            self._idle_timer.start(int(auto_lock_seconds() * 1000))
        return super().eventFilter(obj, event)

    def _lock_now(self):
        """Locks the window: covers it, hides open viewers and editors, and
        waits for the passphrase."""
        if self._lock_overlay is not None:
            return
        self._dialogs_hidden_by_lock = [d for d in self._active_dialogs if d.isVisible()]
        for dlg in self._dialogs_hidden_by_lock:
            dlg.hide()
        overlay = QWidget(self)
        overlay.setObjectName("lockOverlay")
        overlay.setStyleSheet(f"#lockOverlay {{ background: {BG}; }}")
        layout = QVBoxLayout(overlay)
        layout.addStretch(1)
        title = QLabel("PFS is locked", overlay)
        title.setStyleSheet(f"color:{TEXT}; font-size:20px; font-weight:bold;")
        title.setAlignment(Qt.AlignCenter)
        note = QLabel(f"It locked itself after {auto_lock_seconds() / 60:g} minute(s) without use. "
                      f"Enter the vault passphrase to continue.", overlay)
        note.setStyleSheet(f"color:{TEXT_DIM};")
        note.setAlignment(Qt.AlignCenter)
        self._lock_input = QLineEdit(overlay)
        self._lock_input.setEchoMode(QLineEdit.Password)
        self._lock_input.setPlaceholderText("Passphrase")
        self._lock_input.setFixedWidth(320)
        self._lock_input.returnPressed.connect(lambda: self._try_unlock(self._lock_input.text()))
        self._lock_message = QLabel("", overlay)
        self._lock_message.setStyleSheet(f"color:{ACCENT};")
        self._lock_message.setAlignment(Qt.AlignCenter)
        for widget in (title, note):
            layout.addWidget(widget)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self._lock_input)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addWidget(self._lock_message)
        layout.addStretch(1)
        overlay.setGeometry(self.rect())
        overlay.show()
        overlay.raise_()
        self._lock_input.setFocus()
        self._lock_overlay = overlay

    def _try_unlock(self, passphrase: str) -> bool:
        """Unlocks if the passphrase is right; returns whether it was."""
        if self._lock_overlay is None:
            return True
        if not self.engine.verify_passphrase(passphrase):
            self._lock_message.setText("Wrong passphrase.")
            self._lock_input.clear()
            return False
        self._lock_overlay.deleteLater()
        self._lock_overlay = None
        for dlg in self._dialogs_hidden_by_lock:
            if dlg in self._active_dialogs:
                dlg.show()
        self._dialogs_hidden_by_lock = []
        if auto_lock_seconds() > 0:
            self._idle_timer.start(int(auto_lock_seconds() * 1000))
        return True

    def resizeEvent(self, event):
        """Keeps the message centred (and the lock screen covering the window) on resize."""
        super().resizeEvent(event)
        if getattr(self, "_lock_overlay", None) is not None:
            self._lock_overlay.setGeometry(self.rect())
        if hasattr(self, "toast_label") and self.toast_label.isVisible():
            x = max(8, (self.view.width() - self.toast_label.width()) // 2)
            y = max(8, self.view.height() - 76)
            self.toast_label.move(x, y)

    def _maybe_show_tour(self):
        """First-launch overlay explaining the interface, shown once per vault
        (tracked by a marker file in the vault).
        """
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
            """Closes the welcome panel and remembers, in the vault folder, that it was seen."""
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
        """Redraws the overview map's 'you are here' rectangle when the view moves."""
        if hasattr(self, "minimap"):
            self.minimap.viewport().update()

    # ---------- zoom slider <-> view sync ----------

    def _scale_to_slider(self, scale: float) -> int:
        """Converts a zoom level to a position on the zoom slider (logarithmic)."""
        scale = max(CanvasView.MIN_SCALE, min(CanvasView.MAX_SCALE, scale))
        ratio = math.log(scale / CanvasView.MIN_SCALE) / math.log(CanvasView.MAX_SCALE / CanvasView.MIN_SCALE)
        return int(ratio * 1000)

    def _slider_to_scale(self, value: int) -> float:
        """Converts a zoom slider position to a zoom level."""
        ratio = value / 1000
        return CanvasView.MIN_SCALE * (CanvasView.MAX_SCALE / CanvasView.MIN_SCALE) ** ratio

    def _on_view_zoom_changed(self, scale: float):
        """Moves the zoom slider to match the current zoom."""
        self._syncing_zoom = True
        self.zoom_slider.setValue(self._scale_to_slider(scale))
        self._syncing_zoom = False

    def _on_slider_changed(self, value: int):
        """Zooms the map to match the zoom slider."""
        if self._syncing_zoom:
            return
        current = self.view.transform().m11()
        if current <= 0:
            return
        target = self._slider_to_scale(value)
        self.view.scale(target / current, target / current)
        self.view.viewChanged.emit()

    def _on_lock_toggled(self, checked: bool):
        """Locks or unlocks the layout (when locked, dragging moves the view, not nodes)."""
        self.view.locked = checked
        self.lock_button.setText("🔒" if checked else "🔓")

    def _on_physics_pause_toggled(self, checked: bool):
        """Pauses or resumes all movement."""
        self._physics_paused = checked
        self.physics_pause_button.setText("▶" if checked else "⏸")
        if checked:
            self.perf_label.setText("physics paused")

    def _on_theme_toggled(self, checked: bool):
        """Switches between the dark and light themes."""
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
        """Returns the current theme's colours for dialogs and the Details panel."""
        if getattr(self, "_light_theme", False):
            return {"panel": LIGHT_INPUT_BG, "border": LIGHT_BORDER, "text": LIGHT_TEXT,
                     "dim": LIGHT_TEXT_DIM, "accent": LIGHT_ACCENT}
        return {"panel": INPUT_BG, "border": BORDER, "text": TEXT, "dim": TEXT_DIM, "accent": ACCENT}

    def _render_cards(self, title, cards):
        """Renders the Details panel as cards. `cards`: list of
        {"heading": str, "rows": [(key, value), ...], "note": str?}.
        """
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
        """Re-render the selection so a theme change doesn't leave stale colors."""
        selected = self.scene.selectedItems()
        if selected:
            self._on_selection_changed()

    def _fit_to_view(self):
        """Instant fit, for use right after a rebuild."""
        target = self.scene.itemsBoundingRect()
        if target.isEmpty():
            return
        self.view.fitInView(target.adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)
        self._on_view_zoom_changed(self.view.transform().m11())
        self.view.viewChanged.emit()

    def _fit_to_view_animated(self):
        """Animated fit, for the Focus button."""
        target = self.scene.itemsBoundingRect()
        if target.isEmpty():
            return
        self._animate_view_to(target.adjusted(-60, -60, 60, 60))

    def _animate_view_to(self, target_rect, duration=320):
        """Animates zoom and center toward target_rect over `duration` ms."""
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
            """Moves and zooms the view part of the way through the animation (t from 0 to 1)."""
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
        """Double-click: fly to the node and its immediate neighbors."""
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
        """Switches to the Web, Tree or Clade Tree view and redraws."""
        if mode == self._mode:
            return
        self._mode = mode
        # Keep the mode buttons in sync when the mode changes programmatically.
        if mode == "web":
            self.web_action.setChecked(True)
        elif mode == "tree":
            self.tree_action.setChecked(True)
        elif mode == "cladetree":
            self.cladetree_action.setChecked(True)
        self._rebuild()

    def _set_clade_algorithm(self, algo: str):
        """Chooses UPGMA or Neighbour-Joining and shows the Clade Tree."""
        self._clade_algorithm = algo
        if self._mode != "cladetree":
            self.cladetree_action.setChecked(True)
            self._mode = "cladetree"
        self._rebuild()

    # The Clade Tree's layout is its shape (it changes with UPGMA/NJ), so it
    # is always laid out afresh.
    REMEMBERED_LAYOUT_MODES = ("web", "tree")

    def _rebuild(self):
        """Redraws the current view from the vault, keeping nodes where the user left them."""
        for anim in list(self._active_animations):
            anim.stop()
        self._active_animations = []
        # Stop pending one-shot timers too: stopping an animation doesn't cancel a
        # timer that would start it later, after its item is gone.
        for t in list(self._pending_timers):
            t.stop()
        self._pending_timers = []
        # Remember where nodes were, so a redraw (a write, a search, a mode
        # switch and back) keeps the layout instead of re-scattering it.
        if self._scene_mode in self.REMEMBERED_LAYOUT_MODES and self._node_items:
            self._saved_positions[self._scene_mode] = {
                key: (node.pos().x(), node.pos().y()) for key, node in self._node_items.items()}
        self.scene.clear()
        getattr(self, "_time_preview_cache", {}).clear()  # versions may have been pruned meanwhile
        self._node_items = {}
        self._edge_items = []
        self._clade_blob_items = []
        self._clade_blob_by_key = {}
        self._empty_state_item = None
        self._time_bounds = None

        if self._mode == "web":
            self._build_web_graph()
        elif self._mode == "tree":
            self._build_tree_graph()
        else:
            self._build_clade_tree_graph()
        self._scene_mode = self._mode
        for key, (x, y) in self._saved_positions.get(self._mode, {}).items():
            node = self._node_items.get(key)
            if node is not None:
                node.setPos(x, y)

        self._refresh_list_table()
        self._fit_to_view()
        self._apply_search_filter(self.search_box.text())
        self._configure_time_bar()
        if self._mode == "web" and self.clade_action.isChecked():
            self._draw_clade_blobs()
        if hasattr(self, "minimap"):
            self.minimap.refresh_extent()
        self._update_pulsing_nodes()

    PULSE_RECENCY_SECONDS = 300  # nodes touched in the last 5 minutes pulse

    def _update_pulsing_nodes(self):
        # Wall-clock time, not the vault's newest timestamp.
        """Starts a pulse on nodes saved in the last few seconds."""
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
        """Animates a soft pulse around a node."""
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
        """Creates a node on the map and registers it under its key."""
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
        """Creates a line between two nodes (curved if curve_offset is given)."""
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
        """Returns a node's colour: by file type, or by shared content when Dedup Heat is on."""
        if self.heatmap_action.isChecked():
            return _heatmap_color((shared_count or 0) / (total_count or 1))
        return _color_for_phenotype(phenotype_name)

    def _show_empty_state(self, message: str):
        """Shows the 'your vault is empty' message."""
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
        """Collects every file's summary, fingerprints and history, for drawing."""
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
        """Updates the vault summary in the status bar (sizes, sharing, unmerged branches)."""
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
            + (f" · you: {self.engine.user.name}" if self.engine.user else "")
        )

    def _refresh_list_table(self):
        """Fills the Sort/List table with one row per file."""
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
        """The canvas node for a label in any mode (web keys by label, tree and
        clade tree by node uuid).
        """
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
        else:  # cladetree: keyed by a per-build uuid, but
            # each leaf's data(1) is its label
            target_node = next((n for n in self._node_items.values() if n.data(1) == label), None)

        if target_node is not None:
            self.scene.clearSelection()
            target_node.setSelected(True)
            self._animate_view_to(QRectF(target_node.scenePos().x() - 160,
                                          target_node.scenePos().y() - 160, 320, 320))

    def _layout(self, labels, fingerprints):
        """Places files for the Web view: a spring layout where similar files are pulled together."""
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
        """Places every version for the Tree view: each file's history as a tree, side by side."""
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
            """Places one version and, recursively, the versions made from it."""
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
        """Places the nodes of a similarity tree, with branch lengths as vertical distances."""
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
            """Records how far each node is from the root, adding up branch lengths."""
            depth[uid] = accumulated
            for child_uuid in children[uid]:
                compute_depth(child_uuid, accumulated + by_uuid[child_uuid].branch_length)

        for r in roots:
            compute_depth(r, 0.0)

        positions = {}
        next_x = [0.0]

        def layout_subtree(uid):
            """Places one tree node and, recursively, its children."""
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
        """{node_uuid: (color, curve_offset)} for edges on each divergent branch,
        so open branches get distinct colors and curves.
        """
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
        """Draws the Web view: one node per file, and lines for duplicates and grafts."""
        labels, meta_by_label, fingerprints, histories = self._gather()
        self._update_stats_hud(meta_by_label)
        self._time_machine_histories = histories
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
        """Draws the Tree view: one node per version, lines from each version to the next, branches curved."""
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
        """Draws the Clade Tree view from the background worker's UPGMA or NJ tree."""
        _labels, meta_by_label, fingerprints, _hist = self._gather()
        self._update_stats_hud(meta_by_label)
        if len(fingerprints) < 2:
            self._show_empty_state("Need at least 2 fingerprinted files to build a clade tree.")
            return

        # The clade worker keeps this tree up to date in the background.
        all_nodes = self.engine.clade_tree(self._clade_algorithm, fingerprints, wait=CLADE_TREE_WAIT_SECONDS)
        if all_nodes is None:
            tc = TreeConstructor(PhylogeneticAnalyzer())
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
        """Removes the Outline circles."""
        for item in self._clade_blob_items:
            if item.scene() is not None:
                self.scene.removeItem(item)
        self._clade_blob_items = []
        self._clade_membership = {}
        self._clade_leash_radius = {}
        self._clade_blob_by_key = {}

    def _draw_clade_blobs(self):
        """Draws an Outline circle around each group of similar files."""
        self._clear_clade_blobs()
        if self._mode != "web":
            return
        # Brief wait for a fresh partition; _poll_clade_updates redraws later if needed.
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

                # Local rect + setPos, so the blob moves by setting pos(); its label is a
                # child so it moves with it.
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
                self._clade_blob_by_key[clade_name] = blob

                clade_cards.append({"heading": clade_name, "rows": [], "note": ", ".join(sorted(members))})

        # Single-member clades get a dim, unlabeled outline, so every node is contained.
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
            self._clade_blob_by_key[clade_key] = blob

        if not clade_cards:
            clade_cards.append({"heading": "No shared clades yet", "rows": [],
                                 "note": "Need 2+ files sharing 80%+ content -- every file still "
                                         "has its own faint individual outline."})
        self._render_cards("Clades", clade_cards)

    def closeEvent(self, event):
        """Stops the timers when the window closes."""
        self._idle_timer.stop()
        QApplication.instance().removeEventFilter(self)
        self._clade_poll_timer.stop()
        self._vault_refresh_timer.stop()
        super().closeEvent(event)

    def _poll_vault_changes(self):
        """Checks for changes other programs made to the vault, and redraws if there were any."""
        try:
            changed = self.engine.refresh()
        except Exception as e:  # e.g. the write lock timed out; try again next tick
            self.status.showMessage(f"Couldn't check the vault for outside changes: {e}", 5000)
            return
        if changed:
            self._rebuild()
            self._toast("Updated with changes made by another program")

    def _poll_clade_updates(self):
        """Redraws the Outline circles when the background grouping changes."""
        if self._mode != "web" or not self.clade_action.isChecked():
            return
        if self.engine.clade_version() != self._clade_version_drawn:
            self._draw_clade_blobs()

    def _on_clade_toggle(self, checked: bool):
        """Turns Outline on or off."""
        if checked:
            self._draw_clade_blobs()
        else:
            self._clear_clade_blobs()

    # ---------- search ----------

    def _apply_search_filter(self, text: str):
        """Fades nodes whose names don't match the search text."""
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
        """Enables the Time Machine slider when there is history, and resets it to 'now'."""
        has_bounds = self._time_bounds is not None
        self.time_slider.setEnabled(has_bounds)
        self.time_slider.blockSignals(True)
        self.time_slider.setValue(1000)
        self.time_slider.blockSignals(False)
        self._on_time_slider_changed(1000)

    def _on_time_slider_changed(self, value: int):
        """Shows the vault as it was at the slider's moment."""
        if self._time_bounds is None:
            self.time_label.setText("(no data)")
            return
        min_ts, max_ts = self._time_bounds
        cutoff = max_ts if max_ts <= min_ts else min_ts + (value / 1000) * (max_ts - min_ts)
        self._time_cutoff = cutoff

        if self._mode == "web" and self._time_machine_histories:
            self._apply_point_in_time_web(cutoff)
        else:
            # Tree modes: each generation is its own node, so existence fading is already point-in-time.
            for node in self._node_items.values():
                ts = node.data(2)
                node.setVisible(ts is None or ts <= cutoff)
            for edge in self._edge_items:
                edge.setVisible(edge.node_a.isVisible() and edge.node_b.isVisible())

        label = "now" if value >= 1000 else datetime.fromtimestamp(cutoff).strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.setText(label)
        if self._mode == "web":
            if value >= 1000:
                self._time_preview_timer.stop()
                self._on_selection_changed()  # back to the file as it is now
            else:
                self._time_preview_timer.start(TIME_PREVIEW_DELAY_MS)

    def _preview_selection_at_cutoff(self):
        """Details panel: the selected file as it was at the slider's moment,
        with the first lines of its content if it is text."""
        selected = self.scene.selectedItems()
        if self._mode != "web" or len(selected) != 1 or self._time_cutoff is None:
            return
        label = selected[0].data(0)
        when = datetime.fromtimestamp(self._time_cutoff).strftime("%Y-%m-%d %H:%M:%S")
        node = self._historical_generation_for(label, self._time_cutoff)
        if node is None:
            self._render_cards(f"{label} \u00b7 as of {when}", [
                {"heading": "Time Machine", "rows": [], "note": "This file didn't exist yet at that moment."}])
            return
        key = (label, node.generation_index)
        if key not in self._time_preview_cache:
            self._time_preview_cache[key] = self._generation_preview(label, node)
        size, type_name, lines = self._time_preview_cache[key]
        rows = [("Generation", node.generation_index),
                ("Saved", datetime.fromtimestamp(node.birth_timestamp).strftime("%Y-%m-%d %H:%M:%S")),
                ("Size", f"{size:,} bytes" if size is not None else "unavailable (pruned)"),
                ("Type", type_name)]
        cards = [{"heading": f"As of {when}", "rows": rows}]
        if self.engine.is_secret(label):
            cards.append({"heading": "Beginning of the file then", "rows": [],
                          "note": "Hidden: this file is secret."})
        elif lines:
            preview = "<br>".join(html.escape(line) or "&nbsp;" for line in lines)
            cards.append({"heading": "Beginning of the file then", "rows": [],
                          "note": f'<span style="font-family: monospace;">{preview}</span>'})
        cards.append({"heading": "Open it", "rows": [],
                      "note": "In the Tree view, right-click this generation and choose View this version."})
        self._render_cards(f"{label} \u00b7 as of {when}", cards)

    def _generation_preview(self, label, node):
        """(size, type name, first lines if text) for one generation, or
        (None, '?', None) if it was pruned. Big files aren't decrypted. A
        secret file is read in memory and its lines are never shown."""
        if node.pruned:
            return None, "?", None
        if self.engine.is_secret(label):
            try:
                data = self.engine.read_bytes(label, node.generation_index)
            except Exception:
                return None, "?", None
            return len(data), detect_phenotype(data[:64]).name, None
        os.makedirs(EDIT_CACHE_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_timepreview_", dir=EDIT_CACHE_DIR)
        os.close(fd)
        try:
            self.engine.checkout(label, node.generation_index, tmp_path)
            size = os.path.getsize(tmp_path)
            type_name = detect_from_file(tmp_path).name
            lines = None
            if _is_inapp_text_phenotype(type_name) and size <= TIME_PREVIEW_MAX_BYTES:
                with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = [f.readline().rstrip("\n")[:TIME_PREVIEW_LINE_CHARS] for _ in range(TIME_PREVIEW_LINES)]
                while lines and not lines[-1]:
                    lines.pop()
            return size, type_name, lines
        except Exception:
            return None, "?", None
        finally:
            os.remove(tmp_path)

    def _historical_generation_for(self, label, cutoff):
        """The generation that was label's tip at `cutoff`, or None."""
        candidate = None
        for node in self._time_machine_histories.get(label, []):
            if node.birth_timestamp <= cutoff:
                candidate = node
            else:
                break
        return candidate

    def _apply_point_in_time_web(self, cutoff):
        """Point in time for web mode: size (and heat color) each node from the
        generation current at that moment, using its recorded chunk counts.
        """
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
        """Updates the Details panel for the selection: one file, one version, or a comparison of two."""
        selected = self.scene.selectedItems()
        if not selected:
            return
        if len(selected) == 2 and self._mode == "web":
            self._show_diff_between(selected[0].data(0), selected[1].data(0))
            return
        if len(selected) == 2 and self._mode == "tree":
            # Tree mode: two selected generations of one label get a lineage diff.
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
        """Shows a file's cards in the Details panel: file facts, history and tags."""
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

        # Labels sharing this exact manifest: storage aliases that cost nothing extra.
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
        variables_card = None
        if is_secret(tags):
            file_rows.append(("Secret", "yes -- opens only inside the app; values hidden in comparisons"))
            try:
                readers = self.engine.restriction(label)
            except Exception:
                readers = None
            if readers:
                file_rows.append(("Readable by", ", ".join(readers)))
            try:
                events, _unreadable = self.engine.variable_history(label)
            except Exception:
                events = {}
            if events:
                variables_card = {"heading": "Variables (values hidden)",
                                  "rows": [(name, summarize_variable(events[name])) for name in sorted(events)]}

        cards = [
            {"heading": "File", "rows": file_rows},
            {"heading": "Lineage", "rows": [
                ("Generations", len(history)),
                ("Branches", len(heads)),
            ], "note": branch_note if len(heads) > 1 else None},
            {"heading": "Tags", "rows": [(k, v) for k, v in tags.items()] if tags else [("(none)", "")]},
        ]
        if variables_card is not None:
            cards.insert(1, variables_card)
        self._render_cards(label, cards)

    def _show_details_for_generation(self, node_uuid):
        """Shows one version's details: when it was saved, its chunks, and whether it was pruned."""
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
                ("Lateral parents", len(node.lateral_parent_uuids or [])),
            ]},
            {"heading": "Tags (inherited forward)", "rows": [(k, v) for k, v in tags.items()] if tags else [("(none)", "")]},
        ]
        self._render_cards(f"{owning_label} · gen {node.generation_index}", cards)

    def _show_details_for_clade_node(self, node_uuid):
        """Shows details for a Clade Tree node: the file it stands for, or the group it joins."""
        owner = self._node_items[node_uuid].data(1)
        if owner:
            self._show_details_for_label(owner)
        else:
            self._render_cards("Cluster node", [
                {"heading": "Synthetic cluster", "rows": [], "note": "Not a real file -- a computed grouping."},
            ])

    def _show_diff_between(self, label_a, label_b):
        """Compares two files: how similar they are, and what they share and don't."""
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
        """Lineage diff of two selected generations of the same label."""
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
        """Context menu: diff a generation against its primary parent."""
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
        """Line diff when both generations decode as UTF-8; None otherwise. For
        a secret file: which variables changed, read in memory, values hidden."""
        if self.engine.is_secret(label):
            try:
                return masked_changes(self.engine.read_bytes(label, generation_old),
                                      self.engine.read_bytes(label, generation_new))
            except Exception:
                return None
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
        """Runs a lineage diff (chunk map, plus line diff if text) and shows LineageDiffDialog."""
        try:
            result = lineage_diff.diff_generations(self.engine, label, generation_old, generation_new)
        except Exception as e:
            QMessageBox.warning(self, "Lineage diff", str(e))
            return

        text_diff_lines = None if result.identical else self._try_text_diff(label, generation_old, generation_new)

        heading = ("Changed variables (values hidden -- this file is secret):"
                   if text_diff_lines is not None and self.engine.is_secret(label) else None)
        dlg = LineageDiffDialog(self, result, self._theme_colors(), text_diff_lines, heading)
        self._active_dialogs.append(dlg)
        dlg.finished.connect(lambda _r=None: self._active_dialogs.remove(dlg) if dlg in self._active_dialogs else None)
        dlg.show()

    # ---------- write actions ----------

    def _show_node_context_menu(self, node: NodeItem, local_pos: QPoint):
        """Builds and shows the right-click menu for a node, depending on the view."""
        global_pos = self.view.viewport().mapToGlobal(local_pos)
        menu = QMenu(self)
        if self._mode == "web":
            label = node.data(0)
            meta = self.engine.get_metadata(label)
            phenotype_name = meta.get("phenotype_name", "") if meta else ""

            secret = self.engine.is_secret(label)
            menu.addAction("Info", lambda: self._show_details_for_label(label))
            if _is_inapp_text_phenotype(phenotype_name):
                menu.addAction("Edit (in-app, real-time)", lambda: self._edit_label_inapp(label))
            elif _is_inapp_image_phenotype(phenotype_name):
                menu.addAction("View Image", lambda: self._view_image_inapp(label))
            if not secret:
                # Secret files never leave the app: these hand a plaintext copy to another program.
                menu.addAction("View (read-only, external)", lambda: self._view_label(label))
                menu.addAction("Edit externally...", lambda: self._edit_label(label))
            menu.addAction("Rename...", lambda: self._rename_label(label))
            menu.addAction("Duplicate (zero-cost alias)...", lambda: self._duplicate_label(label))
            menu.addAction("Trace ancestry", lambda: self._trace_ancestry(label))
            menu.addAction("Reveal in Tree", lambda: self._reveal_in_tree(label))
            menu.addSeparator()
            menu.addAction("Unmark as secret" if secret else "Mark as secret",
                           lambda: self._set_secret(label, not secret))
            if len(self.engine.users()) > 1 or (secret and self._is_restricted(label)):
                menu.addAction("Restrict to users...", lambda: self._restrict_action(label))
                if secret and self._is_restricted(label):
                    menu.addAction("Remove restriction", lambda: self._unrestrict_action(label))
            menu.addSeparator()
            menu.addAction("Delete (shreds it)..." if secret else "Delete...", lambda: self._delete_label(label))
            menu.addAction("Shred (erase securely)...", lambda: self._shred_action(label))
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
            if not lineage_node.pruned:
                menu.addAction("View this version",
                                lambda: self._view_generation(owning_label, lineage_node.generation_index))
            menu.addAction("Checkout to file...",
                            lambda: self._checkout_generation(owning_label, lineage_node.generation_index))
            menu.addAction("Fork from here...",
                            lambda: self._fork_from_generation_action(owning_label, lineage_node.generation_index))
            if lineage_node.parent_uuid:
                menu.addAction("Diff against parent", lambda: self._diff_against_parent(owning_label, node_uuid))
            if not is_tip and not lineage_node.pruned:
                if self.engine.is_secret(owning_label):
                    menu.addAction("Shred this generation...",
                                    lambda: self._shred_action(owning_label, lineage_node.generation_index))
                else:
                    menu.addAction("Prune this generation...",
                                    lambda: self._prune_generation_action(owning_label, lineage_node.generation_index))
                    menu.addAction("Shred this generation...",
                                    lambda: self._shred_action(owning_label, lineage_node.generation_index))
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
        """Rename without prompting (context menu and command palette)."""
        if not self.engine.has_label(label):
            raise KeyError(f"No such label: '{label}'")
        if self.engine.has_label(new_label):
            raise ValueError(f"'{new_label}' already exists")
        self.engine.rename_label(label, new_label)
        if self._mode == "web" and label in self._node_items:  # keep its place on the map
            self._node_items[new_label] = self._node_items.pop(label)
        self._toast(f"Renamed '{label}' -> '{new_label}'")
        self._rebuild()

    def _rename_label(self, label):
        """Asks for a new name and renames the file."""
        new_label, ok = QInputDialog.getText(self, "Rename", f"New name for '{label}':", text=label)
        if not ok or not new_label.strip() or new_label.strip() == label:
            return
        try:
            self._rename_label_direct(label, new_label.strip())
        except ValueError as e:
            QMessageBox.warning(self, "Rename", str(e))

    def _duplicate_label_direct(self, label, new_label):
        """Duplicate as a lineage child of the source (a lateral parent), drawn
        connected to it. Identical content dedups fully: only a manifest and a
        lineage record are written.
        """
        if not self.engine.has_label(label):
            raise KeyError(f"No such label: '{label}'")
        if self.engine.has_label(new_label):
            raise ValueError(f"'{new_label}' already exists")

        self._perform_write_and_animate(lambda: self.engine.duplicate_label(label, new_label))
        self._toast(f"Duplicated '{label}' -> '{new_label}' (zero-cost content alias, linked back to '{label}')")

    def _duplicate_label(self, label):
        """Asks for a name and makes a zero-cost duplicate."""
        new_label, ok = QInputDialog.getText(self, "Duplicate", f"New label for a copy of '{label}':")
        if not ok or not new_label.strip():
            return
        try:
            self._duplicate_label_direct(label, new_label.strip())
        except ValueError as e:
            QMessageBox.warning(self, "Duplicate", str(e))

    def _delete_label(self, label):
        """Asks for confirmation, then deletes the file and its history."""
        confirm = QMessageBox.question(
            self, "Delete", f"Delete '{label}' and its full history? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            report = self.engine.delete_label(label)
        except PermissionError as e:
            QMessageBox.warning(self, "Delete refused", str(e))
            return
        if report and "versions_shredded" in report:
            self._toast(f"Shredded '{label}' (it was secret): {report['chunks_destroyed']} piece(s) overwritten")
        else:
            self._toast(f"Deleted '{label}'")
        self._rebuild()

    def _set_secret(self, label, secret: bool):
        """Marks a file as secret, or removes the mark."""
        if secret:
            self.engine.set_tag(label, SECRET_TAG, True)
            self._toast(f"'{label}' is now secret: it opens only inside the app")
        else:
            self.engine.remove_tag(label, SECRET_TAG)
            self._toast(f"'{label}' is no longer secret")
        self._rebuild()

    def _is_restricted(self, label) -> bool:
        """True if the file's latest version is sealed for some users."""
        try:
            return self.engine.restriction(label) is not None
        except Exception:
            return False

    def _restrict_action(self, label):
        """Asks which users may read the file, then seals it for them."""
        me = self.engine.user.name if self.engine.user else None
        dlg = RestrictDialog(self, label, self.engine.users(), me, self.engine.restriction(label))
        if dlg.exec() != QDialog.Accepted:
            return
        try:
            self._perform_write_and_animate(lambda: self.engine.restrict(label, dlg.chosen()))
        except (PermissionError, ValueError) as e:
            QMessageBox.warning(self, "Restrict", str(e))
            return
        self._toast(f"'{label}' is now readable only by: {', '.join(sorted(set(dlg.chosen()) | {me}))}")

    def _unrestrict_action(self, label):
        """Makes a restricted file readable by every user again."""
        try:
            self._perform_write_and_animate(lambda: self.engine.unrestrict(label))
        except (PermissionError, ValueError) as e:
            QMessageBox.warning(self, "Remove restriction", str(e))
            return
        self._toast(f"'{label}' is readable by every user again")

    def _shred_action(self, label, generation_index=None):
        """Asks for confirmation, then securely erases a file or one old version."""
        what = (f"'{label}' and all its history" if generation_index is None
                else f"generation {generation_index} of '{label}'")
        confirm = QMessageBox.question(
            self, "Shred",
            f"Shred {what}?\n\nIts content is overwritten inside the vault and can't be recovered, even "
            f"with the passphrase. Content still used by other files or versions is kept.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        holder = {}
        try:
            self._perform_write_and_animate(
                lambda: holder.setdefault("report", self.engine.shred(label, generation_index)))
        except Exception as e:  # refused (protected, current version) or failed, either engine
            QMessageBox.warning(self, "Shred", str(e))
            return
        report = holder["report"]
        kept = (f"; {report['chunks_kept_shared']} kept (still used elsewhere)"
                if report["chunks_kept_shared"] else "")
        self._toast(f"Shredded {what}: {report['chunks_destroyed']} piece(s) overwritten{kept}")

    def _trace_ancestry(self, label):
        """Fades everything except the file and the chain of files it was made from."""
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
        """Switches to the Tree view and centres on the file's latest version."""
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
        """Asks where to save, then writes an old generation there as an ordinary file."""
        if self.engine.is_secret(label):
            confirm = QMessageBox.warning(
                self, "Secret file",
                f"'{label}' is secret. Checking it out writes its values UNENCRYPTED to a file that any "
                f"program can read.\n\nWrite it anyway?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if confirm != QMessageBox.Yes:
                return
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
        """Asks for confirmation, then frees an old generation's storage."""
        confirm = QMessageBox.question(
            self, "Prune",
            f"Prune '{label}' generation {generation_index}? This frees its storage (if nothing else "
            f"references it) but keeps the history record.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            report = self.engine.prune_generation(label, generation_index)
            if report and "versions_shredded" in report:
                self._toast(f"Shredded '{label}' generation {generation_index} (the file is secret)")
            else:
                self._toast(f"Pruned '{label}' generation {generation_index}")
            self._rebuild()
        except (ValueError, PermissionError) as e:
            QMessageBox.warning(self, "Prune failed", str(e))

    def _fork_from_generation_action(self, label, generation_index):
        """Starts a branch from an older generation, unless the file is restricted."""
        if self._is_restricted(label):
            QMessageBox.information(self, "Fork", f"'{label}' is restricted, and a fork would store its new "
                                    f"branch unsealed. Edit it in the app instead, or remove the restriction.")
            return
        self._fork_from_generation_action_unrestricted(label, generation_index)

    def _fork_from_generation_action_unrestricted(self, label, generation_index):
        """Asks for a file and stores it as a branch from an older generation."""
        path, _ = QFileDialog.getOpenFileName(self, f"Fork '{label}' generation {generation_index} with...")
        if not path:
            return
        self._perform_write_and_animate(
            lambda: self.engine.commit_write(label, path, fork_from_generation=generation_index)
        )
        self._toast(f"Forked '{label}' from generation {generation_index}")

    def _merge_action_for_label(self, label):
        """Merges two branches, asking which ones, and opens the conflict window if parts clash."""
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
        gen_a = heads[choices.index(choice_a)].generation_index
        gen_b = heads[choices.index(choice_b)].generation_index
        try:
            line_merge = self.engine.text_merge(label, gen_a, gen_b)
        except Exception as e:  # can't be merged at all (either engine)
            QMessageBox.warning(self, "Merge failed", str(e))
            return
        if line_merge is not None:
            self._finish_line_merge(label, gen_a, gen_b, line_merge)
            return
        try:
            self._merge_with_resolutions(label, gen_a, gen_b, {})
        except MutationConflictError as e:
            dlg = self._conflict_dialog(label, gen_a, gen_b, e.conflicting_positions)
            if dlg.exec() != QDialog.Accepted:
                self._toast("Merge cancelled -- nothing was saved")
                return
            try:
                self._merge_with_resolutions(label, gen_a, gen_b, dlg.resolutions())
            except (MutationConflictError, ValueError) as e2:
                QMessageBox.warning(self, "Merge failed", str(e2))
        except ValueError as e:
            QMessageBox.warning(self, "Merge failed", str(e))

    def _finish_line_merge(self, label, gen_a, gen_b, line_merge, choices=None):
        """Saves a line-by-line merge, asking about conflicts first (unless
        choices is given). Returns True if it was saved."""
        if line_merge.conflicts and choices is None:
            dlg = LineConflictDialog(self, label, gen_a, gen_b, line_merge.conflicts,
                                     hide_lines=self.engine.is_secret(label))
            if dlg.exec() != QDialog.Accepted:
                self._toast("Merge cancelled -- nothing was saved")
                return False
            choices = dlg.choices()
        text = line_merge.text(choices)
        self._perform_write_and_animate(lambda: self.engine.commit_text_merge(label, gen_a, gen_b, text))
        extra = f", {len(line_merge.conflicts)} conflict(s) resolved" if line_merge.conflicts else ""
        self._toast(f"Merged '{label}' generations {gen_a} and {gen_b} line by line{extra}")
        return True

    def _merge_with_resolutions(self, label, gen_a, gen_b, resolutions):
        """Runs the merge with the user's choices and reports the result."""
        self._perform_write_and_animate(
            lambda: self.engine.merge_branches(label, gen_a, gen_b, resolutions or None))
        extra = f" ({len(resolutions)} conflict(s) resolved)" if resolutions else ""
        self._toast(f"Merged '{label}' generations {gen_a} and {gen_b}{extra}")

    def _conflict_dialog(self, label, gen_a, gen_b, positions):
        """Opens the conflict window for a merge, with a description of each side's piece."""
        chunks = {"a": self.engine.get_chunk_hashes(label, gen_a),
                  "b": self.engine.get_chunk_hashes(label, gen_b)}

        def describe(side, pos):
            """Describes one side's piece at a clashing position, or notes that its file ends earlier."""
            return "its version" if pos < len(chunks[side]) else "the file ends before here"
        return ConflictResolutionDialog(self, label, gen_a, gen_b, positions, describe)

    def _new_file_dialog(self):
        """Asks for one or more files and adds them."""
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose one or more files to add to the vault")
        if paths:
            self._add_files(paths)

    def _on_files_dropped(self, paths):
        """Adds the files dropped on the map, ignoring anything that isn't a file."""
        real_paths = [p for p in paths if os.path.isfile(p)]
        if real_paths:
            self._add_files(real_paths)
        elif paths:
            self._toast("Drop didn't include any readable file path -- try + New File(s) instead")

    def _unique_label_from_path(self, path: str) -> str:
        """Returns the file's name, with a number added if that name is already taken."""
        base = os.path.basename(path)
        if not self.engine.has_label(base):
            return base
        stem, ext = os.path.splitext(base)
        i = 2
        while self.engine.has_label(f"{stem}_{i}{ext}"):
            i += 1
        return f"{stem}_{i}{ext}"

    def _add_files(self, paths):
        """Adds files without a label prompt: each label is its filename, with a
        numeric suffix if taken. Rename afterwards if needed.
        """
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
        """Adds a single file."""
        self._add_files([path])

    # ---------- edit-in-place (open in the OS default app, auto-sync back) ----------

    def _edit_label(self, label):
        """Opens the label's content in the OS default app and commits each save
        as a new generation.

        Saves are detected two ways, because editors that save by rename can
        drop the inotify watch: a QFileSystemWatcher (fast) and an mtime poll
        every 1.5 s (_poll_edited_files). The mtime check makes the slower one a
        no-op. Re-opening a label adds another tracked session; if two sessions
        of one label are both saved, the later save wins.
        """
        meta = self.engine.get_metadata(label)
        if meta is None:
            return
        if self._refuse_external_for_secret(label):
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
        """Opens read-only in the default app; never watched, never committed."""
        meta = self.engine.get_metadata(label)
        if meta is None:
            return
        if self._refuse_external_for_secret(label):
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

    def _refuse_external_for_secret(self, label) -> bool:
        """For a secret file, explains that it can't be opened in another
        program and returns True."""
        if not self.engine.is_secret(label):
            return False
        QMessageBox.information(
            self, "Secret file",
            f"'{label}' is secret, so it only opens inside PFS: another program would need an "
            f"unencrypted copy on disk.\n\nUse Edit (in-app) for text, or 'run' in the shell to give its "
            f"variables to a program.")
        return True

    def _show_inapp_viewer(self, title, phenotype_name, data):
        """Shows text or an image read-only in a window inside the app."""
        if _is_inapp_text_phenotype(phenotype_name):
            dlg = TextViewerDialog(self, title, data.decode("utf-8", errors="replace"))
        else:
            dlg = ImageViewerDialog(self, title, data)
        self._active_dialogs.append(dlg)
        dlg.finished.connect(lambda _r=None: self._active_dialogs.remove(dlg) if dlg in self._active_dialogs else None)
        dlg.show()

    def _view_generation(self, label, generation_index):
        """Shows one past generation read-only: text and images in-app, other
        types in the OS default app. Nothing is committed. A secret file is
        read in memory and never handed to another program.
        """
        title = f"{label} -- generation {generation_index} (read-only)"
        if self.engine.is_secret(label):
            try:
                data = self.engine.read_bytes(label, generation_index)
            except Exception as e:  # pruned or shredded, either engine
                QMessageBox.warning(self, "View", str(e))
                return
            phenotype_name = detect_phenotype(data[:64]).name
            if _is_inapp_text_phenotype(phenotype_name) or _is_inapp_image_phenotype(phenotype_name):
                self._show_inapp_viewer(title, phenotype_name, data)
            else:
                self._refuse_external_for_secret(label)
            return
        os.makedirs(EDIT_CACHE_DIR, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="pfs_viewgen_", dir=EDIT_CACHE_DIR)
        os.close(fd)
        try:
            self.engine.checkout(label, generation_index, tmp_path)
        except Exception as e:  # pruned, or no such generation (either engine)
            os.remove(tmp_path)
            QMessageBox.warning(self, "View", str(e))
            return
        phenotype_name = detect_from_file(tmp_path).name
        if _is_inapp_text_phenotype(phenotype_name) or _is_inapp_image_phenotype(phenotype_name):
            with open(tmp_path, "rb") as f:
                data = f.read()
            os.remove(tmp_path)
            self._show_inapp_viewer(title, phenotype_name, data)
            return
        view_path = tmp_path + _extension_for_phenotype(phenotype_name)
        os.replace(tmp_path, view_path)
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(view_path)):
            QMessageBox.warning(self, "View", f"Couldn't find a default app to open this file type.\n"
                                               f"The content is at: {view_path}")
            return
        self._toast(f"Opened '{label}' generation {generation_index} read-only")

    def _edit_label_inapp(self, label):
        """Text: in-app editor whose Save commits directly."""
        if not self.engine.has_label(label):
            return
        if self.engine.is_secret(label):
            # Secret: the text lives only in memory and in the editor.
            tmp_path = None
            try:
                initial_text = self.engine.read_bytes(label).decode("utf-8", errors="replace")
            except PermissionError as e:  # restricted to other users
                QMessageBox.warning(self, "Edit", str(e))
                return
        else:
            os.makedirs(EDIT_CACHE_DIR, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix="pfs_inapp_", suffix=".txt", dir=EDIT_CACHE_DIR)
            os.close(fd)
            self.engine.reconstruct_current(label, tmp_path)
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                initial_text = f.read()

        def on_save(new_text):
            """Stores the editor's text as a new version and switches to the Tree view."""
            if tmp_path is None:
                self._perform_write_and_animate(lambda: self.engine.commit_bytes(label, new_text.encode("utf-8")))
            else:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    f.write(new_text)
                self._perform_write_and_animate(lambda: self.engine.commit_write(label, tmp_path))
            # Show Tree mode, where the new generation is its own node.
            self._reveal_in_tree(label)

        dlg = InAppTextEditorDialog(self, label, initial_text, on_save)
        self._active_dialogs.append(dlg)

        def cleanup(_result=None):
            """Deletes the editor's temporary file when the editor closes."""
            if tmp_path is not None and os.path.exists(tmp_path):
                os.remove(tmp_path)
            if dlg in self._active_dialogs:
                self._active_dialogs.remove(dlg)

        dlg.finished.connect(cleanup)
        dlg.show()

    def _view_image_inapp(self, label):
        """Images: in-app read-only viewer."""
        if not self.engine.has_label(label):
            return
        try:
            image_bytes = self.engine.read_bytes(label)  # in memory; never written to disk
        except PermissionError as e:  # restricted to other users
            QMessageBox.warning(self, "View", str(e))
            return
        dlg = ImageViewerDialog(self, label, image_bytes)
        self._active_dialogs.append(dlg)
        dlg.finished.connect(lambda _r=None: self._active_dialogs.remove(dlg) if dlg in self._active_dialogs else None)
        dlg.show()

    def _on_edited_file_changed(self, label, path):
        """Called when an externally edited file changes on disk: stores it, and re-watches it if needed."""
        self._check_and_commit_edit(label, path)
        for session in self._edit_sessions.get(label, []):
            if session["path"] == path:
                watcher = session["watcher"]
                if path not in watcher.files() and os.path.exists(path):
                    watcher.addPath(path)  # re-arm after a write-then-rename save
                break

    def _check_and_commit_edit(self, label, path):
        """Stores an externally edited file as a new version, if its content really changed."""
        session = next((s for s in self._edit_sessions.get(label, []) if s["path"] == path), None)
        if session is None or not os.path.exists(path):
            return  # editors may briefly remove the file mid-save
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if mtime <= session["last_mtime"]:
            return  # already committed, or unchanged
        session["last_mtime"] = mtime
        try:
            self._perform_write_and_animate(lambda: self.engine.commit_write(label, path))
            self._toast(f"'{label}' updated from your edit -- new generation created")
            # Switch to Tree mode, where the new generation is visible as its own node.
            self._reveal_in_tree(label)
        except Exception as e:
            self._toast(f"Auto-sync for '{label}' failed: {e}")

    def _poll_edited_files(self):
        """Backstop for _edit_label's watcher: checks every open session every 1.5 s."""
        for label, sessions in list(self._edit_sessions.items()):
            for session in list(sessions):
                path = session["path"]
                self._check_and_commit_edit(label, path)
                watcher = session["watcher"]
                if os.path.exists(path) and path not in watcher.files():
                    watcher.addPath(path)

    def _export_canvas(self):
        """Asks where to save, then exports the whole map as a PNG."""
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
        """Selects the next (or previous) node and centres the view on it, for Tab/Shift+Tab."""
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
        """Opens the command palette over the map."""
        dlg = CommandPalette(self)
        center = self.view.mapToGlobal(self.view.rect().center())
        dlg.move(center.x() - dlg.width() // 2, max(40, center.y() - 200))
        dlg.show()
        dlg.input.setFocus()

    def keyPressEvent(self, event):
        """Keyboard shortcuts: Tab/Shift+Tab, Home, Delete and Ctrl+K."""
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
        """Returns the keys of the nodes currently shown (files, or versions in the Tree view)."""
        if self._mode == "web":
            return set(self.engine.labels())
        keys = set()
        for label in self.engine.all_labels():
            for node in self.engine.get_history(label):
                keys.add(node.node_uuid)
        return keys

    def _perform_write_and_animate(self, write_fn):
        """Runs a change, redraws, and animates the nodes and lines that appeared."""
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
        """Keeps a running animation referenced until it finishes."""
        self._active_animations.append(anim)
        anim.finished.connect(lambda: self._active_animations.remove(anim) if anim in self._active_animations else None)

    def _track_pending_timer(self, timer):
        """Like _track_animation for a pending one-shot QTimer, so _rebuild() can cancel it."""
        self._pending_timers.append(timer)
        timer.timeout.connect(lambda: self._pending_timers.remove(timer) if timer in self._pending_timers else None)

    def _animate_node_appearance(self, node: NodeItem):
        """Grows a new node from nothing to its full size."""
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
        """Fades a new line in."""
        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(EDGE_REST_OPACITY)
        anim.setDuration(450)
        anim.valueChanged.connect(lambda v: edge.setOpacity(float(v)))
        self._track_animation(anim)
        anim.start()

    def _spawn_particle_trail(self, edge: EdgeItem):
        """Small particles drifting from parent to child along a new edge; tracked
        like other animations so a rebuild stops them.
        """
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
                """Moves one particle along the line (t from 0 to 1)."""
                t = float(t)
                x = parent_pos.x() + (child_pos.x() - parent_pos.x()) * t
                y = parent_pos.y() + (child_pos.y() - parent_pos.y()) * t
                particle.setPos(x, y)
                particle.setOpacity(math.sin(t * math.pi))

            def cleanup(particle=particle):
                """Removes the particle when its animation ends."""
                if particle.scene() is not None:
                    self.scene.removeItem(particle)

            anim.valueChanged.connect(step)
            anim.finished.connect(cleanup)
            self._track_animation(anim)

            # An owned QTimer (not QTimer.singleShot) so a rebuild can cancel a
            # pending start before its particle is destroyed.
            delay_timer = QTimer(self)
            delay_timer.setSingleShot(True)
            delay_timer.timeout.connect(anim.start)
            self._track_pending_timer(delay_timer)
            delay_timer.start(i * 90)

    # ---------- live physics ("organic hydra" behavior) ----------

    def _physics_tick(self):
        """One animation step: runs the physics and updates the speed readout."""
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
        """The physics: nodes push apart, connected nodes pull together, and Outline/Swirl forces apply."""
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

        # Repulsion through a uniform grid instead of all pairs: beyond CUTOFF the
        # force is negligible. All pairs measured 21.8 ms/tick at 100 nodes and
        # 1446 ms at 1000; the grid keeps it roughly linear.
        CUTOFF = 400.0
        CUTOFF_SQ = CUTOFF * CUTOFF
        grid = {}
        for n in nodes:
            cell = (int(n.pos().x() // CUTOFF), int(n.pos().y() // CUTOFF))
            grid.setdefault(cell, []).append(n)

        # Each neighboring cell pair is visited once: (0,0) within a cell, four offsets across.
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

        # Clade containment (web outline mode): no force inside the leash
        # radius, a gentle pull back beyond it, toward the members' current
        # centroid, so a group can drift together.
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

        # Outlines follow their members' current centroid.
        if self._mode == "web" and self._clade_blob_by_key:
            sums = {}
            for n in nodes:
                clade_key = self._clade_membership.get(n.data(1))
                if clade_key in self._clade_blob_by_key:
                    s = sums.setdefault(clade_key, [0.0, 0.0, 0])
                    s[0] += n.pos().x()
                    s[1] += n.pos().y()
                    s[2] += 1
            for clade_key, (sx, sy, count) in sums.items():
                self._clade_blob_by_key[clade_key].setPos(sx / count, sy / count)

        # Slow rigid rotation of every unpinned node and clade blob (web mode
        # only). Rotation preserves distances, so it doesn't fight the other
        # forces. One turn takes about 3 minutes.
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
    """'python', 'cpp', or None, from each engine's marker files (see pfs_cli.py)."""
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
    """Opens a Python-engine vault, asking for the passphrase in dialogs; refuses C++-engine vaults."""
    existing = _existing_vault_engine(storage_root)
    if existing == "cpp":
        QMessageBox.critical(None, "Wrong Engine", f"'{storage_root}' is a C++-engine vault "
                              f"(catalog.pfsc/keyring.pfsk present). Relaunch with --engine cpp.")
        return None

    session = VaultSession(storage_root)

    def get_new_passphrase():
        """Asks for a new passphrase twice in dialogs."""
        pw1, ok1 = QInputDialog.getText(None, "New Vault", "Set a new vault passphrase:", QLineEdit.Password)
        if not ok1:
            sys.exit(0)
        pw2, ok2 = QInputDialog.getText(None, "New Vault", "Confirm passphrase:", QLineEdit.Password)
        if not ok2:
            sys.exit(0)
        return pw1, pw2

    def get_existing_passphrase():
        """Asks for the existing passphrase in a dialog."""
        pw, ok = QInputDialog.getText(None, "Unlock Vault", f"Passphrase for {storage_root}:", QLineEdit.Password)
        if not ok:
            sys.exit(0)
        return pw

    def confirm_reset():
        """Asks whether to discard vault files that don't match this key."""
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
    """Opens a C++-engine vault, asking for the passphrase in dialogs; refuses Python-engine vaults."""
    from gearhash.master_key_store import create_new_vault_key, unlock_user, WrongPassphraseError, MASTER_KEY_FILENAME
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
        create_new_vault_key(storage_root, pw1)
        user = unlock_user(storage_root, pw1)
    else:
        pw, ok = QInputDialog.getText(None, "Unlock C++ Vault", f"Passphrase for {storage_root}:", QLineEdit.Password)
        if not ok:
            sys.exit(0)
        try:
            user = unlock_user(storage_root, pw)
        except WrongPassphraseError:
            QMessageBox.critical(None, "Unlock Failed", "Wrong passphrase.")
            return None

    kek = user.kek
    try:
        session = CppVaultSession(storage_root, kek)
    except PfsEngineError as e:
        QMessageBox.critical(None, "Unlock Failed", f"Couldn't open the C++ vault: {e}")
        return None
    return CppEngineAdapter(session, kek, user)


def main():
    """Starts the desktop app: parses the arguments, opens the vault and shows the window."""
    parser = argparse.ArgumentParser(description="PFS Cosmic Web GUI")
    parser.add_argument("storage_root", help="vault directory")
    parser.add_argument("--engine", choices=["python", "cpp"], default="python",
                         help="storage backend -- 'python' (default) or 'cpp' (the compiled "
                              "engine, same GUI feature set -- see user_manual.pdf). A vault "
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
