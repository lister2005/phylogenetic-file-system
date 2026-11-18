"""
Secrets mode: helpers shared by the shell, the desktop app and the mounted
folder for files tagged 'secret' (such as .env files).

A secret file's content is never written to disk outside the vault: it is
read into an in-memory file (memfd), parsed in memory, and handed to a
program as environment variables by 'run'. Previews and comparisons show
which variables changed, never their values.
"""

import os
import re
from typing import NamedTuple

from gearhash.scrub import scrub_and_remove, scrub_file  # noqa: F401 (re-exported)

SECRET_TAG = "secret"
SHREDDED_TAG = "shredded"

# Largest secret file 'run' will load (a .env file is a few kilobytes).
MAX_SECRET_BYTES = 1 << 20

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "$": "$"}


def is_secret(tags) -> bool:
    """True if a file's tags mark it as secret."""
    return bool(tags and tags.get(SECRET_TAG))


class MemoryFile:
    """A file that lives only in memory (Linux memfd), usable by path.

    Both engines read and write files by path; /proc/self/fd/<n> lets them
    use this one without the content ever reaching the disk. Close it (or use
    it as a context manager) to free the memory.
    """

    def __init__(self, name: str = "pfs_secret"):
        """Creates an empty in-memory file."""
        self.fd = os.memfd_create(name, os.MFD_CLOEXEC)

    @property
    def path(self) -> str:
        """A path that opens this in-memory file (in this process only)."""
        return f"/proc/self/fd/{self.fd}"

    def write(self, data: bytes) -> None:
        """Replaces the file's content with data."""
        os.ftruncate(self.fd, 0)
        os.pwrite(self.fd, data, 0)

    def read(self, limit: int = None) -> bytes:
        """Returns the whole content; ValueError if it is larger than limit."""
        size = os.fstat(self.fd).st_size
        if limit is not None and size > limit:
            raise ValueError(f"too large for a secret file ({size:,} bytes; the limit is {limit:,})")
        return os.pread(self.fd, size, 0)

    def close(self) -> None:
        """Frees the memory; safe to call more than once."""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        """Lets the file be used in a with-block."""
        return self

    def __exit__(self, *exc):
        """Frees the memory at the end of a with-block."""
        self.close()


def read_via_memory(write_to_path, limit: int = None) -> bytes:
    """Calls write_to_path(path) with an in-memory file's path and returns
    what was written. For engines that only rebuild files to a path.
    """
    with MemoryFile() as mem:
        write_to_path(mem.path)
        return mem.read(limit)


class DotenvError(ValueError):
    """A .env file couldn't be parsed. Holds line numbers, never content."""

    def __init__(self, problems):
        """problems: list of (line number, description)."""
        self.problems = list(problems)
        listing = "; ".join(f"line {n}: {what}" for n, what in self.problems[:5])
        more = f" (and {len(self.problems) - 5} more)" if len(self.problems) > 5 else ""
        super().__init__(f"not a valid .env file -- {listing}{more}")


def _unquote_double(body: str) -> str:
    """Resolves backslash escapes inside a double-quoted value."""
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in _ESCAPES:
            out.append(_ESCAPES[body[i + 1]])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _closing_quote(text: str, quote: str, start: int) -> int:
    """Index of the closing quote at or after start, or -1. Backslash escapes
    the double quote only."""
    i = start
    while i < len(text):
        if text[i] == "\\" and quote == '"':
            i += 2
            continue
        if text[i] == quote:
            return i
        i += 1
    return -1


def parse_dotenv(text: str) -> dict:
    """Parses .env content into {name: value}, in file order.

    Supports blank lines, # comments, an optional 'export ' prefix, unquoted
    values (with trailing ' # comments'), single quotes (taken literally) and
    double quotes (with \\n, \\t, \\" escapes, and values spanning lines).
    Later definitions of a name replace earlier ones. Raises DotenvError,
    which reports line numbers but never values.
    """
    values, problems = {}, []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    i = 0
    while i < len(lines):
        line_no, line = i + 1, lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            problems.append((line_no, "expected NAME=value"))
            continue
        name, rest = line.split("=", 1)
        name = name.strip()
        if not _KEY_RE.match(name):
            problems.append((line_no, "the name must be letters, digits or _ and not start with a digit"))
            continue
        rest = rest.lstrip()
        if rest[:1] in ('"', "'"):
            quote = rest[0]
            body = rest[1:]
            end = _closing_quote(body, quote, 0)
            while end < 0 and i < len(lines):
                # The value continues on the next line.
                body += "\n" + lines[i]
                i += 1
                end = _closing_quote(body, quote, 0)
            if end < 0:
                problems.append((line_no, "a quote is never closed"))
                continue
            trailing = body[end + 1:].strip()
            if trailing and not trailing.startswith("#"):
                problems.append((line_no, "unexpected text after the closing quote"))
                continue
            value = body[:end]
            values[name] = _unquote_double(value) if quote == '"' else value
        else:
            comment = re.search(r"\s#", rest)
            values[name] = (rest[:comment.start()] if comment else rest).strip()
    if problems:
        raise DotenvError(problems)
    return values


def masked_changes(old: bytes, new: bytes) -> list:
    """Describes how a secret file changed without revealing any value.

    For .env content: one line per variable added, removed or changed, then
    a count of unchanged ones. For anything else: a single line saying the
    content changed.
    """
    try:
        before = parse_dotenv(old.decode("utf-8"))
        after = parse_dotenv(new.decode("utf-8"))
    except (UnicodeDecodeError, DotenvError):
        return ["Content changed (hidden: this file is secret)."]
    lines = []
    for name in after:
        if name not in before:
            lines.append(f"+ {name}: added")
        elif before[name] != after[name]:
            lines.append(f"~ {name}: changed")
    for name in before:
        if name not in after:
            lines.append(f"- {name}: removed")
    unchanged = sum(1 for name in after if name in before and before[name] == after[name])
    if not lines:
        lines.append("No variable changed (only spacing or comments).")
    lines.append(f"({unchanged} variable(s) unchanged; values are hidden because this file is secret)")
    return lines


def variable_names(content: bytes) -> list:
    """The variable names a secret .env file defines, in file order. Raises
    DotenvError (or UnicodeDecodeError) if it isn't a valid .env file."""
    return list(parse_dotenv(content.decode("utf-8")).keys())


def environment_for(contents, base_env=None) -> dict:
    """The environment to run a program with: base_env (default: this
    process's) plus every variable from each secret file in contents, later
    files overriding earlier ones."""
    env = dict(os.environ if base_env is None else base_env)
    for content in contents:
        env.update(parse_dotenv(content.decode("utf-8")))
    return env


# Idle time after which the shell and the desktop app lock themselves.
AUTO_LOCK_SECONDS = 900


def auto_lock_seconds() -> float:
    """AUTO_LOCK_SECONDS, or PFS_AUTO_LOCK_SECONDS if set (0 turns auto-lock
    off). Invalid values are ignored."""
    raw = os.environ.get("PFS_AUTO_LOCK_SECONDS")
    if raw is None:
        return AUTO_LOCK_SECONDS
    try:
        return max(float(raw), 0.0)
    except ValueError:
        return AUTO_LOCK_SECONDS


class VariableEvent(NamedTuple):
    """One change to one variable: in which generation, when, and how."""
    generation: int
    timestamp: float
    kind: str  # "added", "changed" or "removed"


def variable_history(versions) -> tuple:
    """Per-variable history of a secret .env file, values never included.

    versions: (generation, parent generation or None, timestamp, content
    bytes or None if unreadable) for each version. Each version is compared
    with its own parent, so branches are handled correctly. Returns
    ({name: [VariableEvent, ...]}, [generations that couldn't be read]).
    """
    parsed, unreadable = {}, []
    for generation, _parent, _ts, content in versions:
        try:
            parsed[generation] = None if content is None else parse_dotenv(content.decode("utf-8"))
        except (UnicodeDecodeError, DotenvError):
            parsed[generation] = None
        if parsed[generation] is None:
            unreadable.append(generation)
    events = {}
    for generation, parent, ts, _content in versions:
        after = parsed[generation]
        if after is None:
            continue
        if parent is None:
            before = {}
        elif parsed.get(parent) is None:
            continue  # nothing readable to compare with
        else:
            before = parsed[parent]
        for name, value in after.items():
            if name not in before:
                events.setdefault(name, []).append(VariableEvent(generation, ts, "added"))
            elif before[name] != value:
                events.setdefault(name, []).append(VariableEvent(generation, ts, "changed"))
        for name in before:
            if name not in after:
                events.setdefault(name, []).append(VariableEvent(generation, ts, "removed"))
    return events, unreadable


def summarize_variable(events) -> str:
    """One line for a variable: when added, how often changed, when last changed or removed."""
    import time as _time

    def when(event):
        """Generation and date of an event."""
        return f"generation {event.generation} ({_time.strftime('%Y-%m-%d %H:%M', _time.localtime(event.timestamp))})"
    added = [e for e in events if e.kind == "added"]
    changed = [e for e in events if e.kind == "changed"]
    parts = [f"added in {when(added[0])}" if added else "present from the start"]
    if changed:
        parts.append(f"changed {len(changed)} time(s), last in {when(changed[-1])}")
    else:
        parts.append("never changed")
    if events[-1].kind == "removed":
        parts.append(f"removed in {when(events[-1])}")
    return "; ".join(parts)
