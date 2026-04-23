"""Shared ASan output parsing utilities.

Used by the SE-stage agent (run_agent_for_spec.py) and ASan replay
scripts to detect harness-artifact crashes.
"""
import os
import re

# ── ASan runtime / interceptor patterns ──────────────────────────────

ASAN_RUNTIME_PREFIXES = (
    "__interceptor_", "__asan_", "__sanitizer_",
    "operator new", "operator delete",
)

ASAN_INTERCEPTED_FUNCS = {
    "memcpy", "memmove", "memset", "memcmp",
    "strcpy", "strncpy", "strcat", "strncat",
    "strlen", "strcmp", "strncmp", "strchr", "strrchr",
    "malloc", "calloc", "realloc", "free",
    "printf", "sprintf", "snprintf", "fprintf",
}

RUNTIME_PATH_PATTERNS = (
    "libsanitizer/", "sanitizer_common/", "asan_interceptors",
    "/libc-start", "/libc_start", "nptl/", "csu/",
)

HARNESS_FILE_BASENAMES = {
    "reproducer.c", "replay_driver.c",
    "stubs.c", "smart_stubs.c", "auto_stubs.c",
}

STUB_FILE_BASENAMES = {
    "stubs.c", "smart_stubs.c", "auto_stubs.c",
}

# ── Frame parser ─────────────────────────────────────────────────────

_FRAME_RE = re.compile(r'#(\d+)\s+\S+\s+in\s+(\S+)\s+(\S+):(\d+)')

# Splits ASan output into sections (e.g. the crash trace vs "freed by" trace)
_FREED_BY_RE = re.compile(r'freed by thread.*?(?=\n\n|\nallocated by|\Z)', re.DOTALL)


def parse_asan_frames(output):
    """Extract (frame_num, func, filepath, line) tuples from ASan output."""
    return _FRAME_RE.findall(output)


def _first_user_frame_file(frames):
    """Return the basename of the first user-code frame, or None."""
    for _num, func, fpath, _line in frames:
        if any(func.startswith(p) for p in ASAN_RUNTIME_PREFIXES):
            continue
        if func in ASAN_INTERCEPTED_FUNCS:
            continue
        if any(pat in fpath for pat in RUNTIME_PATH_PATTERNS):
            continue
        return os.path.basename(fpath)
    return None


def is_harness_crash(frames):
    """Return True if the first user-code frame is in harness code.

    Walks *frames* (list of (num, func, filepath, line) tuples) and skips
    ASan runtime / interceptor / system frames.  The first remaining frame
    is checked: if its basename is a known harness file, the crash is a
    harness artifact, not a real library bug.
    """
    f = _first_user_frame_file(frames)
    return f is not None and f in HARNESS_FILE_BASENAMES


def is_stub_free_uaf(output):
    """Return True if a use-after-free's free() originates in stub code.

    Parses the "freed by thread" section of an ASan UAF report.  If the
    first user-code frame in the free chain is in stubs.c / smart_stubs.c,
    the free is manufactured by a stub — the real library function may not
    free in that context.
    """
    if "use-after-free" not in output:
        return False
    m = _FREED_BY_RE.search(output)
    if not m:
        return False
    freed_frames = parse_asan_frames(m.group(0))
    f = _first_user_frame_file(freed_frames)
    return f is not None and f in STUB_FILE_BASENAMES
