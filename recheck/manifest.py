"""Read and write ReCheck manifests.

The on-disk format is the GNU coreutils one, so a manifest written here can be
checked with ``sha256sum -c`` and vice versa::

    <hex digest><two spaces><file path>

Two leading comment lines record the algorithm. GNU coreutils ignores lines
starting with ``#``, including under ``--strict``, so they cost nothing.
"""

import os
import re

MANIFEST_VERSION = "1"
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_ALGORITHM_PREFIX_RE = re.compile(r"\A([A-Za-z0-9_-]+):([0-9a-fA-F]+)\Z")

_FORMAT_HINT = (
    "a manifest holds one file per line as <hash><two spaces><path>, "
    "for example: e3b0c442...7852b855  iso.img\n"
    "create one with 'recheck -f <file> -c <manifest>'; "
    "run 'recheck -h' for the full format"
)


class ManifestError(ValueError):
    """Raised for malformed manifests or unusable hash literals."""

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


def is_hash_literal(value):
    """True when value is a bare hex digest with no path meaning."""
    if not value or os.sep in value or (os.altsep and os.altsep in value):
        return False
    return bool(_HEX_RE.match(value))


def parse_verify_target(value, algorithm, expected_length):
    """Classify a -v argument.

    Returns ("hash", digest, label) for an inline digest, or ("file", path,
    None) when the argument points at a manifest.
    """
    prefixed = _ALGORITHM_PREFIX_RE.match(value or "")
    if prefixed:
        name = prefixed.group(1).lower()
        digest = prefixed.group(2).lower()
        if name != algorithm.lower():
            raise ManifestError(
                "hash is labelled {}-bit {} but -a is {}. "
                "Use -a {} or drop the label.".format(
                    len(digest) * 4, name, algorithm, name
                )
            )
        if len(digest) != expected_length:
            raise ManifestError(
                "{} digest must be {} hex characters, got {}".format(
                    algorithm, expected_length, len(digest)
                )
            )
        return "hash", digest, algorithm

    if is_hash_literal(value):
        digest = value.lower()
        if len(digest) != expected_length:
            raise ManifestError(
                "hash is {} hex characters but -a {} expects {}. "
                "Pass -a <algorithm> or label the hash, e.g. {}:{}".format(
                    len(digest), algorithm, expected_length, algorithm, digest[:8] + "..."
                )
            )
        return "hash", digest, algorithm

    return "file", value, None


def _escape(name):
    """Escape a path the way coreutils does (leading backslash marker)."""
    if "\n" in name or "\\" in name:
        return "\\" + name.replace("\\", "\\\\").replace("\n", "\\n")
    return name


def _unescape(name):
    if name.startswith("\\"):
        return name[1:].replace("\\n", "\n").replace("\\\\", "\\")
    return name


def format_manifest(entries, algorithm):
    """Render manifest text from [(digest, path), ...]."""
    lines = [
        "# ReCheck manifest v{}".format(MANIFEST_VERSION),
        "# algorithm: {}".format(algorithm),
    ]
    for digest, path in entries:
        lines.append("{}  {}".format(digest, _escape(path)))
    return "\n".join(lines) + "\n"


def write_manifest(path, entries, algorithm):
    """Write a manifest to path and return the number of data lines."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(format_manifest(entries, algorithm))
    return len(entries)


def read_manifest(path):
    """Parse a manifest.

    Returns (entries, declared_algorithm). The declared value comes from the
    ``# algorithm:`` comment and is a hint for diagnostics only; the caller's
    ``-a`` stays authoritative.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        raw = handle.read()

    entries = []
    declared = None

    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            body = line.lstrip()[1:].strip()
            if body.lower().startswith("algorithm:"):
                declared = body.split(":", 1)[1].strip().lower()
            continue

        digest, separator, name = _split_entry(line)
        if not separator or not _HEX_RE.match(digest or "") or not name:
            raise ManifestError(
                "{}:{}: improperly formatted manifest line: {!r}".format(
                    path, lineno, line
                ),
                hint=_FORMAT_HINT,
            )
        entries.append((digest.lower(), _unescape(name)))

    if not entries:
        raise ManifestError(
            "{}: no properly formatted manifest lines found".format(path),
            hint=_FORMAT_HINT,
        )
    return entries, declared


def _split_entry(line):
    """Split ``HASH  PATH`` or the binary-mode ``HASH *PATH`` variant."""
    for separator in ("  ", " *"):
        if separator in line:
            digest, name = line.split(separator, 1)
            return digest.strip(), separator, name
    return line.strip(), "", ""
