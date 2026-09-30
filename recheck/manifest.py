"""Read and write ReCheck manifests.

The on-disk format is the GNU coreutils one, so a manifest written here can be
checked with ``sha256sum -c`` and vice versa::

    <hex digest><two spaces><file path>

Two leading comment lines record the algorithm. GNU coreutils ignores lines
starting with ``#``, including under ``--strict``, so they cost nothing.
"""

import os
import re

from recheck.core import HEX_LENGTHS

MANIFEST_VERSION = "1"
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_ALGORITHM_PREFIX_RE = re.compile(r"\A([A-Za-z0-9_-]+):([0-9a-fA-F]+)\Z")
_LABEL_RE = re.compile(r"\A([A-Za-z0-9_-]+):(\S+)\Z")
_NON_HEX_RE = re.compile(r"[^0-9a-fA-F]")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# A pasted digest is a single unbroken token, so anything carrying path syntax is
# a filename instead. The width window is deliberately tight: it separates a
# mistyped hash from a short hex-ish filename such as "deadbeef.txt".
_WIDTH_SLACK = 8

_FORMAT_HINT = (
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


def _is_hex_token(value):
    """True when value is one unbroken token that is mostly hex digits."""
    if not value or os.sep in value or (os.altsep and os.altsep in value):
        return False
    if "." in value or any(char.isspace() for char in value):
        return False
    return sum(1 for char in value if char in _HEX_DIGITS) * 2 >= len(value)


def looks_like_digest(value):
    """True when value is text that was meant to be a digest but is not one.

    A digest is a single token of hex, so a copy that picked up a stray
    character still looks like one to a human. Recognising that shape lets the
    caller answer "this does not match" instead of "no such file". Any supported
    digest width counts, so an md5 pasted under -a sha256 is still a hash.
    """
    if not _is_hex_token(value):
        return False
    return any(
        abs(len(value) - width) <= _WIDTH_SLACK for width in HEX_LENGTHS.values()
    )


def digest_defect(value, expected_length):
    """Explain why value is not a usable digest, as a clause for a message.

    Returns None when the text really is a digest of the expected width.
    """
    if not value:
        return "it is empty"
    offenders = sorted(set(_NON_HEX_RE.findall(value)))
    if offenders:
        return "it contains characters that are not hex: {}".format(
            ", ".join(repr(char) for char in offenders)
        )
    if len(value) != expected_length:
        return "it is {} characters long, not {}".format(len(value), expected_length)
    return None


def _length_error(algorithm, value, expected_length):
    return ManifestError(
        "hash is {} hex characters but -a {} expects {}. "
        "Pass -a <algorithm> or label the hash, e.g. {}:{}".format(
            len(value), algorithm, expected_length, algorithm, value[:8] + "..."
        )
    )


def parse_verify_target(value, algorithm, expected_length):
    """Classify a -v argument.

    Returns (kind, value, label, defect). ``kind`` is "hash" for a usable
    inline digest, "malformed" for text that was clearly meant to be one, and
    "file" when the argument names a manifest. ``defect`` explains a malformed
    digest and is None otherwise.
    """
    text = value or ""

    labelled = _ALGORITHM_PREFIX_RE.match(text)
    if labelled:
        name = labelled.group(1).lower()
        digest = labelled.group(2)
        if name != algorithm.lower():
            raise ManifestError(
                "hash is labelled {}-bit {} but -a is {}. "
                "Use -a {} or drop the label.".format(
                    len(digest) * 4, name, algorithm, name
                )
            )
        if len(digest) != expected_length:
            raise _length_error(algorithm, digest, expected_length)
        return "hash", digest.lower(), algorithm, None

    if is_hash_literal(text):
        if len(text) != expected_length:
            raise _length_error(algorithm, text, expected_length)
        return "hash", text.lower(), algorithm, None

    # A mistyped digest: report the integrity verdict rather than a missing file.
    body = _LABEL_RE.match(text)
    if body and _is_hex_token(body.group(2)):
        name = body.group(1).lower()
        if name != algorithm.lower():
            raise ManifestError(
                "hash is labelled {} but -a is {}. "
                "Use -a {} or drop the label.".format(name, algorithm, name)
            )
        return "malformed", text, algorithm, digest_defect(
            body.group(2), expected_length
        )

    if looks_like_digest(text):
        return "malformed", text, None, digest_defect(text, expected_length)

    return "file", text, None, None


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
