"""Hashing engine and target collection."""

import hashlib
import os

CHUNK_SIZE = 1024 * 1024

DEFAULT_ALGORITHM = "sha256"

# The name is what the user passes to -a. Order here is the order shown in -h.
ALGORITHMS = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
}

# Digest length is not unique across algorithms (blake2s and sha3_256 are the
# same width as sha256), so the algorithm is never inferred from a digest alone.
HEX_LENGTHS = {
    name: constructor().digest_size * 2 for name, constructor in ALGORITHMS.items()
}


class UnknownAlgorithmError(ValueError):
    """Raised when -a names an algorithm ReCheck does not support."""


class TargetNotFoundError(FileNotFoundError):
    """Raised when -f points at something that does not exist."""


def available_algorithms():
    """Return supported algorithm names in display order."""
    return list(ALGORITHMS)


def describe_algorithms():
    """Return [(name, bit_length, is_default), ...] for help output."""
    return [
        (name, HEX_LENGTHS[name] * 4, name == DEFAULT_ALGORITHM)
        for name in ALGORITHMS
    ]


def algorithm_summary():
    """One-line listing of algorithms for use inside error messages."""
    return ", ".join(
        "{} ({} bits)".format(name, bits)
        for name, bits, _ in describe_algorithms()
    )


def resolve_algorithm(name):
    """Map a user supplied algorithm name to its canonical lowercase form."""
    key = (name or DEFAULT_ALGORITHM).strip().lower()
    if key not in ALGORITHMS:
        raise UnknownAlgorithmError(
            "unknown algorithm: {!r}. Available: {}".format(name, algorithm_summary())
        )
    return key


def expected_hex_length(algorithm):
    """Number of hex characters a digest of ``algorithm`` produces."""
    return HEX_LENGTHS[algorithm]


def hash_file(path, algorithm=DEFAULT_ALGORITHM, chunk_size=CHUNK_SIZE):
    """Hash path in fixed size chunks and return the hex digest."""
    name = resolve_algorithm(algorithm)
    digest = ALGORITHMS[name]()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_targets(paths, follow_symlinks=False):
    """Expand paths into a sorted list of concrete file paths.

    Directories are walked recursively. Overlapping arguments are deduplicated
    by resolved path so no file gets hashed twice.
    """
    collected = []
    seen = set()

    def add(candidate):
        key = os.path.realpath(candidate) if follow_symlinks else os.path.abspath(candidate)
        if key in seen:
            return
        seen.add(key)
        collected.append(candidate)

    for entry in paths:
        if os.path.isdir(entry):
            for root, dirnames, filenames in os.walk(entry, followlinks=follow_symlinks):
                dirnames.sort()
                for filename in sorted(filenames):
                    add(os.path.join(root, filename))
        else:
            add(entry)
    return collected


def human_size(num_bytes):
    """Format a byte count the way nmap-style tools report sizes."""
    step = 1024.0
    for unit in ("B", "K", "M", "G", "T"):
        if abs(num_bytes) < step or unit == "T":
            if unit == "B":
                return "{} {}".format(int(num_bytes), unit)
            return "{:.1f} {} bytes".format(num_bytes, unit)
        num_bytes /= step
    return "{:.1f} P bytes".format(num_bytes)
