"""Command line interface for ReCheck.

    -f <path>   target file or directory (directories are walked recursively)
    -c <file>   write the computed hash(es) to a manifest file
    -v <val>    verify against a manifest file or an inline hash value
    -a <alg>    hash algorithm used for both generation and comparison
    -V          version
    -h, --help  help summary
"""

import argparse
import os
import sys
import time

from recheck import __version__
from recheck.core import (
    DEFAULT_ALGORITHM,
    UnknownAlgorithmError,
    describe_algorithms,
    expected_hex_length,
    hash_file,
    human_size,
    resolve_algorithm,
    scan_paths,
)
from recheck.manifest import (
    ManifestError,
    parse_verify_target,
    read_manifest,
    write_manifest,
)

PROG = "recheck"
BANNER_URL = "https://github.com/1RenXc/ReCheck-Integrity"

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


class ReCheckError(Exception):
    """Error that maps onto a specific process exit code."""

    exit_code = EXIT_ERROR

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


class UsageError(ReCheckError):
    exit_code = EXIT_USAGE


def _version_banner():
    return "{} {} ( {} )".format(PROG, __version__, BANNER_URL)


def _format_algorithm_list():
    return ", ".join(
        "{}{}".format(name, " ({}-bit, default)".format(bits) if is_default
                      else " ({}-bit)".format(bits))
        for name, bits, is_default in describe_algorithms()
    )


def build_help_text():
    return """{banner}
Usage: {prog} -f <file|directory> [Options]
TARGET SPECIFICATION:
  -f <path>: File or directory to hash. Directories are walked recursively.
    Ex: -f ./file.txt, -f /var/log, -f a.bin -f b.bin
HASH GENERATION:
  -c <file>: Write the computed hash(es) to <file> as a manifest.
    The manifest is sha256sum-compatible: `sha256sum -c <file>` also works.
VERIFICATION:
  -v <file|hash>: Compare the target against a manifest file, or against an
    inline hash value. Hex input may be prefixed with its algorithm.
    Ex: -v recheck-file.txt, -v 3f786850..., -v md5:900150983cd24fb0...
  A manifest run also walks the target tree and reports what the walk found
    beyond the manifest:
    UNREADABLE: <folder>   the folder could not be listed, usually by access
                           rights, so its contents were not checked at all
    NEW FILE: <path>       present on disk but absent from the manifest
    NEW FOLDER: <path>     same, for a folder
ALGORITHM SELECTION:
  -a <alg>: Hash algorithm used for generation and comparison. [default: {default}]
    Available: {algorithms}
MISC:
  -V: Print version number
  -h: Print this help summary page.
MANIFEST FORMAT:
  A manifest has one file per line: <hash><two spaces><path>
    e3b0c442...7852b855  iso.img
  Folders are kept as comment lines: #d <path>
  The format matches sha256sum, and lines starting with # are ignored.
  Create one with: {prog} -f <file|directory> -c <manifest>
EXAMPLES:
  {prog} -f ./sample_file.txt
  {prog} -f ./sample_file.txt -c recheck-sample_file.txt
  {prog} -f ./sample_file.txt -v recheck-sample_file.txt
  {prog} -f ./sample_file.txt -v 3f786850e387550fdab836ed7e6dc881de23001b -a sha256
  {prog} -f ./sample_file.txt -a md5 -c sample_file.md5.txt
  {prog} -f ./folder -v recheck-folder.txt
""".format(
        banner=_version_banner(),
        prog=PROG,
        algorithms=_format_algorithm_list(),
        default=DEFAULT_ALGORITHM,
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROG,
        add_help=False,
        usage="%(prog)s -f <file|directory> [Options]",
        description="Verify file integrity with SHA-256 and other hash algorithms.",
    )
    parser.add_argument(
        "-f", "--file", action="append", dest="files", metavar="<path>",
        help="file or directory to hash (repeatable)",
    )
    parser.add_argument(
        "-c", "--create", dest="create", metavar="<file>",
        help="write computed hash(es) to manifest file",
    )
    parser.add_argument(
        "-v", "--verify", dest="verify", metavar="<file|hash>",
        help="verify against a manifest file or an inline hash value",
    )
    parser.add_argument(
        "-a", "--algorithm", dest="algorithm", metavar="<alg>",
        default=DEFAULT_ALGORITHM,
        help="hash algorithm (default: {})".format(DEFAULT_ALGORITHM),
    )
    parser.add_argument(
        "-V", "--version", dest="show_version", action="store_true",
        help="print version number",
    )
    parser.add_argument(
        "-h", "--help", dest="show_help", action="store_true",
        help="print this help summary page",
    )
    return parser


def _io_message(exc):
    if isinstance(exc, FileNotFoundError):
        return "no such file"
    if isinstance(exc, IsADirectoryError):
        return "is a directory"
    if isinstance(exc, PermissionError):
        return "permission denied"
    return exc.strerror or str(exc)


def _throughput(result):
    if result["time"] <= 0 or result["size"] < 0:
        return "n/a"
    rate = result["size"] / result["time"]
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if rate < 1024.0:
            return "{:.1f} {}".format(rate, unit)
        rate /= 1024.0
    return "{:.1f} TB/s".format(rate)


def _print_report(write, result, algorithm):
    write("ReCheck report for {}\n".format(result["path"]))
    if "error" in result:
        write("ERROR: {}\n\n".format(result["error"]))
        return
    size = human_size(result["size"]) if result["size"] >= 0 else "unknown"
    write(
        "Size: {}   Time: {:.2f} s   Throughput: {}\n".format(
            size, result["time"], _throughput(result)
        )
    )
    write("{}: {}\n".format(algorithm, result["digest"]))


def _print_verdict(write, result, expected, algorithm, reason, defect=None):
    """Report the outcome for one file and return (exit code, status).

    status is "match", "mismatch" or "error" and feeds the run summary.
    """
    if "error" in result:
        write("ERROR: {}\n\n".format(result["error"]))
        return EXIT_ERROR, "error"
    if result["digest"] == expected:
        write("MATCH: integrity confirmed\n\n")
        return EXIT_OK, "match"
    write("MISMATCH: {}, so the integrity of {} is not confirmed\n".format(
        reason, result["path"]
    ))
    write("  expected: {}\n".format(expected))
    write("  actual:   {}\n".format(result["digest"]))
    if defect:
        write("  note:     the expected value is not a valid {} digest; {}\n".format(
            algorithm, defect
        ))
    write("\n")
    return EXIT_MISMATCH, "mismatch"


def _summary_line(write, count, verb, started):
    write(
        "ReCheck done: {} file{} {} in {:.2f} seconds\n".format(
            count, "" if count == 1 else "s", verb, time.perf_counter() - started
        )
    )


def _plural(count, singular, plural=None):
    """Format a count with its noun, e.g. 1 MISMATCH / 2 MISMATCHES."""
    if count == 1:
        return "{} {}".format(count, singular)
    return "{} {}".format(count, plural or singular + "s")


def _record_status(status, path, result, mismatches, errors):
    """File one target's outcome for the run summary at the end of the report."""
    if status == "mismatch":
        mismatches.append(path)
    elif status == "error":
        errors.append((path, result.get("error", "could not be read")))


def _print_unreadable(write, issues):
    """Name the folders the recursive walk could not read."""
    for issue in issues:
        write("UNREADABLE: {} ({})\n".format(issue.path, issue.reason))


def _print_run_summary(write, checked, mismatches, errors, additions=(), unreadable=()):
    """Tally the run and name what failed, after the per-file reports.

    additions holds (kind, path) pairs for entries that exist on disk but not in
    the manifest, with kind "file" or "folder". unreadable holds the WalkIssue
    records for folders the walk could not list.
    """
    new_files = [path for kind, path in additions if kind == "file"]
    new_folders = [path for kind, path in additions if kind == "folder"]
    failed = len(mismatches) + len(errors)
    if not checked:
        write("ReCheck summary: no files checked\n")
    elif not failed and not additions and not unreadable:
        write("ReCheck summary: all {} verified\n".format(_plural(checked, "file")))
    else:
        parts = ["{} of {} verified".format(checked - failed, checked)]
        if mismatches:
            parts.append(_plural(len(mismatches), "MISMATCH", "MISMATCHES"))
        if errors:
            parts.append(_plural(len(errors), "ERROR", "ERRORS"))
        if unreadable:
            parts.append(_plural(len(unreadable), "UNREADABLE FOLDER"))
        if new_files:
            parts.append(_plural(len(new_files), "NEW FILE", "NEW FILES"))
        if new_folders:
            parts.append(_plural(len(new_folders), "NEW FOLDER", "NEW FOLDERS"))
        write("ReCheck summary: {}\n".format(", ".join(parts)))
    for path in mismatches:
        write("MISMATCH: {}\n".format(path))
    for path, reason in errors:
        write("ERROR: {} ({})\n".format(path, reason))
    _print_unreadable(write, unreadable)
    for path in new_files:
        write("NEW FILE: {}\n".format(path))
    for path in new_folders:
        write("NEW FOLDER: {}\n".format(path))


def _hash_target(target, algorithm):
    """Hash one file, returning a record holding either a digest or an error."""
    started = time.perf_counter()
    try:
        size = os.path.getsize(target)
    except OSError:
        size = -1
    try:
        digest = hash_file(target, algorithm)
    except OSError as exc:
        return {"path": target, "error": _io_message(exc), "size": size}
    return {
        "path": target,
        "digest": digest,
        "size": size,
        "time": time.perf_counter() - started,
    }


def _resolve_targets(paths, algorithm):
    """Hash every reachable target, reporting failures instead of aborting.

    Returns (results, scan). The scan is handed back because a folder that could
    not be listed has no result of its own: it is reported next to the summary.
    """
    scan = scan_paths(paths)
    return [_hash_target(path, algorithm) for path in scan.files], scan


def _run_hash_only(write, files, algorithm):
    started = time.perf_counter()
    results, scan = _resolve_targets(files, algorithm)
    for result in results:
        _print_report(write, result, algorithm)
    failures = sum(1 for result in results if "error" in result)
    _summary_line(write, len(results) - failures, "hashed", started)
    _print_unreadable(write, scan.issues)
    return EXIT_ERROR if failures or scan.issues else EXIT_OK


def _run_create(write, files, algorithm, manifest_path):
    started = time.perf_counter()
    results, scan = _resolve_targets(files, algorithm)
    for result in results:
        _print_report(write, result, algorithm)
    failures = sum(1 for result in results if "error" in result)
    hashed = len(results) - failures

    if hashed:
        write_manifest(
            manifest_path,
            [(r["digest"], r["path"]) for r in results if "digest" in r],
            algorithm,
            scan.directories,
        )
    write("Saved {} hash{} to {}\n".format(
        hashed, "" if hashed == 1 else "es", manifest_path
    ))
    _summary_line(write, hashed, "hashed", started)
    _print_unreadable(write, scan.issues)
    return EXIT_ERROR if failures or scan.issues else EXIT_OK


def _manifest_lookup_path(entry_path, manifest_path):
    """Resolve a manifest entry the way sha256sum does, then fall back.

    coreutils resolves relative entries against the current directory; if that
    fails, retry relative to the manifest itself.
    """
    if os.path.isabs(entry_path) or os.path.exists(entry_path):
        return entry_path, False
    alternative = os.path.join(
        os.path.dirname(os.path.abspath(manifest_path)), entry_path
    )
    if os.path.exists(alternative):
        return alternative, True
    return entry_path, False


def _path_key(path):
    """One absolute identity for a path.

    A manifest entry says ``proj/a.txt`` while a walk reaches the same file as
    ``/home/you/rc/proj/a.txt``. Both spellings have to reduce to one string
    before they can be compared for "is this in the manifest".
    """
    return os.path.normpath(os.path.abspath(path))


def _is_inside(path, root):
    """True when path is root itself or sits below it."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _entry_roots(entries, manifest_path):
    """Folders to walk when the manifest alone defines the run.

    Every entry's own folder is a candidate, so a file dropped next to a tracked
    one is still found. A candidate already covered by an accepted root is
    skipped, because walking the outer folder reaches it anyway. A candidate
    that no longer exists is dropped too: its entries are already reported as
    missing while the manifest itself is verified.
    """
    roots = []
    covered = []
    for _, path in entries:
        resolved, _ = _manifest_lookup_path(path, manifest_path)
        parent = os.path.dirname(resolved) or os.curdir
        key = _path_key(parent)
        if not os.path.isdir(parent) or any(_is_inside(key, root) for root in covered):
            continue
        covered.append(key)
        roots.append(parent)
    return roots


def _new_entries(scan, listed_files, listed_folders):
    """Return (kind, path) pairs on disk that the manifest does not list.

    An entry that exists now and was absent then either appeared after the
    manifest was written or was never covered by it. Both mean integrity is
    not confirmed, so both are reported the same way. A requested path that is
    not there at all is not new, so it is left out: nothing was added, and a
    missing file is a different report.
    """
    additions = []
    for path in scan.files:
        if _path_key(path) not in listed_files and os.path.exists(path):
            additions.append(("file", path))
    for path in scan.directories:
        if _path_key(path) not in listed_folders:
            additions.append(("folder", path))
    return additions


def _run_verify_manifest(write, files, algorithm, manifest_path):
    started = time.perf_counter()
    try:
        entries, directories, declared = read_manifest(manifest_path)
    except FileNotFoundError:
        raise ReCheckError("manifest not found: {}".format(manifest_path))
    except OSError as exc:
        raise ReCheckError(
            "cannot read manifest {}: {}".format(manifest_path, _io_message(exc))
        )
    except ManifestError as exc:
        raise ReCheckError(str(exc), hint=exc.hint)

    if declared and declared != algorithm:
        write(
            "Note: manifest was generated with {}; comparing with {} "
            "as requested by -a\n".format(declared, algorithm)
        )

    # The walk behind the NEW and UNREADABLE lines. With -f the requested paths
    # set the scope; without -f the manifest's own folders are walked, so a run
    # over a whole tree still notices a file that appeared in it.
    scan = scan_paths(files if files else _entry_roots(entries, manifest_path))
    # Resolve every entry once: that one answer decides both whether the walk
    # already covered a path and where the hash is read from.
    lookups = [_manifest_lookup_path(path, manifest_path) for _, path in entries]
    listed_files = {_path_key(target) for target, _ in lookups}
    # Folder records are resolved the same way file entries are, so a manifest
    # checked from another directory still matches its own folders.
    listed_folders = {
        _path_key(_manifest_lookup_path(path, manifest_path)[0])
        for path in directories
    }
    if directories:
        additions = _new_entries(scan, listed_files, listed_folders)
    else:
        # A coreutils manifest has no folder records, so every folder on disk
        # would look new. Say so instead of drowning the report in noise.
        additions = [
            ("file", path) for path in scan.files
            if _path_key(path) not in listed_files and os.path.exists(path)
        ]
        if scan.directories:
            write(
                "Note: {} lists no folders, so NEW FOLDER reporting is off. "
                "Regenerate it with 'recheck -f <path> -c <manifest>' to turn "
                "it on.\n".format(manifest_path)
            )

    # A -f path that is not on disk and not in the manifest is neither checked
    # nor new, so it is named as the plain error it is.
    absent = [
        (path, "no such file") for path in files or []
        if not os.path.exists(path) and _path_key(path) not in listed_files
    ]

    scope = list(zip(entries, lookups))
    if files:
        wanted = {_path_key(path) for path in scan.files}
        scope = [
            pair for pair in scope if _path_key(pair[1][0]) in wanted
        ]

    mismatches = []
    errors = list(absent)
    verdict = EXIT_ERROR if absent else EXIT_OK
    for (expected, entry_path), (target, relocated) in scope:
        result = _hash_target(target, algorithm)
        if relocated:
            result["path"] = "{} (from manifest directory)".format(entry_path)
        _print_report(write, result, algorithm)
        code, status = _print_verdict(
            write, result, expected, algorithm,
            "the file no longer matches the manifest",
        )
        _record_status(status, entry_path, result, mismatches, errors)
        verdict = max(verdict, code)

    _summary_line(write, len(scope), "verified", started)
    _print_run_summary(write, len(scope), mismatches, errors, additions, scan.issues)
    if additions:
        verdict = max(verdict, EXIT_MISMATCH)
    if scan.issues:
        verdict = max(verdict, EXIT_ERROR)
    return verdict


def _run_verify_literal(write, files, algorithm, digest, defect=None):
    started = time.perf_counter()
    results, scan = _resolve_targets(files, algorithm)
    mismatches = []
    errors = []
    verdict = EXIT_OK
    for result in results:
        _print_report(write, result, algorithm)
        code, status = _print_verdict(
            write, result, digest, algorithm, "the hash does not match", defect
        )
        _record_status(status, result["path"], result, mismatches, errors)
        verdict = max(verdict, code)
    _summary_line(write, len(results), "verified", started)
    _print_run_summary(write, len(results), mismatches, errors, (), scan.issues)
    if scan.issues:
        verdict = max(verdict, EXIT_ERROR)
    return verdict


def _dispatch(write, args, algorithm):
    if args.create and args.verify:
        raise UsageError(
            "-c and -v cannot be used together. "
            "Use -c to save a hash, or -v to compare one."
        )

    if args.create:
        if not args.files:
            raise UsageError(
                "-c needs a target: recheck -f <file|directory> -c <manifest>"
            )
        return _run_create(write, args.files, algorithm, args.create)

    if args.verify:
        try:
            kind, value, _, defect = parse_verify_target(
                args.verify, algorithm, expected_hex_length(algorithm)
            )
        except ManifestError as exc:
            raise UsageError(str(exc), hint=exc.hint)

        if kind in ("hash", "malformed"):
            if not args.files:
                raise UsageError(
                    "-v <hash> needs a target: recheck -f <file> -v <hash>"
                )
            if len(args.files) != 1:
                raise UsageError(
                    "-v <hash> compares a single file, but {} targets were "
                    "given. Use -v <manifest> for multiple files.".format(
                        len(args.files)
                    )
                )
            return _run_verify_literal(write, args.files, algorithm, value, defect)

        # -v <manifest> needs no -f: every entry is checked, like sha256sum -c.
        # Passing -f narrows the run to those files, which is a spot check.
        return _run_verify_manifest(write, args.files, algorithm, value)

    if not args.files:
        raise UsageError(
            "no target given. Try 'recheck -f <file|directory>' "
            "or 'recheck -h' for help."
        )
    return _run_hash_only(write, args.files, algorithm)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    write = sys.stdout.write
    fail = sys.stderr.write

    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code in (0, None) else EXIT_USAGE

    if args.show_help:
        write(build_help_text())
        return EXIT_OK

    if args.show_version:
        write(_version_banner() + "\n")
        return EXIT_OK

    try:
        algorithm = resolve_algorithm(args.algorithm)
        return _dispatch(write, args, algorithm)
    except UnknownAlgorithmError as exc:
        fail("{}: {}\n".format(PROG, exc))
        return EXIT_USAGE
    except ReCheckError as exc:
        fail("{}: {}\n".format(PROG, exc))
        if exc.hint:
            lines = str(exc.hint).splitlines() or [""]
            fail("Hint: {}\n".format(lines[0]))
            for line in lines[1:]:
                fail("      {}\n".format(line))
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
