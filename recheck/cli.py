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
    collect_targets,
    describe_algorithms,
    expected_hex_length,
    hash_file,
    human_size,
    resolve_algorithm,
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
ALGORITHM SELECTION:
  -a <alg>: Hash algorithm used for generation and comparison. [default: {default}]
    Available: {algorithms}
MISC:
  -V: Print version number
  -h: Print this help summary page.
MANIFEST FORMAT:
  A manifest has one file per line: <hash><two spaces><path>
    e3b0c442...7852b855  iso.img
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


def _print_run_summary(write, checked, mismatches, errors):
    """Tally the run and name the files that failed, after the per-file reports."""
    failed = len(mismatches) + len(errors)
    if not checked:
        write("ReCheck summary: no files checked\n")
    elif not failed:
        write("ReCheck summary: all {} verified\n".format(_plural(checked, "file")))
    else:
        parts = ["{} of {} verified".format(checked - failed, checked)]
        if mismatches:
            parts.append(_plural(len(mismatches), "MISMATCH", "MISMATCHES"))
        if errors:
            parts.append(_plural(len(errors), "ERROR", "ERRORS"))
        write("ReCheck summary: {}\n".format(", ".join(parts)))
    for path in mismatches:
        write("MISMATCH: {}\n".format(path))
    for path, reason in errors:
        write("ERROR: {} ({})\n".format(path, reason))


def _resolve_targets(paths, algorithm):
    """Hash every requested target, reporting failures instead of aborting."""
    results = []
    for target in collect_targets(paths):
        started = time.perf_counter()
        try:
            size = os.path.getsize(target)
        except OSError:
            size = -1
        try:
            digest = hash_file(target, algorithm)
        except OSError as exc:
            results.append({"path": target, "error": _io_message(exc), "size": size})
            continue
        results.append(
            {
                "path": target,
                "digest": digest,
                "size": size,
                "time": time.perf_counter() - started,
            }
        )
    return results


def _run_hash_only(write, files, algorithm):
    started = time.perf_counter()
    results = _resolve_targets(files, algorithm)
    for result in results:
        _print_report(write, result, algorithm)
    failures = sum(1 for result in results if "error" in result)
    _summary_line(write, len(results) - failures, "hashed", started)
    return EXIT_ERROR if failures else EXIT_OK


def _run_create(write, files, algorithm, manifest_path):
    started = time.perf_counter()
    results = _resolve_targets(files, algorithm)
    for result in results:
        _print_report(write, result, algorithm)
    failures = sum(1 for result in results if "error" in result)
    hashed = len(results) - failures

    if hashed:
        write_manifest(
            manifest_path,
            [(r["digest"], r["path"]) for r in results if "digest" in r],
            algorithm,
        )
    write("Saved {} hash{} to {}\n".format(
        hashed, "" if hashed == 1 else "es", manifest_path
    ))
    _summary_line(write, hashed, "hashed", started)
    return EXIT_ERROR if failures else EXIT_OK


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


def _run_verify_manifest(write, files, algorithm, manifest_path):
    started = time.perf_counter()
    try:
        entries, declared = read_manifest(manifest_path)
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

    selected = None
    unlisted = []
    mismatches = []
    errors = []
    if files:
        wanted = {os.path.normpath(path) for path in collect_targets(files)}
        selected = [
            (digest, path) for digest, path in entries
            if os.path.normpath(path) in wanted
        ]
        listed = {os.path.normpath(path) for _, path in selected}
        unlisted = sorted(wanted - listed)
        for path in unlisted:
            reason = "not listed in manifest {}".format(manifest_path)
            write(
                "ReCheck report for {}\nERROR: {}\n\n".format(path, reason)
            )
            errors.append((path, reason))

    scope = selected if selected is not None else entries
    verdict = EXIT_ERROR if unlisted else EXIT_OK
    for expected, entry_path in scope:
        resolved, relocated = _manifest_lookup_path(entry_path, manifest_path)
        if os.path.isfile(resolved):
            result = _resolve_targets([resolved], algorithm)[0]
        else:
            result = {"path": entry_path, "error": "no such file", "size": -1}
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
    _print_run_summary(write, len(scope) + len(unlisted), mismatches, errors)
    return verdict


def _run_verify_literal(write, files, algorithm, digest, defect=None):
    started = time.perf_counter()
    results = _resolve_targets(files, algorithm)
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
    _print_run_summary(write, len(results), mismatches, errors)
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
