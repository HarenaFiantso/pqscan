# SPDX-License-Identifier: Apache-2.0
"""Measures pqscan on real projects: how right it is, and how fast.

    python3 bench/bench.py fetch                 # download and unpack the corpus into build/bench
    python3 bench/bench.py evaluate [--write]    # precision and recall against bench/labels
    python3 bench/bench.py perf [--check]        # time and memory against bench/perf.json

The corpus is third-party code, pinned in bench/corpus.json by tag and SHA-256, and never
committed. Only the standard library is used, so any Python 3.9 or newer runs this.
"""

import argparse
import collections
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
WORK = ROOT / "build" / "bench"
ARCHIVES = WORK / "archives"
SOURCES = WORK / "src"
DEFAULT_PQSCAN = ROOT / "build" / "release" / "pqscan"

# Pinned so that priorities, which no metric uses, do not change the output with the calendar.
AS_OF_YEAR = "2026"
SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".C", ".ipp", ".inl", ".tcc")
# pqscan exits 0, 1 or 4 when it has written a report.
REPORT_EXIT_CODES = (0, 1, 4)
CHUNK = 1 << 20
MEBIBYTE = 1 << 20


def load_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def corpus():
    return load_json(BENCH / "corpus.json")["projects"]


# ---------------------------------------------------------------------------------------------
# fetch


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(project, archive):
    url = f"https://codeload.github.com/{project['repository']}/tar.gz/refs/tags/{project['tag']}"
    partial = archive.with_suffix(".part")
    request = urllib.request.Request(url, headers={"User-Agent": "pqscan-bench"})
    with urllib.request.urlopen(request, timeout=120) as response, open(partial, "wb") as file:
        for chunk in iter(lambda: response.read(CHUNK), b""):
            file.write(chunk)
    found = sha256_of(partial)
    if found != project["sha256"]:
        partial.unlink()
        sys.exit(f"bench: {url}: SHA-256 {found}, expected {project['sha256']}")
    partial.rename(archive)


def safe_members(archive):
    """Drops the top directory GitHub adds, and refuses anything that would land outside."""
    for member in archive.getmembers():
        parts = Path(member.name).parts[1:]
        if not parts or member.issym() or member.islnk() or member.isdev():
            continue
        if any(part in ("..", "") for part in parts) or Path(member.name).is_absolute():
            sys.exit(f"bench: refusing archive entry {member.name!r}")
        member.name = str(Path(*parts))
        yield member


def unpack(archive, target):
    partial = target.with_name(target.name + ".part")
    partial.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = list(safe_members(tar))
        if hasattr(tarfile, "data_filter"):
            tar.extractall(partial, members=members, filter="data")
        else:
            tar.extractall(partial, members=members)
    partial.rename(target)


def fetch(_args):
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    SOURCES.mkdir(parents=True, exist_ok=True)
    for project in corpus():
        archive = ARCHIVES / f"{project['name']}-{project['tag']}.tar.gz"
        if not archive.exists() or sha256_of(archive) != project["sha256"]:
            print(f"downloading {project['name']} {project['tag']}")
            download(project, archive)
        target = SOURCES / project["name"]
        stamp = target / ".pqscan-bench-tag"
        if not stamp.exists() or stamp.read_text() != project["sha256"]:
            if target.exists():
                sys.exit(f"bench: {target} is from another version, remove it first")
            print(f"unpacking {project['name']}")
            unpack(archive, target)
            stamp.write_text(project["sha256"])
    return 0


# ---------------------------------------------------------------------------------------------
# evaluate


def run_pqscan(pqscan, paths):
    command = [str(pqscan), "--as-of", AS_OF_YEAR, "--format", "json", "--", *paths]
    result = subprocess.run(command, cwd=SOURCES, capture_output=True, check=False)
    if result.returncode not in REPORT_EXIT_CODES:
        sys.exit(f"bench: pqscan exited {result.returncode}\n{result.stderr.decode(errors='replace')}")
    return json.loads(result.stdout)


def is_source(path):
    return path.endswith(SOURCE_SUFFIXES)


def key_size_of(value):
    return value if isinstance(value, int) else None


def found_groups(report):
    """Findings by (path, line, algorithm). In source, a line counts once per algorithm, however
    many identifiers it holds. In a certificate, a key and a signature are two findings."""
    groups = collections.defaultdict(list)
    for item in report["findings"]:
        place = (item["path"], item["line"], item["algorithm"])
        size = key_size_of(item["key_size"])
        if not is_source(item["path"]):
            groups[place].append(size)
        elif not groups[place]:
            groups[place].append(size)
        elif groups[place][0] is None:
            groups[place][0] = size
    return groups


def labeled_groups(files):
    groups = collections.defaultdict(list)
    for path, labels in files.items():
        for label in labels:
            groups[(path, label["line"], label["algorithm"])].append(label.get("key_size"))
    return groups


class Score:
    def __init__(self):
        self.counts = collections.Counter()
        self.misses = []

    def add(self, other):
        self.counts.update(other.counts)
        self.misses.extend(other.misses)

    def ratio(self, numerator, denominator):
        total = self.counts[numerator] + self.counts[denominator]
        return self.counts[numerator] / total if total else 1.0

    @property
    def precision(self):
        return self.ratio("tp", "fp")

    @property
    def recall(self):
        return self.ratio("tp", "fn")

    @property
    def file_precision(self):
        return self.ratio("file_tp", "file_fp")

    @property
    def file_recall(self):
        return self.ratio("file_tp", "file_fn")

    @property
    def key_size_accuracy(self):
        return self.ratio("sizes_right", "sizes_wrong")


def score_sizes(expected, found, score):
    """Pairs the labels at one place with its findings, equal sizes first, and scores each label
    that gives a size."""
    remaining = list(found)
    for size in expected:
        if size in remaining:
            remaining.remove(size)
            score.counts["sizes_right"] += size is not None
        elif size is not None:
            score.counts["sizes_wrong"] += 1


def score_places(expected_groups, found_by_place):
    score = Score()
    for place in sorted(set(expected_groups) | set(found_by_place), key=str):
        expected = expected_groups.get(place, [])
        found = found_by_place.get(place, [])
        matched = min(len(expected), len(found))
        score.counts["tp"] += matched
        score.counts["fn"] += len(expected) - matched
        score.counts["fp"] += len(found) - matched
        if matched:
            score_sizes(expected[:matched], found, score)
        for _ in range(len(expected) - matched):
            score.misses.append(("missed", place))
        for _ in range(len(found) - matched):
            score.misses.append(("spurious", place))
    return score


def score_files(expected_groups, found_by_place, score):
    expected = {(path, alg) for path, _, alg in expected_groups}
    found = {(path, alg) for path, _, alg in found_by_place}
    score.counts["file_tp"] += len(expected & found)
    score.counts["file_fn"] += len(expected - found)
    score.counts["file_fp"] += len(found - expected)


# Two sets of labels. The rules were extended after reading the misses on the first, so its
# scores are optimistic. The second was labeled afterwards, from files no rule was tuned on.
LABEL_SETS = (
    ("Tuned on", BENCH / "labels"),
    ("Held out", BENCH / "labels" / "held-out"),
)


def evaluate_project(pqscan, labels):
    name = labels.stem
    files = load_json(labels)["files"]
    report = run_pqscan(pqscan, sorted(files))
    unanalyzed = [entry["path"] for entry in report["unanalyzed"]]
    if unanalyzed:
        sys.exit(f"bench: {name}: labeled files were not analyzed: {unanalyzed}")
    expected = labeled_groups(files)
    found = found_groups(report)
    score = score_places(expected, found)
    score_files(expected, found, score)
    return score


def percent(value):
    return f"{100 * value:.1f}%"


def score_row(name, score):
    counts = score.counts
    return (
        f"| {name} | {counts['tp'] + counts['fn']} | {counts['tp']} | {counts['fp']} | {counts['fn']} "
        f"| {percent(score.precision)} | {percent(score.recall)} "
        f"| {percent(score.file_precision)} | {percent(score.file_recall)} "
        f"| {counts['sizes_right']}/{counts['sizes_right'] + counts['sizes_wrong']} |"
    )


def evaluation_table(scores, total):
    lines = [
        "| Project | Labels | Found | False positives | Missed | Precision | Recall "
        "| File precision | File recall | Key sizes |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    lines += [score_row(name, score) for name, score in scores]
    lines.append(score_row("**All**", total))
    return "\n".join(lines)


def miss_list(scores):
    lines = []
    for _, score in scores:
        for kind, (path, line, algorithm) in score.misses:
            where = f"{path}:{line}" if line is not None else path
            lines.append(f"- {kind}: `{where}` {algorithm}")
    return "\n".join(lines) if lines else "None."


def evaluate_set(pqscan, directory):
    """Scores every project that has labels in a directory, and their total."""
    names = {p["name"] for p in corpus() if p["labeled"]}
    scores = [(path.stem, evaluate_project(pqscan, path)) for path in sorted(directory.glob("*.json")) if path.stem in names]
    total = Score()
    for _, score in scores:
        total.add(score)
    return scores, total


def evaluate(args):
    sections = []
    for title, directory in LABEL_SETS:
        scores, total = evaluate_set(args.pqscan, directory)
        sections.append(f"## {title}\n\n{evaluation_table(scores, total)}\n\n### What pqscan got wrong\n\n{miss_list(scores)}")
    text = "\n\n".join(sections)
    print(text)
    if args.write:
        write_evaluation(text)
    return 0


def write_evaluation(text):
    header = (
        "# Evaluation results\n\n"
        "Written by `python3 bench/bench.py evaluate --write`. Do not edit by hand.\n\n"
    )
    (BENCH / "results.md").write_text(header + text + "\n", encoding="utf-8")
# ---------------------------------------------------------------------------------------------
# perf


def tree_bytes(path):
    total = 0
    for directory, _, names in os.walk(path):
        for name in names:
            full = os.path.join(directory, name)
            if not os.path.islink(full):
                total += os.path.getsize(full)
    return total


def peak_rss_mib(usage):
    """ru_maxrss is in bytes on macOS and in kibibytes on Linux."""
    scale = 1 if sys.platform == "darwin" else 1024
    return usage.ru_maxrss * scale / MEBIBYTE


def time_one_scan(pqscan, name):
    command = [str(pqscan), "--as-of", AS_OF_YEAR, "--format", "json", name]
    start = time.perf_counter()
    with open(os.devnull, "wb") as sink:
        process = subprocess.Popen(command, cwd=SOURCES, stdout=sink, stderr=sink)
        _, status, usage = os.wait4(process.pid, 0)
    seconds = time.perf_counter() - start
    code = os.waitstatus_to_exitcode(status)
    if code not in REPORT_EXIT_CODES:
        sys.exit(f"bench: pqscan exited {code} on {name}")
    return seconds, peak_rss_mib(usage)


def measure(pqscan, name, runs):
    """The fastest run and the largest memory peak: noise only ever adds time."""
    results = [time_one_scan(pqscan, name) for _ in range(runs)]
    return min(r[0] for r in results), max(r[1] for r in results)


def perf(args):
    targets = load_json(BENCH / "perf.json")["targets"]
    failures = []
    print("| Project | Size | Seconds | MiB/s | Peak memory | Target |")
    print("| --- | ---: | ---: | ---: | ---: | --- |")
    for project in corpus():
        name = project["name"]
        size = tree_bytes(SOURCES / name) / MEBIBYTE
        seconds, rss = measure(args.pqscan, name, args.runs)
        target = targets.get(name)
        verdict = "none"
        if target:
            limit_seconds = target["seconds"] * args.tolerance
            limit_rss = target["peak_mib"] * args.tolerance
            ok = seconds <= limit_seconds and rss <= limit_rss
            verdict = f"{'ok' if ok else 'MISSED'} (≤ {limit_seconds:g} s, ≤ {limit_rss:g} MiB)"
            if not ok:
                failures.append(name)
        print(f"| {name} | {size:.0f} MiB | {seconds:.2f} | {size / seconds:.0f} | {rss:.0f} MiB | {verdict} |")
    if args.check and failures:
        print(f"bench: over target: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pqscan", type=Path, default=DEFAULT_PQSCAN, help="the binary to measure")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fetch", help="download and unpack the corpus").set_defaults(run=fetch)
    evaluation = commands.add_parser("evaluate", help="measure precision and recall")
    evaluation.add_argument("--write", action="store_true", help="also write bench/results.md")
    evaluation.set_defaults(run=evaluate)
    timing = commands.add_parser("perf", help="measure time and memory")
    timing.add_argument("--runs", type=int, default=3, help="scans per project (default 3)")
    timing.add_argument("--check", action="store_true", help="exit 1 if a target is missed")
    timing.add_argument("--tolerance", type=float, default=1.0, help="multiply every target by this")
    timing.set_defaults(run=perf)
    args = parser.parse_args()
    args.pqscan = args.pqscan.resolve()
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
