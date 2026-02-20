#!/usr/bin/env python3
"""
Build vanity-friendly wordlists for zerotier-idtool prefix files.

The script merges one or more dictionary files, keeps words in plain alphabetic
form (no leet conversion in output), and writes:
  - hexleet_words_3.txt
  - hexleet_words_4.txt
  - hexleet_words_5.txt

Compatibility check:
  Words must consist only of letters accepted by idtool vanity normalization:
  A B C D E F G I O S T Z (case-insensitive)

Optional Datamuse mode can fetch complete length-specific word sets by
recursively querying sp=prefix+wildcards until result sets are below
Datamuse's max response size.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set


TOKEN_RE = re.compile(r"[A-Za-z]+")
ALLOWED_ALPHA = set("abcdefgiostz")
DATAMUSE_API = "https://api.datamuse.com/words"
DATAMUSE_MAX = 1000
DATAMUSE_ALPHA = "abcdefghijklmnopqrstuvwxyz"


@dataclass
class Stats:
    files_read: int = 0
    tokens_seen: int = 0
    tokens_by_len: Dict[int, int] = None
    invalid_chars: int = 0
    accepted: int = 0
    deduped: int = 0
    datamuse_queries: int = 0
    datamuse_words: int = 0
    datamuse_cache_hits: int = 0

    def __post_init__(self) -> None:
        if self.tokens_by_len is None:
            self.tokens_by_len = defaultdict(int)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build 3/4/5-char hexleet vanity wordlists from dictionaries."
    )
    p.add_argument(
        "inputs",
        nargs="*",
        help="Input dictionary files. Supports plain text and Hunspell .dic files.",
    )
    p.add_argument(
        "--datamuse-complete",
        action="store_true",
        help="Fetch complete word sets from Datamuse for requested lengths.",
    )
    p.add_argument(
        "--datamuse-cache",
        default="",
        help="Optional path to save fetched Datamuse words (one per line).",
    )
    p.add_argument(
        "--datamuse-query-cache",
        default="",
        help="Path to persistent Datamuse query cache (JSONL). In auto mode defaults to <out-dir>/datamuse_query_cache.jsonl.",
    )
    p.add_argument(
        "--datamuse-timeout",
        type=float,
        default=5.0,
        help="HTTP timeout for Datamuse requests in seconds (default: 5).",
    )
    p.add_argument(
        "--datamuse-verbose",
        action="store_true",
        help="Print Datamuse fetch progress.",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="Allow output when Datamuse fetch fails (default in auto mode is strict).",
    )
    p.add_argument(
        "--progress-interval",
        type=float,
        default=5.0,
        help="Emit progress updates every N seconds (default: 5).",
    )
    p.add_argument(
        "--out-dir",
        default=".",
        help="Output directory for hexleet_words_{3,4,5}.txt (default: current dir).",
    )
    p.add_argument(
        "--lengths",
        default="3,4,5",
        help="Comma-separated target lengths (default: 3,4,5).",
    )
    p.add_argument(
        "--prefix",
        default="hexleet_words",
        help="Output filename prefix (default: hexleet_words).",
    )
    return p.parse_args()


def iter_tokens_from_line(line: str) -> Iterable[str]:
    for m in TOKEN_RE.finditer(line):
        yield m.group(0)


def iter_tokens(path: pathlib.Path) -> Iterable[str]:
    # Hunspell dictionaries commonly start with a count and then forms
    # like "word/FLAGS". For these, keep only the base form before '/'.
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        first = True
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if first and path.suffix.lower() == ".dic" and line.isdigit():
                first = False
                continue
            first = False
            if path.suffix.lower() == ".dic":
                line = line.split("/", 1)[0]
            for tok in iter_tokens_from_line(line):
                yield tok


def normalize_word(word: str) -> str | None:
    w = word.lower()
    if all(ch in ALLOWED_ALPHA for ch in w):
        return w
    return None


def discover_default_sources() -> List[str]:
    candidates = [
        "/usr/share/dict/american-english",
        "/usr/share/dict/words",
        "/usr/share/dict/cracklib-small",
        "/usr/share/hunspell/en_US.dic",
    ]
    out: List[str] = []
    seen_path: Set[str] = set()
    seen_inode: Set[tuple[int, int]] = set()
    for c in candidates:
        p = pathlib.Path(c).expanduser()
        ps = str(p)
        if ps in seen_path:
            continue
        seen_path.add(ps)
        if not p.exists():
            continue
        try:
            st = p.stat()  # follows symlinks
            inode_key = (st.st_dev, st.st_ino)
        except OSError:
            out.append(ps)
            continue
        if inode_key in seen_inode:
            continue
        seen_inode.add(inode_key)
        out.append(ps)
    return out


def datamuse_query(pattern: str, timeout_s: float) -> List[str]:
    params = urllib.parse.urlencode({"sp": pattern, "max": str(DATAMUSE_MAX)})
    url = f"{DATAMUSE_API}?{params}"
    with urllib.request.urlopen(url, timeout=timeout_s) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    out: List[str] = []
    for item in data:
        w = item.get("word", "")
        if isinstance(w, str) and w:
            out.append(w)
    return out


class DatamuseQueryCache:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self._by_pattern: Dict[str, List[str]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                pattern = row.get("pattern")
                words = row.get("words")
                if isinstance(pattern, str) and isinstance(words, list):
                    cleaned: List[str] = []
                    for w in words:
                        if isinstance(w, str):
                            cleaned.append(w)
                    self._by_pattern[pattern] = cleaned

    def get(self, pattern: str) -> Optional[List[str]]:
        return self._by_pattern.get(pattern)

    def put(self, pattern: str, words: List[str]) -> None:
        self._by_pattern[pattern] = words
        self.path.parent.mkdir(parents=True, exist_ok=True)
        row = {"pattern": pattern, "words": words}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")


def fetch_complete_datamuse_words_for_length(
    length: int,
    timeout_s: float,
    verbose: bool,
    stats: Stats,
    progress_interval_s: float,
    query_cache: Optional[DatamuseQueryCache],
) -> tuple[Set[str], bool]:
    # Start broad, then split into narrower prefixes whenever a result set
    # is saturated at DATAMUSE_MAX (likely truncated).
    queue: List[str] = [""]
    out: Set[str] = set()
    saturated_leaves = 0
    last_progress = time.monotonic()
    failed = False

    while queue:
        now = time.monotonic()
        if (progress_interval_s > 0.0) and ((now - last_progress) >= progress_interval_s):
            print(
                "progress: "
                f"phase=datamuse length={length} queue={len(queue)} "
                f"words_collected={len(out)} queries={stats.datamuse_queries}",
                file=sys.stderr,
            )
            last_progress = now

        prefix = queue.pop()
        pattern = prefix + ("?" * (length - len(prefix)))
        cached_words: Optional[List[str]] = None
        if query_cache is not None:
            cached_words = query_cache.get(pattern)
        if cached_words is not None:
            words = cached_words
            stats.datamuse_cache_hits += 1
            if verbose:
                print(f"datamuse: cache hit pattern {pattern} ({len(words)})", file=sys.stderr)
        else:
            if verbose:
                print(f"datamuse: requesting pattern {pattern}", file=sys.stderr)
            try:
                words = datamuse_query(pattern, timeout_s)
            except (urllib.error.URLError, TimeoutError) as exc:
                print(f"warning: datamuse request failed for pattern '{pattern}': {exc}", file=sys.stderr)
                failed = True
                break
            stats.datamuse_queries += 1
            if query_cache is not None:
                query_cache.put(pattern, words)

        if verbose:
            print(
                f"datamuse: len={length} pattern={pattern} got={len(words)}",
                file=sys.stderr,
            )

        if len(words) >= DATAMUSE_MAX and len(prefix) < length:
            for ch in DATAMUSE_ALPHA:
                queue.append(prefix + ch)
            continue

        if len(words) >= DATAMUSE_MAX and len(prefix) == length:
            # Should not happen for exact words, but guard anyway.
            saturated_leaves += 1

        for w in words:
            wlow = w.lower()
            if wlow.isalpha() and len(wlow) == length:
                out.add(wlow)

    if saturated_leaves > 0:
        print(
            f"warning: datamuse had {saturated_leaves} saturated leaf query(s) "
            f"at length {length}; results may still be incomplete",
            file=sys.stderr,
        )
    return out, failed


def main() -> int:
    args = parse_args()
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        lengths = sorted({int(x) for x in args.lengths.split(",") if x.strip()})
    except ValueError:
        print("error: --lengths must be comma-separated integers", file=sys.stderr)
        return 1
    if not lengths:
        print("error: no target lengths provided", file=sys.stderr)
        return 1

    words_by_len: Dict[int, Set[str]] = {n: set() for n in lengths}
    length_set = set(lengths)
    stats = Stats()
    source_words: Dict[str, Set[str]] = {}
    source_order: List[str] = []

    def ingest_source_tokens(source_name: str, tokens: Iterable[str]) -> None:
        if source_name not in source_words:
            source_words[source_name] = set()
            source_order.append(source_name)
        dst = source_words[source_name]
        for tok in tokens:
            stats.tokens_seen += 1
            n = len(tok)
            if n not in length_set:
                continue
            stats.tokens_by_len[n] += 1
            normalized = normalize_word(tok)
            if normalized is None:
                stats.invalid_chars += 1
                continue
            dst.add(normalized)

    auto_mode = (len(args.inputs) == 0) and (not args.datamuse_complete)
    source_files = list(args.inputs)
    if auto_mode:
        source_files = discover_default_sources()
        print(
            f"auto mode: discovered {len(source_files)} local source file(s)",
            file=sys.stderr,
        )
        for s in source_files:
            print(f"auto mode: source {s}", file=sys.stderr)

    datamuse_enabled = args.datamuse_complete or auto_mode
    datamuse_failed = False
    if datamuse_enabled:
        print("phase: datamuse fetch (best effort)", file=sys.stderr)
        all_dm_words: Set[str] = set()
        query_cache_path = args.datamuse_query_cache
        if (not query_cache_path) and auto_mode:
            query_cache_path = str((out_dir / "datamuse_query_cache.jsonl"))
        query_cache: Optional[DatamuseQueryCache] = None
        if query_cache_path:
            query_cache = DatamuseQueryCache(pathlib.Path(query_cache_path).expanduser())
            print(f"phase: datamuse query-cache {query_cache.path}", file=sys.stderr)
        for n in lengths:
            print(f"phase: datamuse length={n} start", file=sys.stderr)
            dm_words, failed = fetch_complete_datamuse_words_for_length(
                n,
                args.datamuse_timeout,
                args.datamuse_verbose,
                stats,
                args.progress_interval,
                query_cache,
            )
            all_dm_words.update(dm_words)
            print(
                f"phase: datamuse length={n} done unique_words={len(dm_words)}",
                file=sys.stderr,
            )
            if failed:
                datamuse_failed = True
                break
        stats.datamuse_words = len(all_dm_words)
        print(f"phase: datamuse complete words={len(all_dm_words)}", file=sys.stderr)
        if all_dm_words:
            ingest_source_tokens("datamuse", all_dm_words)
        if args.datamuse_cache:
            cache_path = pathlib.Path(args.datamuse_cache).expanduser()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with cache_path.open("w", encoding="utf-8") as f:
                for w in sorted(all_dm_words):
                    f.write(w + "\n")
            if args.datamuse_verbose:
                print(
                    f"datamuse: wrote cache {cache_path} ({len(all_dm_words)} words)",
                    file=sys.stderr,
                )

    for src in source_files:
        path = pathlib.Path(src).expanduser()
        if not path.exists():
            print(f"warning: input file not found, skipping: {path}", file=sys.stderr)
            continue
        stats.files_read += 1
        source_name = str(path)
        print(f"phase: ingest source start {source_name}", file=sys.stderr)
        if source_name not in source_words:
            source_words[source_name] = set()
            source_order.append(source_name)
        dst = source_words[source_name]
        last_progress = time.monotonic()
        for tok in iter_tokens(path):
            stats.tokens_seen += 1
            n = len(tok)
            if n not in length_set:
                continue
            stats.tokens_by_len[n] += 1
            normalized = normalize_word(tok)
            if normalized is None:
                stats.invalid_chars += 1
            else:
                dst.add(normalized)
            now = time.monotonic()
            if (args.progress_interval > 0.0) and ((now - last_progress) >= args.progress_interval):
                print(
                    "progress: "
                    f"phase=ingest source={source_name} tokens_seen={stats.tokens_seen} "
                    f"source_kept={len(dst)}",
                    file=sys.stderr,
                )
                last_progress = now
        print(
            f"phase: ingest source done {source_name} kept={len(dst)}",
            file=sys.stderr,
        )

    total_source_valid = 0
    for src in source_order:
        sset = source_words[src]
        total_source_valid += len(sset)
        for w in sset:
            words_by_len[len(w)].add(w)
    stats.accepted = sum(len(words_by_len[n]) for n in lengths)
    stats.deduped = total_source_valid - stats.accepted

    if auto_mode and datamuse_failed and (not args.allow_partial):
        print(
            "error: datamuse fetch failed in auto mode; refusing partial output. "
            "re-run with --allow-partial to use local sources only.",
            file=sys.stderr,
        )
        return 2

    if stats.files_read == 0 and (stats.accepted == 0) and (len(source_order) == 0):
        print("error: no usable word sources were available", file=sys.stderr)
        return 1

    for n in lengths:
        out_path = out_dir / f"{args.prefix}_{n}.txt"
        with out_path.open("w", encoding="utf-8") as f:
            for w in sorted(words_by_len[n]):
                f.write(w + "\n")
        print(f"{out_path}: {len(words_by_len[n])} entries")

    print(
        "summary: "
        f"files_read={stats.files_read} "
        f"tokens_seen={stats.tokens_seen} "
        f"accepted={stats.accepted} "
        f"invalid_chars={stats.invalid_chars} "
        f"deduped={stats.deduped} "
        f"datamuse_queries={stats.datamuse_queries} "
        f"datamuse_words={stats.datamuse_words} "
        f"datamuse_cache_hits={stats.datamuse_cache_hits}"
    )
    for n in lengths:
        print(f"summary_len_{n}: candidates={stats.tokens_by_len[n]} kept={len(words_by_len[n])}")
    if source_order:
        word_freq: Dict[str, int] = defaultdict(int)
        for src in source_order:
            for w in source_words[src]:
                word_freq[w] += 1
        for src in source_order:
            sset = source_words[src]
            unique = sum(1 for w in sset if word_freq[w] == 1)
            shared = len(sset) - unique
            print(f"source_summary: {src} kept={len(sset)} unique={unique} shared={shared}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted: stopped by user", file=sys.stderr)
        raise SystemExit(130)
