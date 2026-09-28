#!/usr/bin/env python3
"""End-to-end secret pipeline: a file (or directory) in, classified secrets out.

This wires the detection stage (stage1) directly into the risk-classification
stage (stage2) so a reviewer can hand the artifact a raw input file and get back
the risk-labelled secrets, using the *masked* RPM knowledge base (embeddings +
labels only — no plaintext KB text).

    input file(s) ──► regex detection ──► risk classification (masked KB) ──► secrets

Stages:
  1. Load detection rules (merged_regex_v5.json) and the masked KB.
  2. Scan each input file with `scan_single_file` -> raw candidate hits.
  3. `batch_classify_risks(hits, kb)` classifies each candidate as a
     Private-by-design secret / Public-by-design secret / Non-secret noise.
     (embeds each generic/JWT candidate with Jina-v4 and matches it against the
      KB vectors; the KB only supplies a vector + a risk-level label.)
  4. Emit the secret findings (the non-secret noise is dropped by default).

Usage:
  export JINA_MODEL_DIR=/path/to/jina-embeddings-v4
  export RISK_KB_FILE=/path/to/kb_masked.jsonl     # the masked KB
  python scripts/classify_file.py INPUT [INPUT ...] --out secrets.json

INPUT may be a file or a directory (recursively scanned). Defaults:
  --regex   stage1_detect/data/regex/merged_regex_v5.json
  --out     classified_secrets.json
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
S2 = ROOT / "stage1_detect"
S4 = ROOT / "stage2_classify"
# stage1 supplies the detector (hit_git_tf + its filter/ deps); stage2 supplies
# the live classifier. Both ship a module named `risk_classifier`, so the
# classifier is loaded explicitly by path (below) to avoid name shadowing.
sys.path.insert(0, str(S2))


def _load_classifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "risk_classifier_live", str(S4 / "risk_classifier.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.batch_classify_risks

DEFAULT_REGEX = S2 / "data" / "regex" / "merged_regex_v5.json"
DEFAULT_KB = os.environ.get("RISK_KB_FILE") or str(ROOT / "data" / "kb" / "kb_masked_jina2048.jsonl")


def load_rules(regex_path):
    with open(regex_path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    import re
    for rule in rules:
        if "compiled" not in rule:
            try:
                rule["compiled"] = re.compile(rule["regex"])
            except Exception:
                rule["compiled"] = None
    return rules


def load_kb(kb_path):
    kb = []
    with open(kb_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                kb.append(json.loads(line))
    return kb


def gather_files(inputs, crawl_manifest=None):
    files = []
    for inp in inputs:
        p = Path(inp)
        if p.is_dir():
            files.extend(str(x) for x in p.rglob("*") if x.is_file())
        elif p.is_file():
            files.append(str(p))
        else:
            print(f"[warn] not found: {inp}", file=sys.stderr)
    if crawl_manifest:
        manifest_path = Path(crawl_manifest).resolve()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("format") != "keysifter-crawl-v1":
            raise ValueError("unsupported crawl manifest format")
        root = manifest_path.parent
        for item in manifest["files"]:
            path = (root / item["path"]).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise ValueError("crawl manifest refers to a missing or out-of-root file")
            files.append(str(path))
    return list(dict.fromkeys(files))


def scan_files(files, rules, timeout=30):
    from hit_git_tf import scan_single_file
    hits = []
    for fp in files:
        try:
            res = scan_single_file((rules, fp, None, timeout))
            if res:
                hits.extend(res)
        except Exception as e:
            print(f"[warn] scan failed {fp}: {e}", file=sys.stderr)
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", help="input file(s) or directory(ies)")
    ap.add_argument("--crawl-manifest", help="scan only text payloads listed by the collector")
    ap.add_argument("--regex", default=str(DEFAULT_REGEX),
                    help="detection rule JSON (default merged_regex_v5.json)")
    ap.add_argument("--kb", default=DEFAULT_KB,
                    help="KB jsonl (default $RISK_KB_FILE; use the masked KB)")
    ap.add_argument("--out", default="classified_secrets.json")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--include-fp", action="store_true",
                    help="also emit the non-secret-noise items (dropped by default)")
    args = ap.parse_args()

    if not args.inputs and not args.crawl_manifest:
        ap.error("supply input files or --crawl-manifest")
    if not args.kb:
        ap.error("no KB given: set $RISK_KB_FILE or pass --kb")

    print(f"[1/4] loading rules: {args.regex}")
    rules = load_rules(args.regex)
    print(f"      {len(rules)} rules")

    print(f"[2/4] scanning inputs")
    files = gather_files(args.inputs, args.crawl_manifest)
    print(f"      {len(files)} file(s)")
    hits = scan_files(files, rules, args.timeout)
    print(f"      {len(hits)} raw candidate hit(s)")

    print(f"[3/4] loading masked KB: {args.kb}")
    kb = load_kb(args.kb)
    print(f"      {len(kb)} KB entries")

    print(f"[4/4] risk-classifying")
    batch_classify_risks = _load_classifier()
    crit, pot, fp, unm = batch_classify_risks(hits, kb)

    # User-facing label names. The engine uses Critical/Potential/FalsePositive
    # internally; we present them by what they mean.
    LABEL = {
        "Critical": "Private-by-design secret",
        "Potential": "Public-by-design secret",
        "FalsePositive": "Non-secret noise",
    }

    def shape(rows, label):
        out = []
        for r in rows:
            it = r.get("original_item", r)
            out.append({
                "risk": LABEL[label],
                "value": it.get("whole_secret_value") or it.get("value"),
                "variable": it.get("prefix") or it.get("_var_name"),
                "rule": it.get("rule_name"),
                "file": it.get("file"),
                "line": it.get("line_start"),
                "reason": r.get("reason"),
                "score": r.get("score"),
            })
        return out

    result = {
        "summary": {
            "files": len(files),
            "raw_hits": len(hits),
            LABEL["Critical"]: len(crit),
            LABEL["Potential"]: len(pot),
            LABEL["FalsePositive"]: len(fp),
            "Unmatched": len(unm),
        },
        "secrets": shape(crit, "Critical") + shape(pot, "Potential")
                   + (shape(fp, "FalsePositive") if args.include_fp else []),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    s = result["summary"]
    print(f"\n==> {args.out}")
    print(f"    {LABEL['Critical']}={len(crit)}  "
          f"{LABEL['Potential']}={len(pot)}  "
          f"{LABEL['FalsePositive']}={len(fp)}  (from {s['raw_hits']} raw hits)")


if __name__ == "__main__":
    main()
