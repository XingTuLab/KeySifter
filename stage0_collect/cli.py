"""Run the bundled crawler on explicitly supplied URLs."""
from __future__ import annotations

import argparse
import asyncio
import codecs
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
PRESETS = {
    "coverage": dict(max_crawl_depth=3, max_pages=120, concurrency=10,
                     probe_mode="full", probe_concurrency=20,
                     fetch_timeout_ms=8000, networkidle_short_ms=2000,
                     networkidle_long_ms=3000, sw_wait_seconds=3.0),
    "measurement": dict(max_crawl_depth=2, max_pages=30, concurrency=20,
                        probe_mode="balanced", probe_concurrency=20,
                        fetch_timeout_ms=6000, networkidle_short_ms=1500,
                        networkidle_long_ms=2000, sw_wait_seconds=1.0),
    "fast": dict(max_crawl_depth=1, max_pages=15, concurrency=25,
                 probe_mode="lite", probe_concurrency=30,
                 fetch_timeout_ms=5000, networkidle_short_ms=1000,
                 networkidle_long_ms=1500, sw_wait_seconds=0.5,
                 nonstatic_wait_until="domcontentloaded"),
}


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def depth_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("depth must be at least 0")
    return number


def normalize_url(value):
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("targets must be explicit http:// or https:// URLs")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL credentials are not supported by this anonymous collector")
    _ = parts.port  # Validate the port before launching a browser.
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def target_directory(url):
    parts = urlsplit(url)
    host = "".join(c if c.isalnum() or c in ".-_" else "_" for c in parts.netloc)
    return host + "_" + hashlib.sha256(url.encode()).hexdigest()[:12]


def scan_payloads(output_root, target_root, resources):
    """Select downloaded text bodies, excluding metadata and screenshot artifacts."""
    root = output_root.resolve()
    target = target_root.resolve()
    files = []
    seen = set()
    for resource in resources:
        saved = resource.get("saved_path")
        if not saved or resource.get("is_soft_404"):
            continue
        path = Path(saved).resolve()
        if not path.is_relative_to(target) or not path.is_file():
            continue
        if path in seen:
            continue
        with path.open("rb") as handle:
            prefix = handle.read(8192)
        # The downstream rule detector consumes text. Retain UTF-8 text and
        # reject common binary payloads even if their server MIME is incorrect.
        if b"\x00" in prefix:
            continue
        try:
            # Incremental decoding accepts a prefix ending inside a valid
            # multibyte character while still rejecting malformed UTF-8.
            codecs.getincrementaldecoder("utf-8-sig")().decode(prefix, final=False)
        except UnicodeDecodeError:
            continue
        seen.add(path)
        files.append({"path": path.relative_to(root).as_posix(),
                      "url": resource.get("url"),
                      "method": resource.get("method"),
                      "content_type": resource.get("content_type"),
                      "bytes": path.stat().st_size})
    return files


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("urls", nargs="*", help="one or more explicit target URLs")
    ap.add_argument("--urls-file", type=Path, help="UTF-8 file, one URL per line; # comments allowed")
    ap.add_argument("--out", type=Path, required=True, help="new or empty output directory")
    ap.add_argument("--preset", choices=PRESETS, default="coverage")
    ap.add_argument("--workers", type=positive_int, default=1, help="simultaneous target sites")
    ap.add_argument("--max-pages", type=positive_int)
    ap.add_argument("--max-depth", type=depth_int, help="zero-based BFS depth; the landing page is 0")
    ap.add_argument("--concurrency", type=positive_int, help="browser pages per target")
    ap.add_argument("--probe-mode", choices=["lite", "balanced", "full"])
    ap.add_argument("--probe-concurrency", type=positive_int)
    ap.add_argument("--fetch-timeout-ms", type=positive_int)
    ap.add_argument("--networkidle-short-ms", type=positive_int)
    ap.add_argument("--networkidle-long-ms", type=positive_int)
    ap.add_argument("--target-timeout", type=positive_int, default=600, help="seconds per target")
    for feature in ("screenshot", "legacy-ua", "404-probe", "service-worker-probe"):
        ap.add_argument("--skip-" + feature, action="store_true")
    ap.add_argument("--classify", action="store_true", help="run the existing detection/classification pipeline afterward")
    ap.add_argument("--kb", type=Path, help="masked KB override for --classify")
    ap.add_argument("--regex", type=Path, help="detection rules override for --classify")
    ap.add_argument("--include-fp", action="store_true", help="include non-secret noise in classification output")
    return ap


async def collect(urls, output, config, workers, target_timeout):
    from .scraper import ResourceScraper

    semaphore = asyncio.Semaphore(workers)

    async def one(url):
        async with semaphore:
            destination = output / target_directory(url)
            scraper = ResourceScraper(output_dir=str(destination), **config)
            result = {"url": url, "directory": destination.name, "status": "ok"}
            try:
                await asyncio.wait_for(scraper.scrape(url), timeout=target_timeout)
            except asyncio.TimeoutError:
                result.update(status="timeout", error="target time budget exceeded")
            except Exception as exc:
                result.update(status="error", error=str(exc))
            files = scan_payloads(output, destination, scraper.resources)
            if result["status"] == "ok" and not files:
                result.update(status="empty", error="no analyzable text responses were collected")
            result.update(scan_files=len(files), recorded_responses=len(scraper.resources))
            return result, files

    results = await asyncio.gather(*(one(url) for url in urls))
    return [r for r, _ in results], [f for _, files in results for f in files]


def main(argv=None):
    ap = parser()
    args = ap.parse_args(argv)
    urls = list(args.urls)
    if args.urls_file:
        try:
            urls.extend(line.strip() for line in args.urls_file.read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            ap.error(str(exc))
    try:
        urls = list(dict.fromkeys(normalize_url(url) for url in urls))
    except ValueError as exc:
        ap.error(str(exc))
    if not urls:
        ap.error("supply at least one URL or --urls-file")
    output = args.out.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        ap.error("--out must be new or empty; use a fresh directory for each run")
    try:
        import playwright.async_api  # Fail before creating a run directory.
    except ImportError:
        ap.error("install playwright and its browser: pip install playwright; playwright install chromium")
    config = dict(PRESETS[args.preset])
    overrides = {"max_depth": "max_crawl_depth", "max_pages": "max_pages",
                 "concurrency": "concurrency", "probe_mode": "probe_mode",
                 "probe_concurrency": "probe_concurrency", "fetch_timeout_ms": "fetch_timeout_ms",
                 "networkidle_short_ms": "networkidle_short_ms", "networkidle_long_ms": "networkidle_long_ms"}
    for argument, setting in overrides.items():
        value = getattr(args, argument)
        if value is not None:
            config[setting] = value
    for feature in ("screenshot", "legacy_ua", "404_probe", "service_worker_probe"):
        config["enable_" + feature] = not getattr(args, "skip_" + feature)
    output.mkdir(parents=True, exist_ok=True)
    run_config = {"started_at": datetime.now(timezone.utc).isoformat(), "preset": args.preset,
                  "urls": urls, "workers": args.workers, "target_timeout_seconds": args.target_timeout,
                  "crawler": config}
    (output / "run_config.json").write_text(json.dumps(run_config, indent=2), encoding="utf-8")
    targets, files = asyncio.run(collect(urls, output, config, args.workers, args.target_timeout))
    manifest = {"format": "keysifter-crawl-v1", "targets": targets, "files": files}
    manifest_path = output / "scan_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCollection: {len(files)} text files from {len(targets)} target(s)")
    print(f"Scan manifest: {manifest_path}")
    if args.classify and files:
        cmd = [sys.executable, str(ROOT / "scripts" / "classify_file.py"),
               "--crawl-manifest", str(manifest_path), "--out", str(output / "classified_secrets.json")]
        if args.kb:
            cmd.extend(["--kb", str(args.kb.resolve())])
        if args.regex:
            cmd.extend(["--regex", str(args.regex.resolve())])
        if args.include_fp:
            cmd.append("--include-fp")
        result = subprocess.run(cmd, check=False)
        if result.returncode:
            return result.returncode
    if any(target["status"] != "ok" for target in targets):
        print("Some targets failed or were empty; inspect scan_manifest.json.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
