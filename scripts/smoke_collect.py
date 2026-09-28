#!/usr/bin/env python3
"""Run the collector against a temporary synthetic loopback site."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "data" / "sample" / "site"


class FixtureHandler(BaseHTTPRequestHandler):
    post_seen = threading.Event()

    def log_message(self, _format, *_args):
        return

    def _send(self, status, content_type, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            user_agent = self.headers.get("user-agent", "")
            if "Trident/7.0" in user_agent:
                body = "<!doctype html><script src='/legacy/bundle.js'></script>"
                return self._send(200, "text/html; charset=utf-8", body)
            return self._send(200, "text/html; charset=utf-8",
                              (SITE / "index.html").read_bytes())
        static = {
            "/app.js": ("application/javascript; charset=utf-8", "app.js"),
            "/app.js.map": ("application/json; charset=utf-8", "app.js.map"),
            "/nested.html": ("text/html; charset=utf-8", "nested.html"),
        }
        if path in static:
            content_type, name = static[path]
            return self._send(200, content_type, (SITE / name).read_bytes())
        if path == "/.env":
            return self._send(200, "text/plain; charset=utf-8", "DEMO_MODE=true\n")
        if path == "/api/runtime":
            return self._send(200, "application/json; charset=utf-8",
                              json.dumps({"fixture": True, "mode": "loopback"}))
        if path == "/legacy/bundle.js":
            return self._send(200, "application/javascript; charset=utf-8",
                              "window.legacyFixture = true;")
        return self._send(404, "text/plain; charset=utf-8", "not found\n")

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("content-length", "0"))
        self.rfile.read(length)
        if path == "/browser-event":
            self.post_seen.set()
            return self._send(200, "application/json; charset=utf-8",
                              json.dumps({"accepted": True}))
        return self._send(404, "text/plain; charset=utf-8", "not found\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classify", action="store_true",
                        help="also run detection and risk classification")
    args = parser.parse_args(argv)

    FixtureHandler.post_seen.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}/"

    try:
        with tempfile.TemporaryDirectory(prefix="keysifter-smoke-") as tmp:
            output = Path(tmp) / "crawl"
            cmd = [
                sys.executable, str(ROOT / "scripts" / "collect_url.py"), base_url,
                "--out", str(output), "--preset", "coverage",
                "--max-pages", "6", "--max-depth", "2",
                "--concurrency", "2", "--probe-concurrency", "8",
                "--fetch-timeout-ms", "1500",
                "--networkidle-short-ms", "300",
                "--networkidle-long-ms", "300",
                "--target-timeout", "90", "--skip-screenshot",
            ]
            if args.classify:
                cmd.append("--classify")
            env = dict(os.environ)
            result = subprocess.run(cmd, cwd=ROOT, env=env, text=True)
            if result.returncode:
                raise SystemExit(f"collector exited with status {result.returncode}")

            manifest_path = output / "scan_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            paths = {urlsplit(item.get("url") or "").path for item in manifest["files"]}
            expected = {
                "/", "/app.js", "/app.js.map", "/nested.html",
                "/.env", "/api/runtime", "/legacy/bundle.js",
            }
            missing = sorted(expected - paths)
            if missing:
                raise SystemExit(f"smoke manifest is missing: {', '.join(missing)}")
            if not FixtureHandler.post_seen.is_set():
                raise SystemExit("synthetic browser POST was not observed")

            if args.classify:
                classified = json.loads(
                    (output / "classified_secrets.json").read_text(encoding="utf-8"))
                summary = classified["summary"]
                if summary["files"] != len(manifest["files"]):
                    raise SystemExit("classifier file count does not match crawl manifest")
                if summary["raw_hits"] < 1:
                    raise SystemExit("synthetic token did not reach detection")

            print(f"smoke test passed: {len(manifest['files'])} text responses")
            print("validated browser GET/POST capture, probes, source map, and legacy replay")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
