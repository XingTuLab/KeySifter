import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.classify_file import gather_files
from stage0_collect.cli import normalize_url, scan_payloads, target_directory


class UrlTests(unittest.TestCase):
    def test_rejects_invalid_and_credential_urls(self):
        for value in ("ftp://example.test/a", "example.test",
                      "https://user:pass@example.test/", "https://example.test:bad/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_target_directory_distinguishes_paths(self):
        first = target_directory("https://example.test/a")
        second = target_directory("https://example.test/b")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("example.test_"))


class ManifestTests(unittest.TestCase):
    def test_scan_manifest_filters_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            text_file = target / "body.js"
            text_file.write_text("const token = 'synthetic';", encoding="utf-8")
            binary_file = target / "blob.bin"
            binary_file.write_bytes(b"abc\x00def")
            soft_file = target / "soft.html"
            soft_file.write_text("soft", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            resources = [
                {"saved_path": str(text_file), "url": "https://example.test/body.js"},
                {"saved_path": str(text_file), "url": "https://example.test/body.js"},
                {"saved_path": str(binary_file), "url": "https://example.test/blob.bin"},
                {"saved_path": str(soft_file), "is_soft_404": True},
                {"saved_path": str(outside), "url": "https://example.test/outside.txt"},
            ]
            files = scan_payloads(root, target, resources)
            self.assertEqual(["target/body.js"], [item["path"] for item in files])

    def test_multibyte_character_at_prefix_boundary_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            body = target / "boundary.txt"
            body.write_bytes((b"a" * 8191) + "é".encode("utf-8") + b"tail")
            files = scan_payloads(root, target, [{"saved_path": str(body)}])
            self.assertEqual(1, len(files))

    def test_classifier_reads_only_manifest_listed_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = root / "body.js"
            metadata = root / "body.js.meta.json"
            body.write_text("const token = 'synthetic';", encoding="utf-8")
            metadata.write_text("{}", encoding="utf-8")
            manifest = root / "scan_manifest.json"
            manifest.write_text(json.dumps({
                "format": "keysifter-crawl-v1",
                "targets": [],
                "files": [{"path": "body.js"}],
            }), encoding="utf-8")
            self.assertEqual([str(body)], gather_files([], manifest))

    def test_classifier_rejects_manifest_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crawl = root / "crawl"
            crawl.mkdir()
            outside = root / "outside.js"
            outside.write_text("outside", encoding="utf-8")
            manifest = crawl / "scan_manifest.json"
            manifest.write_text(json.dumps({
                "format": "keysifter-crawl-v1",
                "targets": [],
                "files": [{"path": "../outside.js"}],
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                gather_files([], manifest)


if __name__ == "__main__":
    unittest.main()
