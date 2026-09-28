# Usage

KeySifter can scan a local file directly or collect browser-visible assets from
an explicitly supplied, authorized URL before detection and risk classification.

## 1. Install

Python 3.10 is recommended. Either conda or pip can install the Python
dependencies:

~~~bash
conda env create -f environment.yml
conda activate web-secret-ae
# or: python3.10 -m venv .venv
#     source .venv/bin/activate
#     pip install -r requirements.txt
~~~

Install the Chromium build used by Playwright when running the collector:

~~~bash
python -m playwright install chromium
~~~

Collection alone does not need a GPU or embedding model. Risk classification
uses `jinaai/jina-embeddings-v4`; download it once and point KeySifter at the
local directory:

~~~bash
huggingface-cli download jinaai/jina-embeddings-v4 --local-dir ./models/jina-embeddings-v4
export JINA_MODEL_DIR=$PWD/models/jina-embeddings-v4
~~~

The masked risk-pattern knowledge base is bundled at
`data/kb/kb_masked_jina2048.jsonl`. A GPU is recommended for large
classification jobs, but CPU works for small inputs.

## 2. Collect an authorized URL

The output directory must be new or empty. The default `coverage` preset favors
resource discovery.

~~~bash
python scripts/collect_url.py https://example.test/ --out crawl_output/example
~~~

Run collection and the existing detector/classifier in one command:

~~~bash
export JINA_MODEL_DIR=/path/to/jina-embeddings-v4
python scripts/collect_url.py https://example.test/ --out crawl_output/example --classify
~~~

Useful bounded variants:

~~~bash
# Historical bounded measurement-driver profile: depth 2 visits levels 0, 1, and 2.
python scripts/collect_url.py https://example.test/ --out crawl_output/measurement --preset measurement

# Quick check with explicit limits.
python scripts/collect_url.py https://example.test/ --out crawl_output/fast \
  --preset fast --max-pages 10 --max-depth 1

# Multiple explicit targets, with at most two sites active at once.
python scripts/collect_url.py --urls-file targets.txt --out crawl_output/batch --workers 2
~~~

`targets.txt` contains one full HTTP(S) URL per line; blank lines and lines
beginning with `#` are ignored. The collector does not accept credentials in a
URL. Use only targets you are authorized to assess.

Every run writes:

- `run_config.json`: normalized targets and effective crawler settings.
- one target directory containing the crawler's detailed responses and metadata.
- `scan_manifest.json`: only collected UTF-8 text bodies eligible for scanning.
- `classified_secrets.json`: present when `--classify` succeeds.

The manifest excludes binary files, soft-404 bodies, duplicate saved paths,
screenshots, logs, and collector metadata. To classify a completed crawl later:

~~~bash
python scripts/classify_file.py --crawl-manifest crawl_output/example/scan_manifest.json \
  --out crawl_output/example/classified_secrets.json
~~~

See `python scripts/collect_url.py --help` for page, depth, concurrency, timeout,
probe-mode, and optional-feature overrides.

## 3. Scan local files

Files and directories remain supported independently of the crawler:

~~~bash
export JINA_MODEL_DIR=/path/to/jina-embeddings-v4
python scripts/classify_file.py data/sample/sample_page.html --out secrets.json
python scripts/classify_file.py path/to/directory --out secrets.json
~~~

The output summary reports raw hits and the three user-facing risk labels:
`Private-by-design secret`, `Public-by-design secret`, and `Non-secret noise`.
The `secrets` array contains private- and public-by-design findings by default;
pass `--include-fp` to retain non-secret noise as well. Each result includes its
source file and line when available.

## 4. Offline smoke test

The repository includes a synthetic loopback site. This command starts a
temporary server on `127.0.0.1`, runs the collector, validates the expected
resource families, and then removes the temporary crawl output:

~~~bash
python scripts/smoke_collect.py
~~~

Add `--classify` to exercise the full handoff when the local Jina model is
configured. The synthetic values are non-functional and do not authenticate
against any service.

## Responsible use

This artifact is for files and systems you are authorized to scan. Do not use
discovered credentials, attempt authentication, or target people or organizations
outside a sanctioned measurement or security assessment.
