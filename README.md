# KeySifter

Code for a measurement study of secret/credential leakage on the public web.
The pipeline scans web assets that an anonymous visitor already receives,
detects candidate credentials, and classifies each by real-world risk.

It has three stages:

1. **Collection** (`stage0_collect/`) — the preserved browser-based measurement
   crawler plus a bounded CLI. It captures resources an anonymous browser receives,
   follows same-site discovery paths, expands static assets and source maps, and
   emits an auditable manifest of text bodies for scanning.
2. **Detection** (`stage1_detect/`) — a rule-based scan (service-specific and
   generic key-name patterns) with entropy/format filtering, plus an
   `acorn`-based AST pass (`stage1_detect/ast/`) that recovers credential-bearing
   identifiers minification would otherwise hide.
3. **Risk classification** (`stage2_classify/`) — heuristic triage plus a
   Jina-v4 semantic match against a frozen Risk-Pattern Memory, labelling each
   candidate as a **Private-by-design secret** (a real server-side credential),
   a **Public-by-design secret** (a key meant to ship to clients but still
   abusable), or **Non-secret noise**.

The interesting result is the funnel: millions of raw candidate hits collapse
to a few hundred genuine private-by-design secrets.

## What's here

This is a code + minimal-data artifact. It ships the pipeline source, a small
synthetic input/site, and a **masked** knowledge base (embedding vectors + risk
labels only — no plaintext) that is enough to run the classification. Release
archives compress this knowledge base to reduce download size. The full crawl
corpus, real target lists, original plaintext knowledge base, and private
validation modules are not included. The synthetic fixtures in data/sample/sample_page.html and data/sample/site/ are non-functional and do not authenticate against any real service. The bundled Stage 1 output snapshot uses anonymized paths and is intended only for offline classifier evaluation; see data/sample/README.md.

See **[USAGE.md](USAGE.md)** to collect an authorized URL or run the pipeline on
your own file. Crawler-specific details are in
**[stage0_collect/README.md](stage0_collect/README.md)**.

## License

This project is licensed under the GNU General Public License v2.0. See [LICENSE](LICENSE).
