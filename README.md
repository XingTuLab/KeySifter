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

This repository contains the KeySifter source code and a small set of test data. For security and privacy, the bundled knowledge base is masked and contains only embedding vectors and risk labels; no plaintext secrets are included.

See **[USAGE.md](USAGE.md)** to collect an authorized URL or run the pipeline on
your own file. Crawler-specific details are in
**[stage0_collect/README.md](stage0_collect/README.md)**.

## License

This project is licensed under the GNU General Public License v2.0. See [LICENSE](LICENSE).
