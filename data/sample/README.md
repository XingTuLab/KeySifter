# Sample data

This directory contains two different kinds of offline test material:

- **sample_page.html** and **site/** are synthetic fixtures created for the quickstart and crawler smoke test. Their planted values are non-functional and do not authenticate against any real service.
- **detection_output_sample1000.json** is the 1,000-record Stage 1 output snapshot shipped in the original anonymous KeySifter artifact. It is preserved byte-for-byte for offline Stage 2 experiments. File paths are anonymized as **corpus/example...**; candidate strings must not be used to authenticate to or probe any service.

The output snapshot contains 1,000 candidate records across 881 anonymized files. It is input-shaped data for testing classification behavior, not a collection corpus and not a list of validated credentials.

## Expected fixture behavior

The current sample_page.html produces eight Stage 1 candidates. The cf_header_name entry is a negative control and is intentionally not detected. Before semantic matching, deterministic heuristics classify two candidates as Private-by-design, one as Public-by-design, and two as Non-secret noise; three candidates are intentionally left for Jina-v4 semantic matching.
