# Collection stage

`stage0_collect/scraper.py` is the preserved measurement crawler selected from the
available KeySifter implementations. Its SHA-256 is
`f345294407033dd52576f54b3a7325d63b1e6ef49d790755be160bac92e32073`. The
collector wrapper adds explicit inputs, reproducible presets, isolated output
directories, and a scan manifest; it does not change the crawler algorithm.

The crawler records browser-visible responses while exploring the landing page,
same-site links, sitemaps, JavaScript and CSS dependencies, source maps, web
manifests, service-worker behavior, legacy-UA responses, common public paths, and
404-derived paths. Browser actions may naturally produce GET or POST traffic.
The crawler's own explicit resource and dictionary probes use GET. It does not
authenticate, submit discovered credentials, or test whether a credential works.

## Presets

| Preset | BFS depth | Page budget | Probe set | Intended use |
| --- | ---: | ---: | --- | --- |
| `coverage` | 3 | 120 | full | published depth/page settings and broad coverage |
| `measurement` | 2 | 30 | balanced | historical bounded driver profile |
| `fast` | 1 | 15 | lite | quick validation |

Depth is zero-based: the supplied landing page is depth 0, so depth 2 covers
three ordinary BFS levels (0, 1, and 2). The page budget applies to the ordinary
BFS queue. Resource expansion and the optional probe families can add requests
beyond that count.

## Run

~~~bash
python -m playwright install chromium
python scripts/collect_url.py https://example.test/ --out crawl_output/run1
python scripts/collect_url.py https://example.test/ --out crawl_output/run2 --classify
~~~

Each target receives its own directory. `run_config.json` records the effective
settings, the crawler retains its detailed resource manifests, and
`scan_manifest.json` lists only downloaded UTF-8 text bodies accepted for secret
scanning. Binary data, soft-404 bodies, duplicate paths, screenshots, logs, and
collector metadata are excluded from the classification handoff.

For a deterministic check that never contacts the public Web, run:

~~~bash
python scripts/smoke_collect.py
~~~

Only scan systems and URLs you are authorized to assess.
