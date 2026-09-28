import re, math, json, subprocess
from multiprocessing import Pool

def entropy(s):
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum(v/len(s)*math.log2(v/len(s)) for v in freq.values())

PATTERN = re.compile(r'(?:var|let|const)\s+([a-zA-Z$])\s*=\s*["\']([^"\']{20,150})["\']')

def scan_file(fpath):
    try:
        with open(fpath, errors='ignore') as f:
            content = f.read()
        hits = []
        for m in PATTERN.finditer(content):
            val = m.group(2)
            e = entropy(val)
            if e >= 4.5:
                hits.append({
                    'var': m.group(1),
                    'val': val[:100],
                    'entropy': round(e, 2),
                    'file': fpath
                })
        return hits
    except:
        return []

if __name__ == '__main__':
    r = subprocess.run(
        'find <CORPUS> '
        '<CORPUS> '
        '-maxdepth 2 -type f -name "*.js"',
        shell=True, capture_output=True, text=True
    )
    files = [f for f in r.stdout.strip().split('\n') if f]
    print(f'总文件数: {len(files)}', flush=True)

    all_hits = []
    with Pool(70) as pool:
        for i, hits in enumerate(pool.imap_unordered(scan_file, files, chunksize=1000)):
            all_hits.extend(hits)
            if (i+1) % 100000 == 0:
                print(f'  已处理 {i+1}/{len(files)}，命中 {len(all_hits)} 条', flush=True)

    print(f'\n全量扫描完成，命中 {len(all_hits)} 条', flush=True)

    with open('/tmp/local_var_hits_full.json', 'w') as f:
        json.dump(all_hits, f, ensure_ascii=False, indent=2)
    print('结果写入 /tmp/local_var_hits_full.json')
