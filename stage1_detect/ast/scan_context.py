import re, json, math
from multiprocessing import Pool

def entropy(s):
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum(v/len(s)*math.log2(v/len(s)) for v in freq.values())

# call-site 特征规则
SDK_INIT = re.compile(
    r'(initializeApp|firebase\.init|Stripe\s*\(|stripe\.init|Bugsnag\.start|Sentry\.init'
    r'|amplitude\.init|mixpanel\.init|analytics\.init|braintree\.create'
    r'|paypal\.Buttons|pusher\s*=\s*new\s*Pusher|new\s*Pusher\s*\('
    r'|algolia\s*\(|algoliasearch\s*\(|mapboxgl\.accessToken'
    r'|google\.maps|new\s*google\.maps)',
    re.IGNORECASE
)
HTTP_AUTH = re.compile(
    r'(Authorization|X-API-Key|X-Api-Key|api[_-]?key|apikey|access[_-]?token'
    r'|Bearer\s|api[_-]?secret|client[_-]?secret)',
    re.IGNORECASE
)
CRYPTO_USE = re.compile(
    r'(hmac|HMAC|sha256|SHA256|md5\s*\(|MD5\s*\(|encrypt\s*\(|sign\s*\(|createHmac)',
    re.IGNORECASE
)
NOISE = re.compile(
    r'(split\s*\(|replace\s*\(|charCodeAt|charAt\s*\(|indexOf\s*\(|slice\s*\('
    r'|substring\s*\(|toLowerCase|toUpperCase|\.length|RegExp)',
    re.IGNORECASE
)

def classify_val(val):
    stripped = re.sub(r'[^a-zA-Z0-9]', '', val)
    if len(stripped) >= 20:
        unique_ratio = len(set(stripped)) / len(stripped)
        if unique_ratio > 0.85 and len(stripped) >= 30:
            return 'charset_table'
    if re.match(r'^(/|\.\.?/|https?://|data:)', val): return 'path_or_url'
    if re.search(r'[<>{}\s\(\)]', val): return 'code_or_markup'
    if re.match(r'^[a-zA-Z][a-zA-Z0-9]*(-[a-zA-Z0-9]+){2,}(\.[a-z]+)?$', val): return 'asset_id'
    if re.match(r'^(sk_live_|sk_test_|pk_live_|pk_test_|AKIA[0-9A-Z]|AIzaSy|xox[abprs]-|SG\.[A-Za-z0-9]|ghp_|ya29\.|eyJ)', val):
        return 'known_secret_format'
    if re.match(r'^[0-9a-f]{32,64}$', val): return 'hex_hash'
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val): return 'uuid'
    if re.match(r'^[\d]+\.[\d]+\.[\d]+', val): return 'version'
    return 'high_entropy_unknown'

def scan_context(item):
    fpath = item['file']
    val = item['val']
    varname = item['var']
    try:
        with open(fpath, errors='ignore') as f:
            content = f.read()
        # 找到这个值在文件里的位置
        val_pos = content.find(val)
        if val_pos == -1:
            return None
        # 找变量声明位置（往前找 var/let/const x =）
        decl_start = max(0, val_pos - 200)
        decl_chunk = content[decl_start:val_pos + len(val) + 10]
        decl_match = re.search(
            r'(?:var|let|const)\s+([a-zA-Z$])\s*=\s*["\']' + re.escape(val[:30]),
            decl_chunk
        )
        if not decl_match:
            return None
        actual_var = decl_match.group(1)

        # 在整个文件里搜索这个变量的使用（向后 2000 字符内）
        usage_window = content[val_pos: val_pos + 2000]

        # 判断 call-site 类型
        has_sdk   = bool(SDK_INIT.search(usage_window))
        has_http  = bool(HTTP_AUTH.search(usage_window))
        has_crypto= bool(CRYPTO_USE.search(usage_window))
        has_noise = bool(NOISE.search(usage_window))

        if not (has_sdk or has_http or has_crypto):
            return None
        # 噪声信号强且没有 SDK/HTTP 信号时跳过
        if has_noise and not (has_sdk or has_http):
            return None

        # 提取上下文片段
        ctx_start = max(0, val_pos - 100)
        ctx_end   = min(len(content), val_pos + 500)
        context_snippet = content[ctx_start:ctx_end].replace('\n', ' ')[:400]

        signal = []
        if has_sdk:   signal.append('SDK_INIT')
        if has_http:  signal.append('HTTP_AUTH')
        if has_crypto:signal.append('CRYPTO')

        return {
            'var': actual_var,
            'val': val[:80],
            'entropy': item['entropy'],
            'signal': signal,
            'context': context_snippet,
            'file': fpath
        }
    except:
        return None

if __name__ == '__main__':
    with open('<RAG_ROOT>/whole_project/update/round2/measurement_final/remake/mini_filed/local_var_hits_full.json') as f:
        hits = json.load(f)

    unknown = [h for h in hits if classify_val(h['val']) == 'high_entropy_unknown']
    print(f'high_entropy_unknown 总数: {len(unknown)}', flush=True)

    results = []
    with Pool(70) as pool:
        for i, r in enumerate(pool.imap_unordered(scan_context, unknown, chunksize=500)):
            if r:
                results.append(r)
            if (i+1) % 10000 == 0:
                print(f'  已处理 {i+1}/{len(unknown)}，命中 {len(results)} 条', flush=True)

    print(f'\n完成，call-site 命中: {len(results)} 条', flush=True)

    out = '<RAG_ROOT>/whole_project/update/round2/measurement_final/remake/mini_filed/context_hits.json'
    with open(out, 'w') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f'结果写入 {out}')
