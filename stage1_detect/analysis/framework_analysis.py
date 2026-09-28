#!/usr/bin/env python3
"""
Comprehensive analysis of web framework and secret leak patterns
from scraped web data.
"""
import json
import re
import os
from collections import defaultdict, Counter
from urllib.parse import urlparse

# Load data
with open('<DETECT_ROOT>/states/result_88/analysis_data.json', 'r') as f:
    data = json.load(f)

# ─────────────────────────────────────────────────────────────────────────────
# 1. EXTRACT ALL SAMPLES (flatten all rules into one list)
# ─────────────────────────────────────────────────────────────────────────────
all_samples = []
for rule_name, d in data.items():
    for sample in d.get('samples', []):
        all_samples.append(sample)

print(f"Total samples across all rules: {len(all_samples)}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. PARSE FILE PATHS: extract domain, extension, framework indicators
# ─────────────────────────────────────────────────────────────────────────────

# Path pattern: <corpus_root>/{domain}/{filename}
# Override with the CORPUS_DIR_RE env var if your corpus uses a different layout.
DOMAIN_RE = re.compile(os.environ.get("CORPUS_DIR_RE", r'/([^/]+)/[^/]+$'))
EXT_RE = re.compile(r'\.([a-zA-Z0-9]+)(?:\.map)?(?:#|$|\?)')
FRAGMENT_EXT_RE = re.compile(r'#([a-zA-Z0-9_-]+)$')

def extract_domain(filepath):
    m = DOMAIN_RE.search(filepath)
    if m:
        raw = m.group(1)
        # Convert underscores to dots, handle _io, _com patterns
        domain = raw.replace('_io_', '.io/').replace('_com_', '.com/')
        # Simple heuristic: replace remaining underscores with dots for subdomain separation
        domain = domain.replace('_', '.').rstrip('/')
        # Try to fix common patterns: if it ends with .io, .com, .org, keep the original
        # e.g. "example_io" -> "example.io"
        # Heuristic: if domain has no dot, convert first underscore to dot
        if '.' not in domain and '_' in raw:
            # Find the original
            domain = raw.replace('_', '.', 1)  # first underscore -> dot
        return domain
    return 'unknown'

def extract_extension(filepath):
    # Remove fragments like #fontawesome
    clean = re.sub(r'#.*$', '', filepath)
    # Get extension
    m = re.search(r'\.([a-zA-Z0-9]+)(?:\.map)?$', clean)
    if m:
        return m.group(1).lower()
    return 'no_ext'

def extract_fragment(filepath):
    m = FRAGMENT_EXT_RE.search(filepath)
    if m:
        return m.group(1).lower()
    return None

# Framework indicators from path
FRAMEWORK_PATTERNS = {
    'Next.js': [r'/next/', r'next\.js', r'next\.config'],
    'Nuxt.js': [r'/nuxt/'],
    'Gatsby': [r'/gatsby/'],
    'React': [r'/react/', r'/rb-', r'-chunk-', r'chunk-', r'\.module\.'],
    'Vue': [r'/vue/', r'\.vue\.', r'/\?vue'],
    'Angular': [r'/ng-', r'angular', r'\.module\.'],
    'Webpack': [r'webpack', r'\.bundle\.'],
    'Svelte': [r'/svelte/'],
    'TypeScript': [r'\.ts\b', r'/tsc/', r'typescript'],
    'Node.js': [r'/node_modules/', r'\.cjs\.', r'\.mjs\.', r'yarnrc', r'package\.json'],
    'Python': [r'__pycache__/', r'\.pyc', r'\.py\b'],
    'PHP': [r'/vendor/', r'composer\.json', r'Laravel', r'/php/'],
    'Ruby': [r'\.rb\b', r'/vendor/bundle/', r'Gemfile'],
    'Java': [r'\.java\b', r'/target/', r'/build/'],
    'Go': [r'\.go\b', r'/vendor/'],
    'Docker': [r'Dockerfile', r'\.dockerignore', r'docker-compose'],
    'Minified/Source Map': [r'\.map$', r'source map'],
    'Static HTML': [r'\.html?$'],
    'CSS/SCSS': [r'\.css$', r'\.scss$', r'\.sass$'],
    'Config JSON': [r'\.json$'],
    'Config YAML': [r'\.ya?ml$', r'\.toml$'],
    'Env files': [r'\.env', r'\.env\..+', r'\.envrc'],
    'SVG': [r'\.svg$'],
    'Media': [r'\.(png|jpg|jpeg|gif|webp|ico|woff|woff2|ttf|eot|mp4|mp3)$'],
}

def detect_frameworks(filepath):
    found = []
    for fw, patterns in FRAMEWORK_PATTERNS.items():
        for p in patterns:
            if re.search(p, filepath, re.IGNORECASE):
                found.append(fw)
                break
    return found

# ─────────────────────────────────────────────────────────────────────────────
# 3. CATEGORIZE SAMPLES
# ─────────────────────────────────────────────────────────────────────────────

# Global counters
file_ext_counter = Counter()
rule_file_ext_counter = defaultdict(Counter)
rule_domain_counter = defaultdict(Counter)
domain_framework_counter = defaultdict(lambda: Counter())
framework_rule_counter = defaultdict(lambda: Counter())
source_map_count = 0
inline_js_count = 0  # .html files with script tags
external_js_count = 0
config_file_count = 0
total_by_rule = {}
all_domains = set()

# Leak context categories
LEAK_CONTEXTS = {
    'source_map': Counter(),
    'inline_html_script': Counter(),
    'external_js': Counter(),
    'config_json': Counter(),
    'config_env': Counter(),
    'static_html': Counter(),
    'css_embed': Counter(),
    'map_embed_in_html': Counter(),
    'other': Counter(),
}

# Detailed samples for each context
context_samples = defaultdict(list)

for sample in all_samples:
    filepath = sample.get('file', '')
    rule = sample.get('rule_name', '')
    line_content = sample.get('line_content', '')[:100]

    # Extract
    domain = extract_domain(filepath)
    ext = extract_extension(filepath)
    fragment = extract_fragment(filepath)
    frameworks = detect_frameworks(filepath)

    all_domains.add(domain)
    file_ext_counter[ext if not fragment else f"{ext}#{fragment}"] += 1
    rule_file_ext_counter[rule][ext if not fragment else f"{ext}#{fragment}"] += 1
    rule_domain_counter[rule][domain] += 1

    for fw in frameworks:
        domain_framework_counter[domain][fw] += 1
        framework_rule_counter[fw][rule] += 1

    total_by_rule[rule] = total_by_rule.get(rule, 0) + 1

    # Determine leak context
    clean_lower = filepath.lower()
    if '.map' in clean_lower or 'source map' in clean_lower:
        LEAK_CONTEXTS['source_map'][rule] += 1
        context_samples['source_map'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })
        source_map_count += 1
    elif ext == 'html' or '.html' in clean_lower:
        # Check if this is inline script (the sample is from an HTML file)
        if 'script' in line_content.lower() or '<html' in line_content.lower() or '{' in line_content or 'function' in line_content.lower() or 'window.' in line_content.lower():
            LEAK_CONTEXTS['inline_html_script'][rule] += 1
            context_samples['inline_html_script'].append({
                'file': filepath, 'rule': rule, 'domain': domain,
                'line_content': line_content, 'frameworks': frameworks
            })
            inline_js_count += 1
        else:
            LEAK_CONTEXTS['static_html'][rule] += 1
            context_samples['static_html'].append({
                'file': filepath, 'rule': rule, 'domain': domain,
                'line_content': line_content, 'frameworks': frameworks
            })
    elif ext == 'js' or '.js' in clean_lower:
        LEAK_CONTEXTS['external_js'][rule] += 1
        context_samples['external_js'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })
        external_js_count += 1
    elif ext in ['json', 'jsonc']:
        LEAK_CONTEXTS['config_json'][rule] += 1
        context_samples['config_json'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })
        config_file_count += 1
    elif 'env' in clean_lower or 'envrc' in clean_lower:
        LEAK_CONTEXTS['config_env'][rule] += 1
        context_samples['config_env'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })
    elif ext in ['css', 'scss', 'sass']:
        LEAK_CONTEXTS['css_embed'][rule] += 1
        context_samples['css_embed'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })
    elif '.map' in filepath or 'sourceMap' in filepath:
        LEAK_CONTEXTS['source_map'][rule] += 1
        context_samples['source_map'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })
        source_map_count += 1
    else:
        LEAK_CONTEXTS['other'][rule] += 1
        context_samples['other'].append({
            'file': filepath, 'rule': rule, 'domain': domain,
            'line_content': line_content, 'frameworks': frameworks
        })

# ─────────────────────────────────────────────────────────────────────────────
# 4. AGGREGATE AGGREGATE AGGREGATE
# ─────────────────────────────────────────────────────────────────────────────

print("\n" + "="*80)
print("SECTION 1: FILE TYPE DISTRIBUTION")
print("="*80)
print(f"\nTotal unique domains: {len(all_domains)}")
print(f"\nTop 30 file types/fragments by count:")
for ext, count in file_ext_counter.most_common(30):
    pct = count / len(all_samples) * 100
    print(f"  {ext:30s}: {count:6d} ({pct:5.2f}%)")

print("\n" + "="*80)
print("SECTION 2: LEAK CONTEXT DISTRIBUTION")
print("="*80)
total_context = sum(sum(c.values()) for c in LEAK_CONTEXTS.values())
for ctx_name, counter in LEAK_CONTEXTS.items():
    ctx_total = sum(counter.values())
    if ctx_total > 0:
        print(f"\n{ctx_name} ({ctx_total} hits):")
        for rule, cnt in counter.most_common(5):
            print(f"  {rule}: {cnt}")

print("\n" + "="*80)
print("SECTION 3: FRAMEWORK ANALYSIS")
print("="*80)
for fw, counter in sorted(framework_rule_counter.items(), key=lambda x: sum(x[1].values()), reverse=True):
    total = sum(counter.values())
    if total >= 10:
        print(f"\n{fw} ({total} hits across {len(counter)} rule types):")
        for rule, cnt in counter.most_common(5):
            print(f"  {rule}: {cnt}")

print("\n" + "="*80)
print("SECTION 4: RULE × FILE TYPE MATRIX (top 15 rules, top 10 file types)")
print("="*80)
top_rules = [r for r, _ in sorted(total_by_rule.items(), key=lambda x: x[1], reverse=True)[:15]]
top_exts = [e for e, _ in file_ext_counter.most_common(10)]

# Header
header = f"{'Rule':<40}" + "".join(f"{e:>8}" for e in top_exts)
print(header)
print("-" * len(header))
for rule in top_rules:
    row = f"{rule[:40]:<40}"
    for ext in top_exts:
        row += f"{rule_file_ext_counter[rule].get(ext, 0):>8}"
    print(row)

print("\n" + "="*80)
print("SECTION 5: SOURCE MAP DEEP ANALYSIS")
print("="*80)
map_samples = context_samples['source_map']
print(f"Total source map hits: {len(map_samples)}")
print(f"Unique domains with source map hits: {len(set(s['domain'] for s in map_samples))}")
print(f"\nSample source map files (first 10):")
seen = set()
count = 0
for s in map_samples:
    if s['file'] not in seen and count < 10:
        seen.add(s['file'])
        print(f"  {s['file']}")
        print(f"    Rule: {s['rule']}, Content: {s['line_content'][:80]}")
        count += 1

print("\n" + "="*80)
print("SECTION 6: INLINE HTML SCRIPT ANALYSIS")
print("="*80)
html_samples = context_samples['inline_html_script']
print(f"Total inline HTML script hits: {len(html_samples)}")
print(f"Unique domains: {len(set(s['domain'] for s in html_samples))}")
seen = set()
count = 0
for s in html_samples:
    if s['file'] not in seen and count < 10:
        seen.add(s['file'])
        print(f"  {s['file']}")
        print(f"    Rule: {s['rule']}, Content: {s['line_content'][:100]}")
        count += 1

print("\n" + "="*80)
print("SECTION 7: SDK vs SERVER KEY ANALYSIS")
print("="*80)
# Categorize rules
SDK_KEYWORDS = ['PostHog', 'Segment', 'Amplitude', 'Mixpanel', 'Google_Analytics',
                'Google_YouTube', 'Intercom', 'CustomerIO', 'Mailchimp', 'Sentry',
                'Datadog', 'NewRelic', 'FullStory', 'Hotjar', 'Optimizely',
                'KISSmetrics', 'Heap', 'Adjust', 'AppsFlyer', 'Branch.io',
                'Facebook', 'Twitter', 'LinkedIn', 'Stripe', 'PayPal',
                'Algolia', 'SearchIQ', 'Sphinx', 'Swiftype', 'Elastic',
                'Mapbox', 'Google_Maps', 'Google', 'Akamai', 'Cloudflare',
                'Fastly', 'Cloudfront', 'Imgix', 'Cloudinary', 'SendGrid',
                'Mailgun', 'SparkPost', 'Twilio', 'Nexmo', 'Plivo',
                'Twilio', 'Contentful', 'Sanity', 'Strapi', 'Storyblok',
                'Blogger', 'Disqus', 'Sumo', 'Olark', 'Zendesk',
                'Hubspot', 'Pipedrive', 'Close.io', 'Freshsales', 'Chargebee',
                'Recurly', 'Paymill', 'Braintree', 'Razorpay', 'Paytm',
                'Float', 'Deputy', 'WorkBoard', 'Aha', 'ProductHunt',
                'Debounce', 'Abstract', 'Scraper', 'Scraping', 'Apify',
                'Crawlera', 'Phantom', 'Screenshot', 'Blocksp', 'Datafire',
                'Iron', 'Glitch', 'Render', 'Netlify', 'Vercel', 'Heroku',
                'DigitalOcean', 'Linode', 'AWS', 'Azure', 'GCP', 'Firebase',
                'Supabase', 'Pusher', 'Ably', 'PubNub', 'Firebase',
                'Clarifai', 'Wit', 'Microsoft', 'IBM', 'Nvidia', 'Replicate',
                'OpenAI', 'Cohere', 'AI21', 'Anthropic', 'Hugging Face',
                'Deepgram', 'AssemblyAI', 'Speechmatics', 'Rev', 'Nuance',
                'OCR', 'abbyy', 'trainual']

SERVER_KEYWORDS = ['AWS Secret', 'Azure Client Secret', 'Private Key',
                   'Jwt', 'JWT', 'Bearer', 'Authorization', 'OAuth',
                   'Api Secret', 'api_secret', 'SecretKey', 'secret_key',
                   'Client Secret', 'connection string', 'conn_str',
                   'Database', 'Jdbc', 'MongoDB', 'Redis', 'Postgres',
                   'MySQL', 'mssql', 'oracle', 'db_', 'rds_', 'mongo_',
                   'S3 ', 's3_', 'storage_account', 'storage_key',
                   'Slack', 'Discord', 'Telegram', 'SMTP', 'ssh_',
                   'gcp_', 'googleapis', 'firebase_']

def categorize_rule(rule):
    rule_lower = rule.lower()
    is_sdk = any(kw.lower() in rule_lower for kw in SDK_KEYWORDS)
    is_server = any(kw.lower() in rule_lower for kw in SERVER_KEYWORDS)
    if is_sdk and not is_server:
        return 'SDK/Public'
    elif is_server and not is_sdk:
        return 'Server/Secret'
    else:
        return 'Ambiguous/Uncategorized'

for cat in ['SDK/Public', 'Server/Secret', 'Ambiguous/Uncategorized']:
    print(f"\n--- {cat} ---")
    cat_rules = {r: d for r, d in data.items() if categorize_rule(r) == cat}
    total_cat = sum(v['count'] for v in cat_rules.values())
    print(f"Rules: {len(cat_rules)}, Total hits: {total_cat}")
    for r, v in sorted(cat_rules.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
        print(f"  {r}: {v['count']} (domains: {v['domains_count']})")

print("\n" + "="*80)
print("SECTION 8: DOMAIN-LEVEL ANALYSIS (most affected domains)")
print("="*80)
domain_total_counter = Counter()
domain_rule_breakdown = defaultdict(lambda: Counter())
for sample in all_samples:
    domain = extract_domain(sample['file'])
    rule = sample['rule_name']
    domain_total_counter[domain] += 1
    domain_rule_breakdown[domain][rule] += 1

print("\nTop 20 most affected domains (total hits):")
for domain, cnt in domain_total_counter.most_common(20):
    rules_str = ', '.join([f"{r}:{c}" for r, c in domain_rule_breakdown[domain].most_common(5)])
    print(f"  {domain}: {cnt} hits")
    print(f"    Top rules: {rules_str}")

print("\n" + "="*80)
print("SECTION 9: DATA BREAKDOWN BY MAJOR CATEGORIES")
print("="*80)

categories = {
    'Analytics/Product Analytics': ['Posthog API Key', 'Segment', 'Amplitude', 'Mixpanel', 'Heap', 'Hotjar'],
    'Marketing/CRM': ['hubspot-api-key', 'Intercom API Key', 'CustomerIO API Key', 'Mailchimp', 'Zendesk', 'Facebook'],
    'Cloud/Infrastructure': ['AWS', 'Azure', 'Google', 'Firebase', 'Cloudflare', 'Fastly'],
    'Search': ['Algolia', 'Elastic', 'Swiftype', 'SearchIQ', 'Sphinx'],
    'Communication': ['Twilio', 'Slack', 'SendGrid', 'Mailgun', 'Discord', 'Telegram'],
    'Payments': ['Razorpay', 'Stripe', 'PayPal', 'Braintree', 'Chargebee', 'Paymill'],
    'Secret/Auth': ['jwt', 'Azure Client Secret', 'AWS API Secret', 'discord-client-secret'],
    'DevOps/Hosting': ['Host API Key', 'Heroku', 'Netlify', 'Vercel', 'DigitalOcean'],
    'Content/CMS': ['Contentful', 'Blogger', 'Sanity', 'Strapi'],
    'Maps/Geolocation': ['Mapbox', 'Google_Maps'],
}

for cat_name, keywords in categories.items():
    total_cat = sum(data[r]['count'] for r in keywords if r in data)
    domains_cat = set()
    for r in keywords:
        if r in data:
            domains_cat.update(s['domain'] for s in data[r]['samples'])
    if total_cat > 0:
        print(f"\n{cat_name}:")
        print(f"  Total hits: {total_cat}, Unique domains: {len(domains_cat)}")
        for r in keywords:
            if r in data:
                d = data[r]
                print(f"    {r}: {d['count']} (domains: {d['domains_count']}, top_ft: {list(d['top_file_types'].keys())[:3]})")

print("\n" + "="*80)
print("DONE")
print("="*80)
