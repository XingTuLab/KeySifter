"""
risk_classifier.py

Current live classification flow:
1. Apply refine overrides for generic/JWT and a small set of unstable rules.
2. Route by explicit rule_name / series allowlists.
3. Send JWT items to claim-aware parsing.
4. Send generic items through:
   - placeholder / known-safe variable-name filters
   - context-required names that must keep flowing to refine/vector
   - embedding + KB matching for remaining ambiguity

Important:
- There is no active broad "dangerous variable name blacklist -> FalsePositive".
- Names such as secret/password/client_secret/private_key/access_token are
  intentionally treated as context-sensitive and must not be auto-suppressed.
"""

from base_func import *
import os
import json
import time
import logging
import base64
import re
import numpy as np
from sentence_transformers import SentenceTransformer
import torch
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# =============================================================================
# 第一层：CRITICAL_SERIES - 直接 Critical，不走后续流程
# =============================================================================
CRITICAL_SERIES = frozenset([
    "private",   # Private Key
    "aws",       # AWS API Secret
    "razorpay",  # RazorPay API Secret
    "gcp",       # Google Cloud / YouTube
    "hubspot",   # HubSpot
    "toggltrack",# Toggltrack
    "sumologic", # Sumo Logic
    "hive",      # Hive
    "contentful",# Contentful
    "zendesk",   # Zendesk
    "sirv",      # Sirv
    "witnessai", # Witness AI
    "zapier",    # Zapier webhook
    "host",      # Host
    "onelogin",  # Onelogin
    "grafana",   # Grafana
    "locationiq", # LocationIQ
])

# =============================================================================
# 第一层：POTENTIAL_SERIES - 直接 Potential，不走后续流程
# =============================================================================
POTENTIAL_SERIES = frozenset([
    "algolia",   # Algolia Search-Only API Key
    "posthog",   # PostHog Analytics
    "flickr",    # Flickr
])

# =============================================================================
# 第一层：CRITICAL_RULES - 明确高危的规则名（所有 series 都 Critical）
# 包含 snake_case 变体
# =============================================================================
CRITICAL_RULES = frozenset([
    # === 私钥/证书 ===
    "Private Key", "private-key", "RSA Private Key", "PGP Private Key",
    "Elliptic Curve Private Key", "age secret key",

    # === AWS ===
    "AWS API Secret",

    # === Google Cloud ===
    "Google_YouTube_OAuth ID",

    # === 支付 - 后端 Secret ===
    "RazorPay API Secret",
    "Stripe API Key", "Stripe_Restricted API Key",
    "flutterwave-secret-key", "flutterwave-encryption-key",
    "Checkout API Key",


    # === HubSpot ===
    "HubSpot API Key", "hubspot-api-key",

    # === Toggltrack ===
    "Toggltrack API Key",

    # === Sumo Logic ===
    "Sumo Logic Access Token", "sumologic-access-token",

    # === Hive ===
    "Hive API Key",

    # === Sirv ===
    "Sirv API Key",

    # === Contentful ===
    "Contentful API Personal Token",

    # === Zendesk ===
    "Zendesk API Token",

    # === Zapier ===
    "Zapier webhook",

    # === Host ===
    "Host API Key",

    # === Onelogin ===
    "Onelogin OAuth Client Secret",

    # === Grafana ===
    "grafana-api-key",

    # === Firebase ===
    "Firebase API Key", "firebase-api-key",

    # === Flickr ===
    "Flickr Access Token", "flickr-access-token",
])

# =============================================================================
# 第一层：LOW_RISK_RULES - 明确低危的规则名（设计为前端公开）
# =============================================================================
LOW_RISK_RULES = frozenset([
    # === 搜索 ===
    "Algolia API Key",

    # === 分析/埋点 ===
    "Posthog API Key", "Posthog Analytics",
    "new-relic-browser-api-token",

    # === Google 前端 key ===
    "Google_YouTube_API key",

    # === 图片 ===
    "Flickr API Key",

    # === 地图 / 地理定位 ===
    "Mapbox API Key", "mapbox-api-token",
    "LocationIQ API Key",

    # === 前端公开访问 token ===
    "Contentful Delivery API Token", "contentful-delivery-api-token",
    "lob-pub-api-key",
    "mailgun-pub-key",
    "PubnubPublish Key", "Pubnub Subscription Key",

    # === 支付 - 前端公开 ===
    "Stripe_Standard API Key",
    "flutterwave-public-key",
    "RazorPay API Key", "Razorpay API Key", "razorpay-api-key",
])

# =============================================================================
# JWT 风险字段
# =============================================================================
JWT_CRITICAL_CLAIMS = frozenset([
    "sub", "user_id", "uid", "account_id",
    "email", "preferred_username", "username",
    "role", "roles", "scope", "scopes",
    "permission", "permissions", "admin",
    "is_admin", "is_superuser", "is_root",
    "client_id", "azp", "aud",
    "access_token", "refresh_token",
    "secret", "password", "pwd",
])

JWT_CRITICAL_ISSUERS = frozenset([
    "accounts.google.com", "https://accounts.google.com",
    "https://securetoken.googleapis.com",
    "api.twitter.com", "auth0.com", "okta.com", "onelogin.com",
    "stripe.com", "paypal.com",
    "github.com", "https://github.com",
    "gitlab.com", "https://gitlab.com",
])

JWT_CRITICAL_APP_ID_PATTERNS = [
    "google_", "goog-", "gcp-",
    "tw_", "twitch_",
    "gh_", "github_",
    "slack_", "discord_", "telegram_",
]

# =============================================================================
# 本地 GPU embedding 配置
# =============================================================================
LOCAL_EMBEDDING_MODEL = os.environ.get("JINA_MODEL_DIR", "<MODELS>/jina-embeddings-v4")
LOCAL_DEVICE = os.environ.get("RISK_DEVICE", "cuda:0")
EMBED_BATCH_SIZE = 128

# =============================================================================
# 辅助函数
# =============================================================================
def _is_generic_or_jwt(rule_name):
    """判断是否为 generic 或 jwt 类型"""
    rn = rule_name.lower()
    if rn == "jwt" or rn == "jwt-base64":
        return True, "jwt"
    if "generic" in rn:
        return True, "generic"
    return False, None


def _extract_var_name_from_match(item):
    """从 match 字段提取变量名"""
    match_str = item.get('match', '') or ''
    value = item.get('value', '') or ''
    if not match_str or not value:
        # Fallback: handle key:"value" style patterns where value may need normalization.
        simple = re.search(r'([A-Za-z0-9_\-]{2,64})[\"\'` ]?\s*[:=]\s*[\"\'`]?', match_str)
        return simple.group(1) if simple else None
    val_idx = match_str.find(value)
    if val_idx <= 0:
        simple = re.search(r'([A-Za-z0-9_\-]{2,64})[\"\'` ]?\s*[:=]\s*[\"\'`]?', match_str)
        return simple.group(1) if simple else None
    end = val_idx - 1
    while end >= 0 and match_str[end] in ' \t"\'=:':
        end -= 1
    if end < 0:
        return None
    start = end
    while start >= 0 and (match_str[start].isalnum() or match_str[start] in '_-'):
        start -= 1
    start += 1
    vn = match_str[start:end + 1]
    if len(vn) >= 2 and len(vn) < 50:
        return vn
    return None


REFINE_FP_VAR_NAMES = frozenset([
    # iter1/iter2: confirmed frontend identifiers / browser-only tokens
    "_token", "csrf", "csrftoken", "csrf_token", "csrf-token", "csrf_token",
    "merchantkey", "localcachekey", "dtoken", "session_token",
    "auth0client", "yotpositekey", "convivacustomerkey", "sitekey",
    # iter3: known public service / tracking / visitor tokens
    "vtoken", "sitetoken", "session", "sessiontoken", "acctoken", "dy",
    "playertoken", "pixel_token", "ltoken", "tdtoken", "bptoken", "sktoken",
    "fetchifytoken", "fetchify_token", "qf", "qftoken", "qf_token",
    "vrtoken", "vr_token", "sftoken", "encodedapikey",
])

CONTEXT_REQUIRED_VAR_NAMES = frozenset([
    # These names are too ambiguous to classify from the variable name alone.
    # They must continue to the context / KB layer.
    "appkey", "app_key",
    "apikey", "api_key", "api-key",
    "api_token", "api_secret",
    "token", "key", "secret",
    "password", "passwd",
    "access_token", "access-token",
    "auth_token", "auth-token",
    "refresh_token", "refresh-token",
    "client_id", "client_secret",
    "id_token",
    "x_api_key", "x-api-key",
    "bearer", "bearer_token",
    "public_key", "private_key",
])

DIRECT_FP_PLACEHOLDER_NAMES = frozenset([
    "xxxx", "xxxxx", "xxxxxx",
    "test123",
    "dummy", "dummy_key", "dummy_token",
    "fake", "fake_key", "fake_token",
    "mock_key", "mock_token",
    "example_key", "example_token", "example_api_key",
    "your_api_key", "your_key", "your_token", "your_secret",
    "your_api_key_here", "insert_key_here", "paste_key_here", "your_key_here",
    "not_set", "set_api_key_here", "replace_with_your_key",
    "change_me", "changeme", "changethis", "change_this",
    "use_your_key", "replace_with_key",
])

DIRECT_FP_PLACEHOLDER_PREFIXES = (
    "test_", "demo_", "sample_", "placeholder_", "dummy_",
    "fake_", "mock_", "example_", "your_",
)

REFINE_OVERRIDE_RULE_NAMES = frozenset([
    "Uri", "URL",
    "AWS API Secret",
    "RazorPay API Secret",
    "HubSpot API Key", "hubspot-api-key",
    "Toggltrack API Key",
    "Hive API Key",
    "Zapier webhook",
    "jwt", "jwt-base64",
])

HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{32,64}$", re.I)
MD5_RE = re.compile(r"^[0-9a-f]{32}$", re.I)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
FETCHIFY_RE = re.compile(r"^[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}$", re.I)
MERCHANT_KEY_PLACEHOLDER_RE = re.compile(r"^md_key_\d+i\d+$", re.I)
PURE_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
AWS_SECRET_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=]{40}$")
SKEY_VERSION_PARAM_RE = re.compile(r"(?:^|[?&\s\"'])skey=[0-9a-f]{8,64}(?:&amp;|&)?v=v\d+", re.I)
NEW_RELIC_BROWSER_RE = re.compile(r"\bNR(?:JS|BR)-[A-Za-z0-9]{10,}\b")
FRONTEND_LIBRARY_LICENSE_RE = re.compile(r"^[A-F0-9]{8}(?:-[A-F0-9]{8}){3}$", re.I)
IMAGE_RESOURCE_KEY_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:png|jpe?g|webp|gif|svg)$", re.I)

AMBIGUOUS_BROAD_RULE_NAMES = frozenset([
    "Abstract API",
    "atlassian-api-token",
    "Azure Client Secret",
    "Blogger API Key",
    "CloudFlare API Key",
    "CoinBase API Key",
    "Contentful API Personal Token",
    "CustomerIO API Key",
    "Datafire API Key",
    "Debounce API Key",
    "discord-client-secret",
    "Float API Key",
    "HereAPI Key",
    "Host API Key",
    "IBM API Key",
    "Ideogram-api-key",
    "Intercom API Key",
    "Jdbc Token",
    "Jira Token",
    "LessannoyingCRM API Key",
    "Mite API Key",
    "NasDaqdatalink API Key",
    "private-key",
    "ProspectCRM API Key",
    "Raven API Key",
    "sentry-access-token",
    "Shortcut API Key",
    "Sirv API Key",
    "twitter-api-key",
    "Usersecretscanner API Key",
    "Wit API Key",
    "Zendesk API Token",
])

WORDLIKE_BROAD_RULE_NAMES = frozenset([
    "CustomerIO API Key",
    "Debounce API Key",
    "Host API Key",
    "Mite API Key",
    "Raven API Key",
    "Wit API Key",
])

ASSET_FILE_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".pdf", ".js", ".css", ".map", ".mjs",
)

OBVIOUS_PLACEHOLDER_VALUES = frozenset([
    "API_KEY",
    "API_KEY_RANDOM",
    "CLOUDINARY_API_KEY",
    "ELASTICSEARCH_API_KEY",
    "INTENTIONALLY_BLANK_WRITE_KEY",
    "REPLACE_WITH_SDK_KEY",
    "ZEP_API_KEY_RANDOM",
])

_RE_EXPERIMENT_VARIATION = re.compile(r"^\d{9,}-variation-[a-z0-9]+$", re.I)
_RE_SUMO_SITE_ID = re.compile(r"^[a-f0-9]{64}$", re.I)
_RE_DROPBOX_APP_KEY = re.compile(r"^[a-z0-9]{15,16}$", re.I)
_RE_RAZORPAY_BRAND_ASSET = re.compile(r"^rzp_[a-z0-9_]{8,}$", re.I)
_RE_ALL_CAPS_CONFIG_NAME = re.compile(r"^[A-Z][A-Z0-9_]{20,}$")
_RE_TIMEBOUND_AUTH_KEY = re.compile(r"^\d{10,16}-\d+-\d+-[0-9a-f]{32}$", re.I)
_KB_OVERRIDE_IDS_TO_POTENTIAL = {
    "60050910-9b4f-4021-a516-37a785ac6fc3",  # captcha/site key class
}
_KB_OVERRIDE_MAPBOX_PUBLIC_IDS = {
    "540ae999-d45c-47c9-8c0b-38c7b232ae14",  # service-key too broad; rescue only clear public keys
    "a7a0a0fd-9f9a-4d50-8151-aa34f9f43a67",  # Token bucket too broad
    "374e1300-fcd8-44ed-8ab5-81f3d7934bd1",  # data-access-token
}


def _get_item_text(item, key):
    val = item.get(key, "")
    if val is None:
        return ""
    return str(val)


def _normalize_candidate_value(item, value=None):
    """Trim common scanner over-capture from query-style matches."""
    if value is None:
        v = _get_item_text(item, "value")
    else:
        v = str(value)
    v = v.strip().strip('"\'')
    if not v:
        return v

    lower_v = v.lower()
    if lower_v.endswith("&amp;"):
        return v[:-5]
    if lower_v.endswith("&amp"):
        return v[:-4]

    match_lower = _get_item_text(item, "match").lower()
    if "&" in v:
        head, tail = v.split("&", 1)
        tail_lower = tail.lower()
        if tail_lower.startswith("amp;"):
            return head
        if any(anchor in match_lower for anchor in [
            "apikey=", "api_key=", "api-key=", "key=", "token=", "authkey=",
            "rlkey=", "client_secret=", "secret_key=", "secret=", "access_token=",
        ]):
            if (
                "=" in tail or
                tail_lower.startswith((
                    "{", "lang=", "rll=", "code=", "group_code=", "noverify=",
                    "v=", "ver=", "callback=",
                ))
            ):
                return head
    return v


def _combined_item_text(item):
    parts = [
        _get_item_text(item, "rule_name"),
        _get_item_text(item, "series"),
        _get_item_text(item, "file"),
        _get_item_text(item, "match"),
        _get_item_text(item, "embedding_context"),
        _get_item_text(item, "whole_secret_value"),
    ]
    context = item.get("context", [])
    if isinstance(context, list):
        for ctx in context[:3]:
            if isinstance(ctx, dict):
                parts.extend(str(v) for v in ctx.values() if v)
    return " ".join(p for p in parts if p)


def _split_identifier_words(value):
    v = str(value or "").strip().strip('"\'').lstrip("-_")
    if not v:
        return []
    if "_" in v:
        return [p for p in re.split(r"_+", v) if p]
    return re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+", v)


def _looks_like_human_readable_identifier(value):
    v = str(value or "").strip().strip('"\'').lstrip("-_")
    if len(v) < 8 or len(v) > 80:
        return False
    if re.search(r"\d", v):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]{6,}", v):
        return True
    if re.fullmatch(r"[A-Za-z]+(?:_[A-Za-z]+)+", v):
        return True
    if re.fullmatch(r"[a-z]+(?:-[a-z]+){2,}", v):
        return True
    all_words = _split_identifier_words(v)
    if all_words and all_words[0].lower() in {
        "should", "get", "set", "use", "has", "is", "can", "enable", "disable",
        "create", "update", "remove", "delete", "handle",
    } and len(all_words) >= 3:
        return True
    words = [w for w in all_words if len(w) >= 4]
    word_chars = sum(len(w) for w in words)
    return (
        (len(words) >= 2 and word_chars >= len(v) - 2)
        or (len(words) >= 4 and word_chars >= len(v) * 0.75)
    )


def _looks_like_human_readable_slug(value):
    v = str(value or "").strip().strip('"\'').lstrip("-_")
    if len(v) < 12 or len(v) > 160:
        return False
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+){2,}", v):
        alpha_parts = [p for p in v.split("-") if re.search(r"[a-z]", p) and len(p) >= 3]
        return len(alpha_parts) >= 2
    if re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9_-]+){2,}", v):
        return True
    if re.fullmatch(r"\d{9,}-variation-\d+", v):
        return True
    if re.fullmatch(r"static-\d+\.\d+", v):
        return True
    return False


def _looks_like_frontend_artifact_value(value):
    v = str(value or "").strip().strip('"\'').lstrip("-_")
    if len(v) < 12 or len(v) > 180:
        return False
    lower_v = v.lower()
    if any(anchor in lower_v for anchor in [
        "__webpack_imported_module_",
        "webpack_imported_module",
        "_module_ts",
        "assets_src",
        "node_modules",
        "sourceMappingURL".lower(),
    ]):
        return True
    if "__" in v and any(sep in v for sep in ".-_/"):
        return True
    if re.search(r"(?:^|[-_.])(?:css|layout|button|header|footer|modal|widget|container|component|module|assets|src|helpers|utils|hooks|theme|style|chunk)(?:[-_.]|$)", lower_v):
        return True
    return False


def _looks_like_code_reference_value(value):
    v = str(value or "").strip().strip('"\'')
    if not v:
        return False
    if v.startswith(("pk.", "sk.", "SG.", "ghp_", "github_pat_", "glpat-", "AIzaSy")):
        return False
    if "__WEBPACK_IMPORTED_MODULE_" in v or "process.env." in v:
        return True
    if v.startswith((
        "$", "this.", "state.", "config.", "window.", "document.",
        "props.", "ctx.", "module.", "exports.", "process.",
    )):
        return True
    if re.search(r"[{}()\[\]]", v):
        return True
    if re.search(r"(?:=void\b|&&|\|\||=>)", v):
        return True
    if re.search(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\s*=", v):
        return True
    if re.search(r"=\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", v):
        return True
    if re.fullmatch(r"[!~+\-]*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?:[+\-*/]\d+)?;?", v):
        cleaned = v.lstrip("!~+-").rstrip(";")
        first = cleaned.split(".", 1)[0]
        segments = cleaned.split(".")
        if first in {"this", "window", "document", "state", "config", "process", "e", "t", "n", "r", "i", "u", "s", "Kt", "dt", "pt", "Ir"}:
            return True
        if any(re.search(r"[A-Z_]", segment) for segment in segments[1:]):
            return True
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", v):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]{12,160}", v) and v.count(".") >= 2 and any(ch in v for ch in "_-"):
        return True
    return False


def _obvious_noncredential_value_reason(item, var_name=""):
    value = _normalize_candidate_value(item)
    match_str = _get_item_text(item, "match")
    v = str(value or "").strip().strip('"\'')
    core = v.lstrip("-_")
    if not core:
        return "empty value"
    if _is_code_fragment(v, match_str):
        return "JavaScript/code fragment"
    if _looks_like_code_reference_value(v):
        return "code/property reference"
    if core in OBVIOUS_PLACEHOLDER_VALUES:
        return "placeholder/env-var token name"
    if re.search(
        r"(?:REPLACE_WITH|PLACEHOLDER|INTENTIONALLY_BLANK|YOUR_(?:API_)?KEY|YOUR_TOKEN|YOUR_SECRET|API_KEY_RANDOM)",
        core.upper(),
    ):
        return "placeholder/env-var token name"
    if _RE_EXPERIMENT_VARIATION.fullmatch(core):
        return "A/B experiment variation id"
    if _RE_ALL_CAPS_CONFIG_NAME.fullmatch(core):
        return "configuration constant name"
    if any(core.lower().endswith(ext) for ext in ASSET_FILE_EXTENSIONS):
        return "asset filename/module artifact"
    if _looks_like_frontend_artifact_value(core):
        return "frontend asset/module artifact"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", core):
        return "email address"
    if core.startswith("%") and (UUID_RE.search(core) or "%s" in core.lower()):
        return "format/placeholder string"
    if _looks_like_human_readable_slug(core):
        return "human-readable slug/translation key"
    if _looks_like_human_readable_identifier(core):
        return "human-readable identifier"
    if "&" in v and _is_query_fragment_like_value(item, var_name):
        return "query parameter fragment"
    return ""


def _ambiguous_rule_obvious_fp_reason(item, var_name=""):
    rule_name = _get_item_text(item, "rule_name")
    if rule_name not in AMBIGUOUS_BROAD_RULE_NAMES:
        return ""
    value = _normalize_candidate_value(item)
    core = str(value or "").strip().strip('"\'').lstrip("-_")
    reason = _obvious_noncredential_value_reason(item, var_name)
    if reason:
        return f"{rule_name} 宽规则误命中: {reason}"
    if _looks_like_frontend_artifact_value(core):
        return f"{rule_name} 宽规则误命中: frontend asset/module artifact"
    if rule_name == "Contentful API Personal Token" and re.fullmatch(r"[a-f0-9]{24}-[a-f0-9]{24}", core, re.I):
        return f"{rule_name} 宽规则误命中: content/database identifier"
    if rule_name in WORDLIKE_BROAD_RULE_NAMES and re.fullmatch(r"[A-Za-z]{8,40}", core):
        return f"{rule_name} 宽规则误命中: natural-language word"
    if rule_name == "Azure Client Secret" and (core.startswith("%") or UUID_RE.search(core)):
        return f"{rule_name} 宽规则误命中: format string / UUID label"
    return ""


def _classify_facebook_context(item, var_name=""):
    rule_name = _get_item_text(item, "rule_name").lower()
    series = _get_item_text(item, "series").lower()
    if "facebook" not in rule_name and series != "facebook":
        return None
    value = _normalize_candidate_value(item)
    text_lower = f"{var_name} {_combined_item_text(item)}".lower()
    if re.fullmatch(r"[a-f0-9]{32}", value, re.I):
        if any(anchor in text_lower for anchor in [
            "client_token", "clienttoken",
            "client_access_token", "facebook_client_token",
            "facebook_client_access_token",
        ]):
            return _classification("Potential", "refine Potential: facebook client token")
    if re.fullmatch(r"\d{15,18}", value):
        if any(anchor in text_lower for anchor in [
            "app_id", "appid", "facebook_app_id", "client_id",
        ]):
            return _classification("Potential", "refine Potential: facebook public app/entity id")
    return None


def _classify_service_specific_context(item, var_name=""):
    rule_name = _get_item_text(item, "rule_name")
    rule_lower = rule_name.lower()
    value = _normalize_candidate_value(item)
    text_lower = f"{var_name} {_combined_item_text(item)}".lower()
    core = str(value or "").strip().strip('"\'')

    if rule_name in {"RazorPay API Key", "Razorpay API Key", "razorpay-api-key"}:
        if _RE_RAZORPAY_BRAND_ASSET.fullmatch(core):
            return _classification("FalsePositive", "refine FP: Razorpay frontend brand/static asset token")

    if rule_lower == "sumologic-access-token":
        if "sumositeid" in text_lower and _RE_SUMO_SITE_ID.fullmatch(core):
            return _classification("Potential", "refine Potential: Sumo site identifier / public config token")

    if rule_lower == "dropbox-api-token":
        if any(anchor in text_lower for anchor in ["dropboxappkey", "dropbox_api_key", "dropbox api key", "dropboxapikey"]) and _RE_DROPBOX_APP_KEY.fullmatch(core):
            return _classification("Potential", "refine Potential: Dropbox app key")

    if rule_name == "Wit API Key":
        if "without hyphens" in text_lower and re.fullmatch(r"[a-f0-9]{32}", core, re.I):
            return _classification("FalsePositive", "refine FP: UUID text/example without hyphens")

    if rule_name in {"Ideogram-api-key", "Datafire API Key", "Intercom API Key"}:
        match_str = _get_item_text(item, "match")
        if (
            _looks_like_code_reference_value(core)
            or _is_code_fragment(core, match_str)
            or re.search(r'","[A-Za-z_][A-Za-z0-9_]*","', core)
            or re.search(r"</?[A-Za-z][^>]*>|HTML_TAG|</div>|class=", core)
            or re.search(r"\b(?:export const|const|let|var)\s+[A-Za-z_$]", core)
            or re.search(r"[A-Za-z_$][\w$]*\s*=\s*[A-Za-z_$][\w$]*", core)
        ):
            return _classification("FalsePositive", f"refine FP: {rule_name} code/html artifact")

    return None


def _is_code_fragment(value, match_str=""):
    text = f"{value} {match_str}"
    return any(p in text for p in [
        "${", "encodeURIComponent", "JSON.stringify", "JSON.parse",
        "function(", "=>", "...", ".concat(", "+encodeURIComponent",
        "window.", "document.", "console.log",
        "_0x", "(0x",
        "}=e.r(", "$export$", "=!1}={}",
    ])


def _is_hex_digest(value):
    return bool(HEX_DIGEST_RE.match(str(value).strip()))


def _is_md5_hash(value):
    return bool(MD5_RE.match(str(value).strip()))


def _is_sha1_hash(value):
    return bool(SHA1_RE.match(str(value).strip()))


def _is_uuid(value):
    return bool(UUID_RE.match(str(value).strip()))


def _looks_like_aws_secret(value):
    v = str(value).strip()
    if not AWS_SECRET_CHARS_RE.match(v):
        return False
    # Pure hex 40-char strings are overwhelmingly SHA-1/module hashes in this dataset.
    if _is_sha1_hash(v):
        return False
    return True


def _has_aws_context(item, var_name=""):
    text = f"{var_name} {_combined_item_text(item)}".lower()
    return any(kw in text for kw in [
        "aws_secret_access_key", "secretaccesskey", "aws_secret",
        "amazonaws", "aws-sdk", "s3.amazonaws", "access key id",
    ])


def _is_probable_hash_context(item, var_name=""):
    text = f"{var_name} {_combined_item_text(item)}".lower()
    return any(kw in text for kw in [
        ".js", ".map", ".json", "bundle", "chunk", "webpack", "vite",
        "rollup", "module", "manifest", "commit", "revision", "cache",
        "checksum", "sha1", "hash", "digest", "sentry.io",
    ])


def _is_signed_media_transform_param(item):
    text = _combined_item_text(item).lower()
    has_auth = re.search(r"(?:^|[?&\s\"'])auth=", text) is not None
    has_transform = (
        ("width=" in text or "height=" in text) and
        ("quality=" in text or "smart=true" in text or "fit=" in text)
    )
    return has_auth and has_transform


def _is_versioned_skey_param(item):
    text = _combined_item_text(item)
    return bool(SKEY_VERSION_PARAM_RE.search(text))


def _is_browser_monitoring_or_widget_token(item):
    text = _combined_item_text(item)
    text_lower = text.lower()
    value = _normalize_candidate_value(item)
    if NEW_RELIC_BROWSER_RE.search(value) or "newreliclicensekey" in text_lower:
        return "New Relic browser license key"
    if "boomr_api_key" in text_lower or "boomerang" in text_lower or "mpulse" in text_lower:
        return "Akamai mPulse browser telemetry key"
    if "ddjskey" in text_lower or ("datadog" in text_lower and any(anchor in text_lower for anchor in ["rum", "browser", "clienttoken", "client token"])):
        return "Datadog browser telemetry key"
    if "userback" in text_lower and "access_token" in text_lower:
        return "Userback widget token"
    if "optimonkclient" in text_lower or "optimonk" in text_lower:
        return "OptiMonk client configuration token"
    if "fortertoken" in text_lower:
        return "Forter anti-fraud session token"
    if "apestertoken" in text_lower:
        return "Apester widget token"
    if "contentmapid" in text_lower:
        return "content map identifier"
    if "fides_key" in text_lower:
        return "Fides privacy configuration key"
    if re.search(r"(?:^|[\"'\s,{])(?:pkey|[0-9]+-client)[\"'`]?\s*[:=]", text_lower):
        if any(anchor in text_lower for anchor in ["adthrive", "opscobid", "ad_", "advertis"]):
            return "ad/auction client identifier"
    return ""


def _is_csrf_or_state_token(item):
    text = _combined_item_text(item).lower()
    return any(anchor in text for anchor in [
        "csrf", "xsrf", "anti-forgery", "antiforgery",
        "requestverificationtoken", "__requestverificationtoken",
    ])


def _is_image_resource_key(item):
    text = _combined_item_text(item).lower()
    value = _get_item_text(item, "value").strip().strip('"\'')
    if "imagekey" not in text and "image_key" not in text:
        return False
    return bool(IMAGE_RESOURCE_KEY_RE.match(value)) or any(
        value.lower().endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg")
    )


def _is_noncredential_license_key(item):
    text = _combined_item_text(item).lower()
    value = _get_item_text(item, "value").strip().strip('"\'')
    if "licensekey" not in text and "license_key" not in text:
        return False
    if any(anchor in text for anchor in [
        "publishable", "stripe", "pk_live", "pk_test", "lobpublishable",
        "public_api_key", "publicapikey",
    ]):
        return False
    return bool(FRONTEND_LIBRARY_LICENSE_RE.match(value)) or any(anchor in text for anchor in [
        "lightgallerylicensekey", "newreliclicensekey", "frontend", "browser",
    ])


def _is_url_parameter_misparse(item):
    text = _combined_item_text(item).lower()
    return bool(re.search(r"(?:^|[?&\s\"'])api_key=maps&signature=", text))


def _maybe_base64_decode_text(value):
    v = str(value or "").strip()
    if not v or len(v) < 8:
        return ""
    # Cursor/state blobs are usually URL-safe or standard base64.
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", v):
        return ""
    try:
        pad = (-len(v)) % 4
        decoded = base64.urlsafe_b64decode(v + ("=" * pad)).decode("utf-8")
    except Exception:
        return ""
    return decoded


def _is_pagination_or_state_cursor(item, var_name=""):
    text_lower = _combined_item_text(item).lower()
    var_lower = (var_name or "").lower()
    if var_lower not in {"after_token", "before_token", "page_token", "cursor", "cursor_token"}:
        if not any(anchor in text_lower for anchor in ["after_token", "before_token", "page_token", "cursor"]):
            return False
    value = _normalize_candidate_value(item)
    decoded = _maybe_base64_decode_text(value)
    if decoded and any(anchor in decoded.lower() for anchor in ["searchdate", "cursor", "sort", "page", "uid="]):
        return True
    return len(value) >= 16


def _is_public_sdk_or_map_key(item, var_name=""):
    text_lower = _combined_item_text(item).lower()
    var_lower = (var_name or "").lower()
    value = _normalize_candidate_value(item)

    if value.startswith("pk.") and any(anchor in text_lower for anchor in ["mapbox", "vector.pbf", "tiles.mapbox", "mapbox-streets"]):
        return "Mapbox public access token"
    if value.startswith("pk_") and var_lower in {"channel-key", "channel_key"}:
        return "public channel key"
    if var_lower in {"writekey", "analyticswritekey"}:
        return "analytics write key"
    if var_lower in {"dd-api-key", "dd_client_token", "dd-client-token", "ddjskey"} and value.startswith("pub"):
        return "Datadog public client token"
    if var_lower == "clienttoken" and value.startswith("pub"):
        return "public client token"
    if var_lower in {"sdkkey", "sdk-key", "appkey", "app_key", "apikey", "api_key"} and 16 <= len(value) <= 40 and re.fullmatch(r"[A-Za-z0-9_-]+", value):
        if any(anchor in text_lower for anchor in ["sdk", "client", "browser", "frontend", ".js", ".html"]):
            return "public SDK client key"
    if var_lower in {"policykey", "brightcovepolicykey"} and len(value) >= 40:
        return "Brightcove/browser policy key"
    if var_lower in {"segmentkey", "segment_key"} and re.fullmatch(r"[A-Za-z0-9_-]{16,40}", value):
        return "analytics segment key"
    if var_lower == "clientkey" and value.startswith("sdk-"):
        return "public SDK client key"
    if var_lower in {"domain_key", "domainkey"} and re.fullmatch(r"[A-Za-z0-9_-]{20,48}", value):
        return "domain-scoped public key"
    if var_lower == "projectkey" and re.fullmatch(r"[A-Za-z0-9_-]{16,40}", value):
        return "project-scoped public key"
    if var_lower in {"readtoken", "read_token"} and re.fullmatch(r"[A-Za-z0-9]{16,32}", value):
        return "read-only content token"
    if var_lower == "preview_token" and re.fullmatch(r"[a-z0-9]{24,40}", value):
        return "preview content token"
    return ""


def _is_query_fragment_like_value(item, var_name=""):
    value = _get_item_text(item, "value")
    v = str(value or "")
    if "&" not in v:
        return False
    tail = v.split("&", 1)[1].lower()
    return any(
        tail.startswith(prefix) for prefix in (
            "id=", "expires=", "width=", "height=", "lang=", "rll=", "amp",
            "quality=", "smart=", "fit=", "group_code=", "noverify=",
        )
    )


def _is_structured_recommendation_token(item, var_name=""):
    value = _normalize_candidate_value(item)
    var_lower = (var_name or "").lower()
    if var_lower == "rectoken" and value.startswith("rt."):
        return "recommendation token"
    if var_lower == "auth_key" and _RE_TIMEBOUND_AUTH_KEY.fullmatch(value):
        return "time-bound auth key"
    return ""


def _is_short_state_or_widget_token(item, var_name=""):
    text_lower = _combined_item_text(item).lower()
    var_lower = (var_name or "").lower()
    value = _normalize_candidate_value(item)

    if var_lower in {"token", "rectoken", "contextual-token", "preview_token", "guest_token", "share_token"}:
        if "&expires=" in _get_item_text(item, "value").lower():
            return "short-lived URL token"
        if len(value) <= 24 and re.fullmatch(r"[A-Za-z0-9_-]{8,24}", value):
            return "short frontend token"
    if var_lower in {"_key", "key", "apikey", "apiKey"} and len(value) <= 16 and re.fullmatch(r"[A-Za-z0-9_-]{6,16}", value):
        return "short frontend key"
    if var_lower in {"data-token", "data-access-token"} and value.startswith("pk."):
        return "embedded public map token"
    return ""


def _is_page_data_short_key(item, var_name=""):
    file_path = _get_item_text(item, "file").lower()
    value = _normalize_candidate_value(item)
    var_lower = (var_name or "").lower()
    if not (
        "page-data" in file_path or
        "resource_manifest" in file_path or
        file_path.endswith(".json")
    ):
        return False
    if var_lower not in {"", "_key", "key"}:
        return False
    return len(value) <= 16 and re.fullmatch(r"[A-Za-z0-9_-]{6,16}", value) is not None


def _is_m3u8_auth_key(item, var_name=""):
    file_path = _get_item_text(item, "file").lower()
    value = _normalize_candidate_value(item)
    var_lower = (var_name or "").lower()
    if not file_path.endswith(".m3u8"):
        return False
    if var_lower not in {"auth_key", "key"}:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{16,80}", value))


def _has_critical_secret_anchor(item, var_name=""):
    text = f"{var_name} {_combined_item_text(item)}".lower()
    return any(anchor in text for anchor in [
        "secretkey", "secret_key", "account_secret_key", "client_secret",
        "sharedkey", "shared_key", "private_key", "privatekey",
        "password", "passwd", "credential", "signing_key",
        "encryption_key", "hmac", "aes_key",
    ])


def _has_definitive_critical_secret_anchor(item, var_name=""):
    text = f"{var_name} {_combined_item_text(item)}".lower()
    return any(anchor in text for anchor in [
        "client_secret", "clientsecret",
        "oauth_secret", "oauthsecret",
        "private_key", "privatekey",
        "encryption_secret_key", "encryptionsecretkey",
        "azpay_secret_key", "azpaysecretkey",
        "db_password", "database_password",
        "app_auth", "private_api_key",
    ])


# Public/publishable SDK key prefixes: the VALUE itself proves the credential
# is client-side and public, overriding a secret-sounding variable name.
# e.g. Statsig `statsigClientSecret: "client-..."` is a public client SDK key,
# not a server secret. The 'secret-' prefix (real Statsig server key) is NOT here.
_PUBLIC_SDK_PREFIX_RE = re.compile(
    r'^(client-|pk_live_|pk_test_|pk\.|pub-|pub_|public-|publishable[_-])',
    re.IGNORECASE,
)


def _value_has_public_sdk_prefix(value):
    return bool(_PUBLIC_SDK_PREFIX_RE.match(str(value or "").strip()))


# A value that is itself a literal HTTP-header / config-key NAME (not a secret
# value). e.g. `CF-Access-Client-Secret`, `X-Api-Key` are header names that get
# mis-extracted as the credential value. Pattern: hyphen-joined capitalized
# words ending in a credential noun, with no high-entropy random segment.
_HEADER_NAME_RE = re.compile(
    r'^(?:CF|X|HTTP|Sec)-[A-Za-z]+(?:-[A-Za-z]+)*-(?:Secret|Key|Token|Id|Auth)$',
    re.IGNORECASE,
)


def _is_header_or_config_name(value):
    v = str(value or "").strip()
    return bool(_HEADER_NAME_RE.match(v))



def _value_has_known_critical_prefix(value):
    v = str(value or "").strip()
    return v.startswith((
        "ghp_", "github_pat_", "glcbt-", "glpat-", "glptt-", "glsa_",
        "sk_live_", "rk_live_", "xoxb-", "xoxp-", "xoxs-",
    ))


def _kb_payload(kb_item):
    if not isinstance(kb_item, dict):
        return {}
    return kb_item.get("payload") or {}


def _kb_service(kb_item):
    if not isinstance(kb_item, dict):
        return ""
    payload = _kb_payload(kb_item)
    return str(kb_item.get("service") or payload.get("service") or "")


def _kb_risk_level(kb_item):
    payload = _kb_payload(kb_item)
    orig_analysis = payload.get("original_full_json", {}).get("original_analysis", {})
    return (orig_analysis.get("risk_level", "PotentialRisk") or "PotentialRisk").lower()


def _kb_override_classification(item, kb_item):
    if not isinstance(kb_item, dict):
        return None
    kid = str(kb_item.get("id") or "")
    value = _normalize_candidate_value(item)
    text_lower = _combined_item_text(item).lower()
    var_name = item.get("_var_name", "") or item.get("variable_name", "") or _extract_var_name_from_match(item) or ""
    var_lower = str(var_name or "").lower()

    if re.fullmatch(r"k\$[a-f0-9]{32}", value, re.I):
        return "FalsePositive", "KB override FP(content/hash key)"
    if re.fullmatch(r"OGY-[A-F0-9]{12}", value, re.I) and "assetkey" in text_lower:
        return "FalsePositive", "KB override FP(asset key/id)"
    if re.fullmatch(r"(?:auth-suite|auth)[-_][A-Za-z0-9_-]+", value) and "authorize" in text_lower:
        return "FalsePositive", "KB override FP(auth state constant)"
    if re.fullmatch(r"[a-z0-9.-]+\.(?:vipserver|com|net|org|io|cn|jp|fr|de|cz|hu)", value, re.I):
        return "FalsePositive", "KB override FP(host/config value)"
    if "super_socializerauth=disqus" in text_lower or "heateorslauth=disqus" in text_lower:
        return "FalsePositive", "KB override FP(social-login provider query)"
    if "buzz_key=" in text_lower and "segment_key=" in text_lower:
        return "FalsePositive", "KB override FP(analytics query fragment)"
    if re.search(r"(?:^|[?&\"'])api=0&sn=\d+&", text_lower):
        return "FalsePositive", "KB override FP(analytics query fragment)"
    if re.search(r"(?:heateorslauth|supersocializerauth)=[a-z]+&[^\"'\s]*redirect_to=", text_lower):
        return "FalsePositive", "KB override FP(social-login redirect query)"
    if re.search(r"[+][A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+[+]", value):
        return "FalsePositive", "KB override FP(code interpolation)"
    if value.startswith("+") and re.search(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", value):
        return "FalsePositive", "KB override FP(code interpolation)"
    if "cat_key=" in text_lower and "&aktcat=" in text_lower:
        return "FalsePositive", "KB override FP(category query fragment)"
    if value.lower().startswith(("license-", "prd-")) and re.fullmatch(r"[A-Za-z0-9_-]{8,32}", value):
        return "FalsePositive", "KB override FP(resource/license identifier)"

    if kid in _KB_OVERRIDE_IDS_TO_POTENTIAL:
        if "sitekey" in text_lower or "captcha" in text_lower or value.startswith("0x4AAAA"):
            return "Potential", f"KB override Potential(id={kid}, captcha/site-key)"
        return None

    if kid in _KB_OVERRIDE_MAPBOX_PUBLIC_IDS:
        if value.startswith("pk.") and ("mapbox" in text_lower or "access_token" in text_lower or "map" in text_lower):
            return "Potential", f"KB override Potential(id={kid}, public-map-token)"
        if value.startswith(("pk_live_", "pk_test_")):
            return "Potential", f"KB override Potential(id={kid}, publishable-payment-key)"
        if value.startswith("0x4AAAA"):
            return "Potential", f"KB override Potential(id={kid}, captcha/site-key)"
        return None

    # Recover a few clearly public telemetry/SDK families even if their matched KB is noisy.
    if var_lower in {"clientsdkkey", "statsig_client_sdk_key", "statsigclientkey"} or "statsig" in text_lower:
        if value.startswith(("client-", "sdk-")) and re.fullmatch(r"[A-Za-z0-9_-]{18,80}", value):
            return "Potential", "KB override Potential(statsig client sdk key)"
    if "weather" in text_lower and re.fullmatch(r"[A-Fa-f0-9]{30,32}", value):
        return "Potential", "KB override Potential(weather api key)"

    return None


def _allows_vector_critical(item, kb_item, best_score):
    value = _get_item_text(item, "value").strip().strip('"\'')
    service = _kb_service(kb_item).lower()
    var_name = item.get("_var_name", "") or item.get("variable_name", "") or _extract_var_name_from_match(item) or ""

    if _value_has_known_critical_prefix(value):
        return True
    if _has_critical_secret_anchor(item, var_name):
        return True
    if "aws" in service and _looks_like_aws_secret(value) and _has_aws_context(item, var_name):
        return True
    if best_score >= 0.92 and _looks_like_aws_secret(value) and _has_aws_context(item, var_name):
        return True
    return False


def _postprocess_vector_classification(item, kb_item, best_score, threshold=0.8):
    var_name = item.get("_var_name", "") or item.get("variable_name", "") or _extract_var_name_from_match(item) or ""
    obvious_fp_reason = _obvious_noncredential_value_reason(item, var_name)
    if obvious_fp_reason:
        return "FalsePositive", f"vector后置FP: {obvious_fp_reason}", kb_item, best_score
    if best_score < threshold or not kb_item:
        return "Potential", f"generic向量未命中(var={var_name}, score={best_score:.3f})", None, best_score

    kb_override = _kb_override_classification(item, kb_item)
    if kb_override:
        cat, reason = kb_override
        return cat, reason, kb_item, best_score

    risk_level = _kb_risk_level(kb_item)
    if risk_level in ("critical", "high", "severe"):
        if best_score >= 0.85 and _allows_vector_critical(item, kb_item, best_score):
            return "Critical", f"KB高危(risk={risk_level}, score={best_score:.3f})", kb_item, best_score
        return "Potential", f"KB高危降级(risk={risk_level}, score={best_score:.3f}, weak_critical_evidence)", kb_item, best_score
    if risk_level in ("potentialrisk", "medium", "moderate", "warning"):
        return "Potential", f"KB-Potential(risk={risk_level}, score={best_score:.3f})", kb_item, best_score
    if risk_level in ("falsepositive", "lowrisk", "safe", "low", "info"):
        return "FalsePositive", f"KB-FP(risk={risk_level}, score={best_score:.3f})", kb_item, best_score
    return "Potential", f"KB未知(risk={risk_level}, score={best_score:.3f})", kb_item, best_score


def _classification(cat, reason):
    return {
        "final_classification": cat,
        "reason": reason,
        "match_kb_details": None,
        "score": -1.0,
    }


def _should_apply_refine_override(item):
    rule_name = _get_item_text(item, "rule_name")
    is_gen_jwt, _ = _is_generic_or_jwt(rule_name)
    if is_gen_jwt:
        return True
    return rule_name in REFINE_OVERRIDE_RULE_NAMES


def _refine_rule_override(item, var_name=None):
    """
    Rules distilled from result_116/refine.

    These overrides run before broad rule/series and KB decisions so confirmed
    Critical false matches can be downgraded to Potential or FalsePositive.
    Ordering matters: explicit high-risk token formats are protected first.
    """
    rule_name = _get_item_text(item, "rule_name")
    series = _get_item_text(item, "series")
    value = _normalize_candidate_value(item)
    match_str = _get_item_text(item, "match")
    file_path = _get_item_text(item, "file")
    if var_name is None:
        var_name = item.get("variable_name", "") or _extract_var_name_from_match(item) or ""
    var_name = str(var_name or "")
    var_lower = var_name.strip().lower()
    text = _combined_item_text(item)
    text_lower = text.lower()
    rule_lower = rule_name.lower()
    series_lower = series.lower()
    context_required_name = var_lower in CONTEXT_REQUIRED_VAR_NAMES

    ambiguous_rule_fp_reason = _ambiguous_rule_obvious_fp_reason(item, var_name)
    if ambiguous_rule_fp_reason:
        return _classification("FalsePositive", f"refine FP: {ambiguous_rule_fp_reason}")

    facebook_context_result = _classify_facebook_context(item, var_name)
    if facebook_context_result:
        return facebook_context_result

    service_specific_result = _classify_service_specific_context(item, var_name)
    if service_specific_result:
        return service_specific_result

    # Recover direct secret literals that were previously suppressed by shape-only rules.
    if any(anchor in text_lower for anchor in [
        "client_secret", "app_secret_key", "encryption_secret_key", "api_secret_key", "totp_secret_key",
    ]):
        if (not _looks_like_code_reference_value(value)
                and not _is_code_fragment(value, match_str)
                and not _is_header_or_config_name(value)):
            if re.fullmatch(r"[A-Z2-7]{32}", value):
                return _classification("Critical", "refine保护: TOTP/base32 secret literal")
            if re.fullmatch(r"[A-Za-z0-9_-]{14,48}", value):
                return _classification("Critical", "refine保护: direct secret literal")

    # True-positive protection. These are only needed inside override-eligible
    # rule families so obvious true positives are not downgraded by refine rules.
    if value.startswith(("ghp_", "github_pat_")) or re.search(r"(ghp_|github_pat_)[A-Za-z0-9_]+", match_str):
        return _classification("Critical", "refine保护: GitHub token")
    if value.startswith(("glcbt-", "glpat-", "glptt-", "glsa_")):
        return _classification("Critical", "refine保护: GitLab token")
    if value.startswith("AIzaSy"):
        return _classification("Potential", "refine Potential: Google API key")
    if value.startswith(("sk_live_", "rk_live_")):
        return _classification("Critical", "refine保护: live secret/payment key")
    if value.startswith(("rzp_live_", "rzp_test_")):
        return _classification("Potential", "refine Potential: Razorpay public/live key id")
    if (rule_name == "AWS API Secret" or _has_aws_context(item, var_name)) and _looks_like_aws_secret(value):
        return _classification("Critical", "refine保护: AWS Secret Access Key format")
    # Guard: value must look like a real credential, not a JS code reference or identifier.
    # e.g. "e.options.paymentIntentSecret})" or "constructPrivateKey" are code, not secrets.
    _v_for_anchor = str(value).strip()
    _value_is_code_ref = (
        _looks_like_code_reference_value(_v_for_anchor)
        or bool(re.search(r'[{}()\[\]]', _v_for_anchor))          # JS expression chars
        or bool(re.search(r'\.[a-zA-Z_]\w*', _v_for_anchor))  # property access
        or (bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', _v_for_anchor)) and len(_v_for_anchor) < 40)  # plain identifier
    )
    if not _value_is_code_ref and not _value_has_public_sdk_prefix(_v_for_anchor) and not _is_header_or_config_name(_v_for_anchor) and _has_definitive_critical_secret_anchor(item, var_name):
        return _classification("Critical", "refine保护: definitive server-side secret anchor")

    # Confirmed no-credential patterns from iter1/iter2/iter3.
    obvious_fp_reason = _obvious_noncredential_value_reason(item, var_name)
    if obvious_fp_reason:
        return _classification("FalsePositive", f"refine FP: {obvious_fp_reason}")
    if _is_code_fragment(value, match_str):
        return _classification("FalsePositive", "refine FP: JavaScript/code fragment")
    if _is_uuid(value):
        return _classification("FalsePositive", "refine FP: UUID/GUID identifier")
    if FETCHIFY_RE.match(value):
        return _classification("FalsePositive", "refine FP: short public service token")
    if MERCHANT_KEY_PLACEHOLDER_RE.match(value):
        return _classification("FalsePositive", "refine FP: merchantKey test placeholder")
    if "public_yotpo" in text_lower or var_lower in {"yotpositekey", "yotpo_key", "public_yotpo_key"}:
        return _classification("FalsePositive", "refine FP: Yotpo public key")
    if not context_required_name and var_lower in REFINE_FP_VAR_NAMES:
        return _classification("FalsePositive", f"refine FP: known public/non-secret var={var_name}")

    if _is_signed_media_transform_param(item):
        return _classification("FalsePositive", "refine FP: signed media transform parameter")
    if _is_versioned_skey_param(item):
        return _classification("FalsePositive", "refine FP: versioned static-resource skey")
    if _is_csrf_or_state_token(item):
        return _classification("FalsePositive", "refine FP: CSRF/XSRF state token")
    if _is_pagination_or_state_cursor(item, var_name):
        return _classification("FalsePositive", "refine FP: pagination/state cursor token")
    if _is_page_data_short_key(item, var_name):
        return _classification("FalsePositive", "refine FP: page-data/resource short key")
    if _is_m3u8_auth_key(item, var_name):
        return _classification("FalsePositive", "refine FP: m3u8 media auth key")
    structured_token_reason = _is_structured_recommendation_token(item, var_name)
    if structured_token_reason == "recommendation token":
        return _classification("FalsePositive", "refine FP: recommendation token")
    if structured_token_reason == "time-bound auth key":
        return _classification("FalsePositive", "refine FP: time-bound auth key")
    public_sdk_reason = _is_public_sdk_or_map_key(item, var_name)
    if public_sdk_reason:
        return _classification("Potential", f"refine Potential: {public_sdk_reason}")
    short_token_reason = _is_short_state_or_widget_token(item, var_name)
    if short_token_reason:
        return _classification("FalsePositive", f"refine FP: {short_token_reason}")
    if _is_image_resource_key(item):
        return _classification("FalsePositive", "refine FP: image resource key")
    if _is_noncredential_license_key(item):
        return _classification("FalsePositive", "refine FP: frontend library/browser license key")
    if _is_url_parameter_misparse(item):
        return _classification("FalsePositive", "refine FP: URL parameter misparsed as api_key")
    browser_token_reason = _is_browser_monitoring_or_widget_token(item)
    if browser_token_reason:
        return _classification("FalsePositive", f"refine FP: {browser_token_reason}")

    if var_lower in {
        "writekey", "analyticswritekey", "ddjskey", "website_token",
        "optimonkclient", "altkraft_token", "altkraft_token_v3",
    }:
        return _classification("FalsePositive", f"refine FP: frontend/browser token var={var_name}")

    if var_lower in {"rlkey", "authkey", "dm_key"} and ("&" in _get_item_text(item, "value") or "&amp" in _get_item_text(item, "value").lower()):
        return _classification("FalsePositive", f"refine FP: query parameter fragment var={var_name}")
    if var_lower in {"apikey", "apiKey", "key", "_key"} and _is_query_fragment_like_value(item, var_name):
        return _classification("FalsePositive", f"refine FP: query parameter fragment var={var_name}")
    if var_lower == "auth" and _is_query_fragment_like_value(item, var_name):
        return _classification("FalsePositive", "refine FP: signed/media auth parameter fragment")
    if var_lower in {"sharedkey", "sharedKey"} and "base64" not in text_lower and len(value) >= 32 and PURE_BASE64_RE.match(value):
        return _classification("Potential", "refine Potential: shared public integration key")

    if _is_hex_digest(value):
        if _is_probable_hash_context(item, var_name) or rule_lower in {"generic-api-key", "generic-password", "aws api secret"}:
            return _classification("FalsePositive", "refine FP: hex hash/digest, not a credential")

    if "resource_manifest" in file_path.lower() and PURE_BASE64_RE.match(value):
        return _classification("FalsePositive", "refine FP: resource manifest token")

    if rule_name in {"HubSpot API Key", "hubspot-api-key"} and "hubspotformid" in text_lower:
        return _classification("FalsePositive", "refine FP: HubSpot form ID")
    if rule_name == "RazorPay API Secret" and re.match(r"^Zm[A-Za-z0-9+/=]{20,}$", value):
        return _classification("FalsePositive", "refine FP: Razorpay merchant key ID")
    if rule_name in {"Toggltrack API Key", "Hive API Key"} and re.search(r"(?:^|[\"'\s])(?:Toggle-|hivedMarker-)", match_str):
        return _classification("FalsePositive", "refine FP: CSS class name")
    if rule_lower in {"jwt", "jwt-base64"} and value.startswith("eyJhbGciOiJub25lIn0."):
        return _classification("FalsePositive", "refine FP: jwt.io none-algorithm demo token")
    if rule_name == "Uri" and "sentry.io" in text_lower:
        return _classification("FalsePositive", "refine FP: public Sentry DSN component")
    if rule_name == "Uri" and "mailto:" in text_lower:
        return _classification("FalsePositive", "refine FP: mailto/userinfo URI")

    if var_lower == "api" and re.search(r"(?:^|[?&])api=1(?:&|$)|api\.amazonaws\.com", match_str):
        return _classification("FalsePositive", "refine FP: URL api parameter")
    if (var_lower == "sitekey" or "sitekey" in text_lower) and value.startswith("6L"):
        return _classification("FalsePositive", "refine FP: reCAPTCHA site key")
    if var_lower == "unauth":
        decoded = _maybe_base64_decode_text(value)
        if decoded and "uid=" in decoded.lower():
            return _classification("FalsePositive", "refine FP: unauth state payload")

    # Downgrade from Critical to Potential when the value may be usable but
    # lacks enough service/context proof for Critical.
    if rule_name == "Zapier webhook" and value.startswith("https://hooks.zapier.com/"):
        return _classification("Potential", "refine Potential: Zapier webhook endpoint")
    if rule_name == "Uri" and re.search(r"https?://[^/\s\"']+:[^@\s\"']+@", match_str):
        return _classification("Potential", "refine Potential: URL userinfo credential requires validation")
    return None


def _is_blacklist_var_name(var_name):
    """Return True only for the current narrow safe-name / placeholder filter."""
    if not var_name:
        return False
    vn = var_name.strip()
    if not vn or len(vn) < 2:
        return False
    vn_lower = vn.lower()
    if vn_lower in CONTEXT_REQUIRED_VAR_NAMES:
        return False
    if vn_lower in REFINE_FP_VAR_NAMES or vn_lower in DIRECT_FP_PLACEHOLDER_NAMES:
        return True
    for prefix in DIRECT_FP_PLACEHOLDER_PREFIXES:
        if vn_lower.startswith(prefix):
            return True
    return False


# =============================================================================
# JWT 解析逻辑
# =============================================================================
def _parse_jwt_payload(value):
    """解析 JWT token，返回 (header, payload, error)"""
    parts = value.strip().split('.')
    if len(parts) != 3:
        return None, None, "Not a valid JWT (expected 3 parts)"
    try:
        payload_b64 = parts[1].replace('-', '+').replace('_', '/')
        padding = 4 - len(payload_b64) % 4
        if padding < 4:
            payload_b64 += '=' * padding
        payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
    except Exception as e:
        return None, None, f"Failed to decode JWT payload: {e}"
    try:
        header_b64 = parts[0].replace('-', '+').replace('_', '/')
        padding = 4 - len(header_b64) % 4
        if padding < 4:
            header_b64 += '=' * padding
        header = json.loads(base64.b64decode(header_b64).decode('utf-8'))
    except:
        header = {}
    return header, payload, None


def _classify_jwt(value):
    """分析 JWT 内容，判断风险等级"""
    header, payload, err = _parse_jwt_payload(value)
    if err:
        return "Potential", f"JWT解析失败({err})"
    alg = (header.get('alg', 'none') or 'none').upper()
    # alg=none 直接 Critical
    if alg == 'NONE':
        return "Critical", "alg=none (无签名, JWT极易被伪造)"
    # HS256+secret 字段
    if alg in ('HS256', 'HS384', 'HS512'):
        if any(k in json.dumps(payload).lower() for k in ['secret', 'password', 'pwd', 'credential']):
            return "Critical", f"HS alg + secret字段 (服务端共享密钥泄露风险)"
    # 高危 iss
    iss = payload.get('iss', '') or ''
    if any(iss.lower().startswith(p) or iss.lower() == p for p in [p.lower() for p in JWT_CRITICAL_ISSUERS]):
        return "Critical", f"iss={iss} (已知高危平台)"
    # 高危 app_id/client_id
    for pid_key in ['app_id', 'client_id', 'azp', 'clientId']:
        pid_val = payload.get(pid_key, '')
        if pid_val:
            pid_lower = str(pid_val).lower()
            for pattern in JWT_CRITICAL_APP_ID_PATTERNS:
                if pid_lower.startswith(pattern):
                    return "Critical", f"{pid_key}={pid_val} (已知高危客户端)"
    # 高危 scope/role
    scopes = payload.get('scope', '') or payload.get('scopes', '') or ''
    roles = payload.get('role', '') or payload.get('roles', '') or payload.get('permissions', '') or ''
    if scopes or roles:
        scope_str = (str(scopes) + str(roles)).lower()
        if any(kw in scope_str for kw in ['admin', 'root', 'superuser', 'write', 'delete', 'manage']):
            return "Critical", f"高危scope/role: {roles or scopes}"
    # 检查 exp
    exp = payload.get('exp')
    if exp:
        try:
            import time as _time
            if exp < _time.time():
                return "Potential", f"JWT已过期(exp={exp})"
            if exp - _time.time() > 7 * 24 * 3600:
                return "Potential", f"JWT过期时间过长(exp={exp})"
        except:
            pass
    # 敏感字段
    sensitive = []
    for claim_key in payload:
        if claim_key.lower() in JWT_CRITICAL_CLAIMS and payload[claim_key]:
            sensitive.append(f"{claim_key}={str(payload[claim_key])[:20]}")
    if sensitive:
        return "Potential", f"含敏感字段: {', '.join(sensitive[:3])}"
    return "Potential", f"JWT默认处理(alg={alg})"


# =============================================================================
# 核心分类函数
# =============================================================================
def _classify_item(item):
    """
    单条数据分类主逻辑
    返回: {
        "final_classification": "Critical" | "Potential" | "FalsePositive" | "PendingVector" | "Unmatched",
        "reason": str,
        "match_kb_details": None,
        "score": -1.0,
    }
    """
    rule_name = item.get('rule_name', '')
    series = item.get('series', '')
    value = item.get('value', '') or ''
    var_name = item.get('variable_name', '')
    if not var_name or var_name == 'N/A' or var_name.strip() == '':
        var_name = _extract_var_name_from_match(item) or ''

    if _should_apply_refine_override(item):
        refine_result = _refine_rule_override(item, var_name)
        if refine_result:
            return refine_result

    facebook_context_result = _classify_facebook_context(item, var_name)
    if facebook_context_result:
        return facebook_context_result

    service_specific_result = _classify_service_specific_context(item, var_name)
    if service_specific_result:
        return service_specific_result

    ambiguous_rule_fp_reason = _ambiguous_rule_obvious_fp_reason(item, var_name)
    if ambiguous_rule_fp_reason:
        return {"final_classification": "FalsePositive", "reason": ambiguous_rule_fp_reason, "match_kb_details": None, "score": -1.0}

    # Step 1: Rule_name 显式覆盖优先，避免 public token 被 series 误判为 Critical
    if rule_name in LOW_RISK_RULES:
        return {"final_classification": "Potential", "reason": f"rule_name={rule_name} (低危)", "match_kb_details": None, "score": -1.0}
    if rule_name in CRITICAL_RULES:
        return {"final_classification": "Critical", "reason": f"rule_name={rule_name} (高危)", "match_kb_details": None, "score": -1.0}

    # Step 1: Series 分流
    if series in CRITICAL_SERIES:
        return {"final_classification": "Critical", "reason": f"series={series}", "match_kb_details": None, "score": -1.0}
    if series in POTENTIAL_SERIES:
        return {"final_classification": "Potential", "reason": f"series={series} (前端公开)", "match_kb_details": None, "score": -1.0}

    # Uri/URL 自身并不是稳定高危规则，未命中特定 refine 保护时继续交给上下文层
    if rule_name in {"Uri", "URL"}:
        return {
            "final_classification": "PendingVector",
            "reason": f"rule_name={rule_name} (待上下文分析)",
            "match_kb_details": None,
            "score": -1.0,
            "_var_name": var_name,
        }

    # Step 1: generic / jwt 走向量分析
    is_gen_jwt, gen_type = _is_generic_or_jwt(rule_name)
    if not is_gen_jwt:
        return {"final_classification": "Unmatched", "reason": f"rule_name={rule_name} 未分类", "match_kb_details": None, "score": -1.0}

    # JWT 类型 - Step 3: 解析字段内容
    if gen_type == "jwt":
        classification, reason = _classify_jwt(value)
        return {"final_classification": classification, "reason": f"jwt: {reason}", "match_kb_details": None, "score": -1.0}

    # generic 类型 - Step 2: 当前生效的窄范围安全名/占位符过滤
    if _is_blacklist_var_name(var_name):
        return {"final_classification": "FalsePositive", "reason": f"generic安全名/占位符命中: {var_name}", "match_kb_details": None, "score": -1.0}

    # generic 类型 - Step 3: 向量分析
    return {
        "final_classification": "PendingVector",
        "reason": f"generic待向量分析: var_name={var_name}",
        "match_kb_details": None,
        "score": -1.0,
        "_var_name": var_name,
    }


# =============================================================================
# 向量分析
# =============================================================================
_normalized_vectors = None

def _normalize_vectors(vectors):
    vectors = np.array(vectors, dtype=np.float32)
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1, norms)
    return vectors / norms


_embed_model = None
_embed_model_lock = None


def _ensure_embed_model():
    global _embed_model
    if _embed_model is None:
        import threading
        global _embed_model_lock
        if _embed_model_lock is None:
            _embed_model_lock = threading.Lock()
        with _embed_model_lock:
            if _embed_model is None:
                print(f"[向量模型] 加载: {LOCAL_EMBEDDING_MODEL} on {LOCAL_DEVICE}")
                _embed_model = SentenceTransformer(
                    LOCAL_EMBEDDING_MODEL, device=LOCAL_DEVICE,
                    trust_remote_code=True, use_auth_token=False,
                    model_kwargs={"default_task": "retrieval"},
                )
                print(f"[向量模型] 完成: {torch.cuda.get_device_name(0)}")


def _describe_string(s):
    import string
    from collections import Counter
    PREFIXES = [
        "AGE-SECRET-KEY-1","AIDA","AIPA","AIza","AKIA","AGPA","ANPA","ANVA","AM_",
        "API_KEY","AQVN","AROA","ASIA","BBFF-",
        "BUNDLE_ENTERPRISE__CONTRIBSYS__COM","BUNDLE_GEMS__CONTRIBSYS__COM",
        "CLOJARS_","EAACEdEose0cBA","EZAK","EZTK",
        "FLWPUBK_TEST-","FLWSECK","FLWSECK_TEST-",
        "GR1348941","NF-","NRAK-","NRJS-","PMAK-",
        "SG.","SK","YC",
        "access-development-","access-production-","access-sandbox-",
        "access_token$production$", "aio_","amzn.mws.","api_","api_org_","apify_api_",
        "authress_","b_","dapi","dnkey-","doo_v1_","dop_v1_","dor_v1_",
        "dp.pt.","dt0c01.","duffel_live_","duffel_test_","ext_","ey",
        "fio-u-","flb_live_",
        "gho_","ghp_","ghr_","ghs_","ghu_","github_pat_",
        "glc_","glpat-","glptt-","glsa_",
        "hf_","hvb.","hvs.","ico-","idg","jina_","k_",
        "key","key-","lin_api_","live_","npm_","nvapi-",
        "phc_","pk.","pk_","pk_live_","pk_test_","pnu_","pplx_",
        "pscale_oauth_","pscale_pw_","pscale_tkn_",
        "pubkey-","pul-","p8e-","pypi-","rdme_","rk_live_",
        "rubygems_","rzp_","sc_","scauth_","secret_",
        "shippo_live_","shippo_test_",
        "shpat_","shpca_","shppa_","shpss_",
        "sk","sk-","sk.","sk_","sk_live_","sk_test_",
        "sq0atp-","sq0csp-","sq0idp-",
        "t1.","tfp_","tk-us-","web_",
        "xai-","xapp-","xkeysib-",
        "xoxa","xoxb-","xoxe","xoxp","xoxr","xoxs"
    ]
    CHAR_GROUPS = {
        "LowerAlpha": set(string.ascii_lowercase),
        "UpperAlpha": set(string.ascii_uppercase),
        "Digit": set(string.digits),
        "_": {"_"}, "-": {"-"}, "+": {"+"}, "/": {"/"}, "=": {"="}, ".": {"."}, "@": {"@"},
    }
    s = str(s).strip()
    result = {"length": len(s)}
    prefix = next((p for p in PREFIXES if s.startswith(p)), None)
    if prefix:
        result["prefix"] = prefix
    counts = Counter()
    for ch in s:
        for name, group in CHAR_GROUPS.items():
            if ch in group:
                counts[name] += 1
                break
    charset = " + ".join([k for k, v in counts.items() if v > 0])
    if charset:
        result["charset"] = charset
    return result


def _build_embedding_context(item):
    """构建 embedding 上下文字符串"""
    enriched_ec = item.get('embedding_context', '')
    if enriched_ec and len(enriched_ec.strip()) > 10:
        return enriched_ec
    # v4_fp.json 格式兼容：key_name 在 _iter1.key_name，value 在 original_item 中
    _iter1 = item.get('_iter1', {})
    _orig = item.get('original_item', {})
    if _iter1 and _orig:
        # v4_fp.json 格式：var_name 从 _iter1.key_name 取，value/context 从 original_item 取
        var_name_from_iter = _iter1.get('key_name', '') or ''
        if var_name_from_iter and var_name_from_iter != 'N/A':
            var_name = var_name_from_iter
        else:
            var_name = _orig.get('variable_name', '') or var_name_from_iter
        value = _orig.get('value', '') or item.get('value', '')
        embedding_context = item.get('embedding_context', '') or _orig.get('embedding_context', '')
        prefix = item.get('prefix', '') or _orig.get('prefix', '')
        rule_name = item.get('rule_name', '') or _orig.get('rule_name', item.get('rule_name', ''))
        series = item.get('series', '') or _orig.get('series', '')
        match_str = item.get('match', '') or _orig.get('match', '') or ''
        context_list = item.get('context', []) or _orig.get('context', [])
    else:
        var_name = item.get('variable_name', '') or ''
        value = item.get('value', '')
        embedding_context = item.get('embedding_context', '')
        prefix = item.get('prefix', '')
        rule_name = item.get('rule_name', '')
        series = item.get('series', '')
        match_str = item.get('match', '') or ''
        context_list = item.get('context', [])
    if (not var_name or var_name == 'N/A' or var_name.strip() == '') and match_str:
        extracted = _extract_var_name_from_match(item)
        if extracted:
            var_name = extracted
    if not var_name or var_name == 'N/A' or var_name.strip() == '':
        var_name = prefix or 'Unknown'
    desc = _describe_string(value)
    value_preview = value[:64] + '...' if len(value) > 64 else value
    charset = desc.get('charset', 'N/A')
    length = desc.get('length', 'N/A')
    prefix_desc = desc.get('prefix', 'N/A')
    context_detail = ""
    if isinstance(context_list, list) and len(context_list) > 0:
        ctx_parts = []
        for ctx in context_list[:3]:
            if isinstance(ctx, dict):
                for key in ['path', 'snippet', 'tag', 'type', 'scope']:
                    if key in ctx and ctx[key]:
                        val_str = str(ctx[key])
                        if len(val_str) > 100:
                            val_str = val_str[:100] + "..."
                        ctx_parts.append(f"{key}:{val_str}")
                        break
        if ctx_parts:
            context_detail = ", ".join(ctx_parts[:3])
    semantic_sig = ""
    if rule_name == "Private Key" or value.startswith("-----BEGIN PRIVATE KEY-----") or value.startswith("-----BEGIN RSA PRIVATE KEY-----"):
        semantic_sig = "Semantic Signature: PKCS#8 or RSA/DSA/EC Private Key in PEM format. Critical: private keys can be used for cryptographic signing, authentication."
    elif "smtp://" in match_str.lower():
        semantic_sig = "Semantic Signature: SMTP credential in URL smtp://user:password@host:port. Critical: SMTP credentials grant access to send emails."
    elif rule_name in ("Uri", "URL") and ("github" in match_str.lower() or "ghp_" in value):
        semantic_sig = "Semantic Signature: GitHub Personal Access Token (ghp_) in URL. Critical: GitHub PAT grants repository access."
    elif rule_name in ("AWS API Secret", "AWS") or (
        len(value) == 40 and
        any(c in '+=/' for c in value) and  # 必须含 base64 特殊字符，区分纯 hex / 纯数字
        all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value)
    ):
        semantic_sig = "Semantic Signature: AWS Secret Access Key. Critical: AWS API credentials grant cloud infrastructure access."
    elif value.startswith("glpat-") or value.startswith("glcbt-"):
        semantic_sig = "Semantic Signature: GitLab Token (glpat- or glcbt-). Critical: GitLab tokens grant repository and CI/CD access."
    elif value.startswith("ghp_"):
        semantic_sig = "Semantic Signature: GitHub Personal Access Token (ghp_). Critical: GitHub PAT grants repository access."
    elif value.startswith("rzp_live_") or value.startswith("rzp_test_"):
        semantic_sig = "Semantic Signature: Razorpay API Key (rzp_live_ or rzp_test_). Critical: payment gateway API credentials."
    embedding_parts = [
        f"Variable Name: {var_name}",
        f"Features - Length: {length}, Charset: {charset}, prefix: {prefix_desc}",
        semantic_sig if semantic_sig else None,
        f"context: [{context_detail}]" if context_detail else None,
        f"value: {value_preview}" if value_preview else None,
        f"Series: {series}",
        f"Service: {rule_name}",
    ]
    return ". ".join([p for p in embedding_parts if p])


def _classify_by_vector(item, kb_vectors, kb_items, threshold=0.8):
    """generic 类型的向量分析"""
    query_vec = item.get('_query_vec')
    var_name = item.get('_var_name', '') or item.get('variable_name', '')
    if _should_apply_refine_override(item):
        refine_result = _refine_rule_override(item, var_name)
        if refine_result:
            return refine_result["final_classification"], refine_result["reason"], None, refine_result["score"]
    kb_len = len(kb_vectors) if kb_vectors is not None else 0
    if query_vec is None or kb_len == 0:
        return "Potential", f"generic无向量匹配(var={var_name})", None, -1.0
    try:
        query_np = np.array([query_vec], dtype=np.float32)
        norms = np.linalg.norm(query_np)
        if norms > 0:
            query_np = query_np / norms
        scores = np.dot(kb_vectors, query_np.T).flatten()
        best_idx = int(np.argmax(scores))
        best_score = float(scores[best_idx])
    except:
        return "Potential", f"generic向量计算失败", None, -1.0
    if best_score < threshold or best_idx >= len(kb_items):
        return "Potential", f"generic向量未命中(var={var_name}, score={best_score:.3f})", None, best_score
    kb_item = kb_items[best_idx]
    return _postprocess_vector_classification(item, kb_item, best_score, threshold)


# =============================================================================
# 主调用函数
# =============================================================================
def batch_classify_risks(
    data_list,
    kb_data,
    api_key=None,
    base_url=None,
    model_name=None,
    similarity_threshold=0.8,
    max_workers=None
):
    """
    执行批量风险分类 - 重写版
    Step 1: Series + Rule_name 初分类
    Step 2: generic 窄范围安全名/占位符过滤 (直接 FP)
    Step 3: generic/jwt 向量分析
    """
    res_critical = []
    res_potential = []
    res_false_positive = []
    res_unmatched = []

    if not data_list:
        return res_critical, res_potential, res_false_positive, res_unmatched

    if max_workers is None:
        max_workers = 30

    total = len(data_list)
    print(f"🚀 Batch classify (重写版): {total:,} items, threshold={similarity_threshold}")

    # Step 1: 初分类
    print("📋 Step 1: Rule-based 初分类...")
    t0 = time.time()
    step1_critical = []
    step1_potential = []
    step1_fp = []
    need_vector = []

    for item in data_list:
        result = _classify_item(item)
        cat = result["final_classification"]
        item["_classify_result"] = result
        if cat == "Critical":
            step1_critical.append(item)
        elif cat == "Potential":
            step1_potential.append(item)
        elif cat == "FalsePositive":
            step1_fp.append(item)
        elif cat == "PendingVector":
            need_vector.append(item)
        else:
            res_unmatched.append(item)

    print(f"   Step 1: C={len(step1_critical)}, P={len(step1_potential)}, FP={len(step1_fp)}, 向量={len(need_vector)}, 无分类={len(res_unmatched)}")

    # Step 3: 向量分析 (仅 generic 待分析项)
    if need_vector:
        kb_vectors_list = []
        kb_items_list = []
        for kb_item in kb_data:
            vec = kb_item.get('vector')
            if vec:
                kb_vectors_list.append(vec)
                kb_items_list.append(kb_item)

        if kb_vectors_list:
            print(f"📦 Preparing KB vectors: {len(kb_vectors_list)} entries...")
            kb_vectors_np = np.array(kb_vectors_list, dtype=np.float32)
            kb_vectors_np = _normalize_vectors(kb_vectors_np)
        else:
            kb_vectors_np = None
            kb_items_list = []

        _ensure_embed_model()
        print(f"🔮 Generating embeddings for {len(need_vector)} items...")
        t_emb = time.time()
        embedding_contexts = [_build_embedding_context(item) for item in need_vector]
        clean_texts = [ec.replace("\n", " ")[:8192] for ec in embedding_contexts]
        all_embeddings = []
        for i in range(0, len(need_vector), EMBED_BATCH_SIZE):
            batch_texts = clean_texts[i:i+EMBED_BATCH_SIZE]
            vecs = _embed_model.encode(
                batch_texts,
                normalize_embeddings=True,
                show_progress_bar=False,
                task="retrieval",
            )
            all_embeddings.extend(vecs.tolist())
        for i, emb in enumerate(all_embeddings):
            need_vector[i]["_query_vec"] = emb
        print(f"   Embedding 完成: {time.time()-t_emb:.1f}s")

        print(f"🔍 向量分析中 ({len(need_vector)} items)...")
        t_vec = time.time()
        pending_results = [None] * len(need_vector)
        done_count = 0

        def _process_vector(idx_item):
            idx, item = idx_item
            try:
                cat, reason, kb_item, score = _classify_by_vector(item, kb_vectors_np, kb_items_list, similarity_threshold)
                return idx, {
                    "final_classification": cat,
                    "reason": reason,
                    "match_kb_details": kb_item,
                    "score": score,
                    "original_item": item,
                }
            except Exception as e:
                return idx, {
                    "final_classification": "Potential",
                    "reason": f"向量分析异常: {e}",
                    "match_kb_details": None,
                    "score": -1.0,
                    "original_item": item,
                }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_process_vector, (idx, item)): idx for idx, item in enumerate(need_vector)}
            for future in tqdm(as_completed(futures), total=len(need_vector), desc="  Vector Analysis"):
                idx, pr = future.result()
                pending_results[idx] = pr
                done_count += 1
                if done_count % 10000 == 0:
                    print(f"   进度: {done_count:,}/{len(need_vector):,}")

        print(f"   向量分析完成: {time.time()-t_vec:.1f}s")

        for pr in pending_results:
            if pr is None:
                res_unmatched.append(pr)
                continue
            cat = pr["final_classification"]
            if cat == "Critical":
                res_critical.append(pr)
            elif cat == "Potential":
                res_potential.append(pr)
            elif cat == "FalsePositive":
                res_false_positive.append(pr)
            else:
                res_unmatched.append(pr)

    # 合并 Step 1 结果
    for item in step1_critical:
        res_critical.append({
            "final_classification": "Critical",
            "reason": item["_classify_result"]["reason"],
            "match_kb_details": None,
            "score": -1.0,
            "original_item": item,
        })
    for item in step1_potential:
        res_potential.append({
            "final_classification": "Potential",
            "reason": item["_classify_result"]["reason"],
            "match_kb_details": None,
            "score": -1.0,
            "original_item": item,
        })
    for item in step1_fp:
        res_false_positive.append({
            "final_classification": "FalsePositive",
            "reason": item["_classify_result"]["reason"],
            "match_kb_details": None,
            "score": -1.0,
            "original_item": item,
        })

    print(f"   ✅ 总计: Critical={len(res_critical)}, Potential={len(res_potential)}, FP={len(res_false_positive)}, Unmatched={len(res_unmatched)}")
    print(f"   Step 1+向量总耗时: {time.time()-t0:.1f}s")

    return res_critical, res_potential, res_false_positive, res_unmatched


# ====== 调用示例 ======
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    KB_FILE = "<RAG_ROOT>/db/kb_vectors_jina2048.jsonl"
    INPUT_FILE = "<DETECT_ROOT>/states/result_88/filtered_results.json"
    print("Loading KB...")
    kb_data = []
    if os.path.exists(KB_FILE):
        with open(KB_FILE) as f:
            for line in f:
                if line.strip():
                    kb_data.append(json.loads(line))
    print(f"KB: {len(kb_data)} entries")
    if os.path.exists(INPUT_FILE):
        with open(INPUT_FILE) as f:
            data_list = json.load(f)[:10]
    else:
        data_list = []
    print(f"Input: {len(data_list)} items")
    c, p, fp, u = batch_classify_risks(data_list, kb_data)
    print(f"Critical={len(c)}, Potential={len(p)}, FP={len(fp)}, Unmatched={len(u)}")
