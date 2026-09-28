"""
风险分类器 risk_classifier.py
将每条扫描命中 (hit_dict 条目) 分类为:
  Critical       - 后端高危泄露，需告警
  Potential      - 前端公开/低危误报
  FalsePositive  - 明确误报（占位符等）

分类逻辑:
  Step 1: 非 generic/jwt → rule_name 命中 Potential 列表 → Potential；其余 → Critical
  Step 2: generic/jwt   → 变量名黑名单三分类（FP / Critical / 模糊）
  Step 3: 模糊变量名     → 向量分析（与知识库相似度匹配）
  改进: Uri 误报过滤、GCP/Stripe 等高危格式兜底检测、黑名单联合 value 判断
"""

from __future__ import annotations

import base64
import json
import re
import time
import math
import os
import numpy as np
from html import unescape as html_unescape
from typing import Any, Dict, List, Optional

from dataclasses import dataclass
from base_func import multi_unescape


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class RiskResult:
    risk: str     # Critical / Potential / FalsePositive
    reason: str   # 分类原因
    var_name: str = ""


_GENERIC_VAR_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_OBVIOUS_NON_SECRET_VALUE_PATTERNS = (
    re.compile(r"^\)\.concat\(", re.I),
    re.compile(r"^\+?encodeURIComponent\(", re.I),
    re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\([^)]*\)$", re.I),
)
_IGNORED_VAR_TOKENS = frozenset({
    "const", "let", "var", "return", "true", "false", "null", "undefined",
    "concat", "encodeuricomponent", "decodeuricomponent", "window", "document",
})


def _decode_text(text: Any) -> str:
    """统一处理 unicode/html 转义，避免 prefix/match 中的转义影响变量名提取。"""
    if text is None:
        return ""
    decoded = str(text)
    try:
        decoded = multi_unescape(decoded)
    except Exception:
        pass
    return html_unescape(decoded)


def _normalize_var_name(name: Any) -> str:
    """将变量名规整为 snake_case，统一处理 camelCase / kebab-case / HTML 转义。"""
    normalized = _decode_text(name).strip()
    if not normalized:
        return ""
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized)
    normalized = normalized.replace("-", "_").replace(".", "_")
    normalized = re.sub(r"[^A-Za-z0-9_]+", "_", normalized)
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized.lower()


def _extract_var_name_from_match(match_text: str, value: str) -> str:
    """
    当 prefix 丢失时，从原始 match 中反推变量名。
    例:
      apiKey: "xxx"           -> api_key
      SESSION_TOKEN=xxx;      -> session_token
      contentMapId":"xxx"     -> content_map_id
    """
    text = _decode_text(match_text)
    if not text:
        return ""

    if value:
        idx = text.find(value)
        if idx != -1:
            text = text[:idx]

    candidates = _GENERIC_VAR_TOKEN_RE.findall(text)
    for token in reversed(candidates):
        normalized = _normalize_var_name(token)
        if normalized and normalized not in _IGNORED_VAR_TOKENS:
            return normalized
    return ""


def _is_obvious_non_secret_value(value: str) -> bool:
    """明显不是密钥的 JS/模板代码片段，直接过滤。"""
    if not value:
        return True
    value = value.strip()
    if len(value) <= 2:
        return True
    return any(pattern.match(value) for pattern in _OBVIOUS_NON_SECRET_VALUE_PATTERNS)


# ============================================================================
# Step 1: Potential 列表（不含 Secret 的公开类型 rule_name）
# ============================================================================
POTENTIAL_RULES: frozenset = frozenset({
    "Algolia API", "algolia-api-key",
    "Mapbox API Key", "mapbox-api-token",
    "LocationIQ API Key",
    "Contentful Delivery API Token", "contentful-delivery-api-token",
    "lob-pub-api-key",
    "mailgun-pub-key",
    "new-relic-browser-api-token",
    "GeoApify API Key", "Geoipifi API Key", "GetGeoA API Key",
    "Geocode API Key", "GeocodeIO API Key", "Geocodify API Key",
    "Stripe_Standard API Key", "Flutterwave API Key", "flutterwave-public-key",
    "RazorPay API Key", "Paymongo API Key", "Paystack API Key",
    "PayPal Braintree_Access Token",
    "Facebook OAuth ID", "Facebook_Access Token",
    "Google_YouTube_API key", "Google_YouTube_OAuth ID",
    "Twitter API Key", "Twitter Access Token", "Twitter Bearer Token",
    "twitter-access-token", "twitter-api-key", "twitter-bearer-token",
    "Discord API Token", "Discord Web Hook", "discord-api-token",
    "Twitch API Key", "twitch-api-token",
    "telegram-bot-api-token", "Telegram API Token",
    "Flickr API Key", "flickr-access-token",
    "Pixabay API Key", "Unsplash API Key", "Disqus API Key",
    "PubnubPublish Key", "Pubnub Subscription Key",
    "Sendbird API Key", "Sendbird Organizational API Key",
    "sendbird-access-token",
    "Agora API", "MUX API Key",
    "Plaid API Key", "plaid-api-token",
    "Square_Access Token", "square-access-token",
    "shopify-access-token", "shopify-custom-access-token", "shopify-private-app-access-token",
    "Lob API Key", "lob-api-key",
    "Okta API Domain URL", "okta-access-token",
    "Auth0 Domain URL", "Azure Key ID",
    "ImageKit API Key", "Uploadcare API Key",
    "Zendesk API Token", "FreshDesk API Key",
})


# ============================================================================
# 前端公开 key / client-side token 过滤
# ============================================================================
# 这些值通常设计为公开暴露在浏览器侧，默认按 FalsePositive 处理。
# 例外：AIza... 按用户要求保留为 Potential 待人工验证。
FRONTEND_PUBLIC_RULES: frozenset = frozenset({
    "Algolia API", "algolia-api-key",
    "Mapbox API Key", "mapbox-api-token",
    "LocationIQ API Key",
    "Contentful Delivery API Token", "contentful-delivery-api-token",
    "lob-pub-api-key",
    "mailgun-pub-key",
    "new-relic-browser-api-token",
    "GeoApify API Key", "Geoipifi API Key", "GetGeoA API Key",
    "Geocode API Key", "GeocodeIO API Key", "Geocodify API Key",
    "Stripe_Standard API Key", "Flutterwave API Key", "flutterwave-public-key",
    "RazorPay API Key", "Paymongo API Key", "Paystack API Key",
    "Posthog API Key",
    "launchdarkly-access-token",
    "Facebook OAuth ID",
    "Google_YouTube_OAuth ID",
})

FRONTEND_PUBLIC_VALUE_PATTERNS: list = [
    (r'^pk_live_[A-Za-z0-9]{16,128}$', "Stripe Publishable Key (pk_live_)"),
    (r'^pk_test_[A-Za-z0-9]{16,128}$', "Stripe Test Publishable Key (pk_test_)"),
    (r'^pk\.[A-Za-z0-9]{60,}$', "Mapbox Public Token"),
    (r'^sdk-[A-Za-z0-9-]{10,}$', "LaunchDarkly Client-side SDK Key"),
    (r'^phc_[A-Za-z0-9]{20,}$', "PostHog Project API Key"),
]

FRONTEND_PUBLIC_VAR_TOKENS: frozenset = frozenset({
    "public", "publishable", "browser", "client", "frontend", "front_end",
    "sdk", "search_only", "searchonly", "readonly", "read_only",
})


# ============================================================================
# Step 2: generic/jwt 变量名黑名单
# ============================================================================

# 明确无害 → FalsePositive（占位符/测试变量）
# 注: request_headers/authorization_header/base64_encode 等保留在黑名单
# 因为这些变量名本身强烈暗示非真实密钥环境
BLACKLIST_FP_VAR_NAMES: frozenset = frozenset(_normalize_var_name(name) for name in {
    # 通用占位符
    "placeholder", "placeholder_key", "placeholder_api_key",
    "placeholder_token", "placeholder_password",
    "example", "example_key", "example_token", "example_api_key", "example_secret",
    "demo", "demo_key", "demo_token", "demo_api_key", "demo_secret",
    "test", "test_key", "test_token", "test_api_key", "test_secret",
    "testing", "testing_key", "testing_token",
    "foo", "bar", "foobar",
    "changeme", "change_me", "changeit", "default", "default_key", "default_token",
    "sample", "sample_key", "sample_token", "sample_secret",
    "dummy", "dummy_key", "dummy_token", "dummy_secret",
    "fake", "fake_key", "fake_token", "fake_api_key",
    "mock", "mock_key", "mock_token",
    "temp", "temp_key", "temp_token", "tmp_key", "tmp_token",
    "xxx", "xxxx", "xxxxxxxx", "xxxxxxxxxxxxxxxx",
    # 开发者提示占位符
    "insert_your_key_here", "your_key_here",
    "api_key_here", "token_here", "key_here",
    "your_api_key", "your_token", "your_secret_key",
    "REPLACE_ME", "REPLACE_WITH_KEY", "REPLACE_WITH_YOUR_KEY",
    "YOUR_API_KEY", "YOUR_SECRET_KEY", "YOUR_TOKEN",
    "your_client_id", "your_client_secret",
    "your_access_token", "your_password",
    # 通用程序变量名（非真实密钥）- 仅保留明确无害的占位符变量
    # 已移除过于宽泛的词: key, token, secret, password
    # 已移除: api_key, access_token, auth_token (真实代码中常见)
    # 已移除: api_key_var, token_var, secret_var
    # 已移除: get_api_key, api_key_from_env, env_api_key
    # 以下保留（用户要求，这些变量名本身暗示非真实密钥环境）
    "request_headers", "authorization_header",
    "base64_encode", "base64_decode",
    "func_result", "result_key",
    # 代码片段相关
    "rb_sym2str", "evp_pkey_dup", "rstring_len",
    "getenv", "os.environ",
})

# 明确危害 → Critical（生产/高危密钥特征）
BLACKLIST_CRITICAL_VAR_NAMES: frozenset = frozenset(_normalize_var_name(name) for name in {
    "production", "production_key", "production_api_key",
    "production_secret", "production_token", "prod_key",
    "live", "live_key", "live_secret", "live_token",
    "master", "master_key", "master_secret", "master_token",
    "main", "main_key", "main_secret", "main_token",
    "admin", "admin_key", "admin_secret", "admin_token", "admin_api_key",
    "root", "root_key", "root_token",
    "super", "super_key", "super_secret",
    "owner", "owner_key", "owner_token",
    "prod", "prod_key", "prod_secret", "prod_token",
    "staging", "staging_key", "staging_secret",
    "real", "real_key", "real_secret",
    "primary", "primary_key", "primary_secret",
    "private_key", "private_token", "private_secret",
    "secret_key", "secret_token", "secret_api_key",
})


# ============================================================================
# Step 3: 高危格式模式兜底检测（改进2/改进10）
# ============================================================================
# 在向量分析前，先检测已知的高危服务格式，避免 KB 未知时的漏报
# 优先级从高到低，前两个返回 Critical，Stripe 返回 Potential（不降为 FP）

HIGH_RISK_SERVICE_PATTERNS: list = [
    # GCP — 按用户要求降为 Potential，待人工确认 referrer / API 限制
    (r'^AIza[0-9A-Za-z\-_]{20,45}$', "Potential", "series=gcp (GCP API Key 格式，保留 Potential 待验证)"),
    # Stripe 生产 key
    (r'^sk_live_[A-Za-z0-9]{16,128}$', "Critical", "Stripe Secret Key (sk_live_)"),
    (r'^pk_live_[A-Za-z0-9]{16,128}$', "FalsePositive", "Stripe Publishable Key (pk_live_)"),
    (r'^rk_live_[A-Za-z0-9]{16,128}$', "Critical", "Stripe Restricted Key (rk_live_)"),
    (r'^whsec_[A-Za-z0-9]{16,128}$', "Critical", "Stripe Webhook Secret (whsec_)"),
    # AWS
    (r'^AKIA[A-Z0-9]{16}$', "Critical", "AWS Access Key ID (AKIA...)"),
    # Slack
    (r'^xox[baprs]-[0-9a-zA-Z_-]{10,}$', "Critical", "Slack Token"),
    # GitHub
    (r'^ghp_[A-Za-z0-9]{36}$', "Critical", "GitHub Personal Access Token (ghp_)"),
    (r'^github_pat_[A-Za-z0-9_]{22,}$', "Critical", "GitHub Fine-grained PAT"),
    # Razorpay
    (r'^rzp_(live|test)_[A-Za-z0-9]{13}$', "Critical", "Razorpay Key (rzp_...)"),
    # OpenAI - 放宽到40-60字符（实际密钥约51字符）
    (r'^sk-[A-Za-z0-9]{40,60}$', "Critical", "OpenAI API Key (sk-...)"),
    (r'^sk-proj-[A-Za-z0-9_-]{40,60}$', "Critical", "OpenAI Project Key (sk-proj-...)"),
    # Anthropic - 放宽到40-60字符
    (r'^sk-ant-[A-Za-z0-9_-]{40,60}$', "Critical", "Anthropic API Key (sk-ant-...)"),
    # NPM
    (r'^npm_[A-Za-z0-9]{36}$', "Critical", "NPM Access Token"),
    # Twilio
    (r'^SK[0-9a-fA-F]{32}$', "Critical", "Twilio API Key"),
    # SendGrid
    (r'^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$', "Critical", "SendGrid API Key"),
    # Mapbox public token
    (r'^pk\.[A-Za-z0-9]{60,}$', "FalsePositive", "Mapbox Public Token"),
    # Heroku
    (r'^[0-9a-f]{30}-[0-9a-f]{14}-[0-9a-f]{24}$', "Critical", "Heroku API Key"),
    # private 私有 key
    (r'-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----', "Critical", "私有密钥文件"),
]


# ============================================================================
# 向量分析（与知识库相似度匹配）
# ============================================================================

_kb_embeddings: Optional[List[Dict[str, Any]]] = None
_kb_matrix = None
_embed_model = None
_SIM_THRESHOLD = 0.80
_VECTOR_EMBED_BATCH_SIZE = int(os.environ.get("RISK_VECTOR_BATCH_SIZE", "512"))

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_WORKSPACE_ROOT = os.path.dirname(os.path.dirname(_PROJECT_ROOT))
LOCAL_EMBEDDING_MODEL = os.environ.get(
    "LOCAL_EMBEDDING_MODEL",
    os.path.join(_WORKSPACE_ROOT, "models", "jina-embeddings-v4"),
)
KB_VECTORS_FILE = os.environ.get(
    "KB_VECTORS_FILE",
    os.path.join(_WORKSPACE_ROOT, "web100", "rag", "web_secret", "databaserag", "db", "kb_vectors_jina2048.jsonl"),
)

def _normalize_kb_risk(risk: Any) -> str:
    """将 KB 中的 risk_level 归一到 Critical / Potential / FalsePositive。"""
    normalized = str(risk or "").strip().lower()
    if normalized in {"critical", "high", "severe"}:
        return "Critical"
    if normalized in {"falsepositive", "false_positive", "safe", "lowrisk", "low", "info"}:
        return "FalsePositive"
    return "Potential"


def _load_kb_embeddings() -> List[Dict[str, Any]]:
    """懒加载 Jina 2048 维知识库向量（进程级缓存）"""
    global _kb_embeddings
    if _kb_embeddings is None:
        _kb_embeddings = []
        try:
            if not os.path.exists(KB_VECTORS_FILE):
                return _kb_embeddings
            with open(KB_VECTORS_FILE, "r") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    kb_item = json.loads(line)
                    vector = kb_item.get("vector")
                    if not vector:
                        continue
                    payload = kb_item.get("payload") or {}
                    original_full = payload.get("original_full_json") or {}
                    original_analysis = original_full.get("original_analysis") or {}
                    risk = (
                        original_analysis.get("risk_level")
                        or original_analysis.get("risk")
                        or original_full.get("label")
                        or "Potential"
                    )
                    description = (
                        payload.get("semantic_signature")
                        or original_analysis.get("reason")
                        or kb_item.get("text_content", "")
                    )
                    _kb_embeddings.append({
                        "embedding": vector,
                        "risk": _normalize_kb_risk(risk),
                        "description": description,
                    })
        except Exception:
            _kb_embeddings = []
    return _kb_embeddings


def _get_kb_matrix() -> np.ndarray:
    """以 float32 numpy 矩阵形式缓存 KB 向量，便于批量相似度计算。"""
    global _kb_matrix
    if _kb_matrix is None:
        kb = _load_kb_embeddings()
        if not kb:
            _kb_matrix = np.empty((0, 0), dtype=np.float32)
        else:
            matrix = np.asarray([item["embedding"] for item in kb], dtype=np.float32)
            norms = np.linalg.norm(matrix, axis=1, keepdims=True)
            norms = np.clip(norms, 1e-12, None)
            _kb_matrix = matrix / norms
    return _kb_matrix


def _get_embedding_model():
    """懒加载本地 Jina embedding 模型（进程级缓存）"""
    global _embed_model
    if _embed_model is None:
        try:
            import torch
            from sentence_transformers import SentenceTransformer

            device = "cuda:0" if torch.cuda.is_available() else "cpu"
            _embed_model = SentenceTransformer(
                LOCAL_EMBEDDING_MODEL,
                device=device,
                trust_remote_code=True,
                model_kwargs={"default_task": "retrieval"},
            )
        except Exception:
            _embed_model = None
    return _embed_model


def _compute_embedding(text: str) -> Optional[List[float]]:
    """使用本地 jina-embeddings-v4 计算文本向量。"""
    embeddings = _compute_embeddings([text])
    if embeddings is None or len(embeddings) == 0:
        return None
    return embeddings[0].tolist()


def _compute_embeddings(texts: List[str]) -> Optional[np.ndarray]:
    """批量计算文本向量，统一走 normalize_embeddings。"""
    if not texts:
        return np.empty((0, 0), dtype=np.float32)
    model = _get_embedding_model()
    if model is None:
        return None
    try:
        embeddings = model.encode(
            [text.replace("\n", " ")[:8192] for text in texts],
            task="retrieval",
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=min(_VECTOR_EMBED_BATCH_SIZE, len(texts)),
            convert_to_numpy=True,
        )
        if len(embeddings) > 0:
            return np.asarray(embeddings, dtype=np.float32)
    except Exception:
        pass
    return None


def _cosine_sim(a: List[float], b: List[float]) -> float:
    """余弦相似度"""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _detect_high_risk_format(value: str) -> Optional[RiskResult]:
    """高危格式兜底检测：已知服务格式直接返回，跳过 KB 向量分析"""
    for pattern, risk, desc in HIGH_RISK_SERVICE_PATTERNS:
        if re.match(pattern, value):
            return RiskResult(risk=risk, reason=f"高危格式兜底检测: {desc}", var_name="")
    return None


def _detect_frontend_public_key(item: Dict[str, Any], var_name: str = "") -> Optional[RiskResult]:
    """识别设计为浏览器公开暴露的 client-side key，按 FalsePositive 处理。"""
    rule_name = item.get("rule_name", "")
    value = str(item.get("value", "") or "")

    if rule_name in FRONTEND_PUBLIC_RULES:
        return RiskResult(risk="FalsePositive", reason=f"前端公开 key: {rule_name}", var_name=var_name)

    for pattern, desc in FRONTEND_PUBLIC_VALUE_PATTERNS:
        if re.match(pattern, value):
            return RiskResult(risk="FalsePositive", reason=f"前端公开 key: {desc}", var_name=var_name)

    if var_name and any(token in var_name for token in FRONTEND_PUBLIC_VAR_TOKENS):
        return RiskResult(risk="FalsePositive", reason=f"前端公开 key: 变量名暗示公开用途 ({var_name})", var_name=var_name)

    return None


def _classify_by_vector(var_name: str, item: Dict[str, Any]) -> RiskResult:
    """向量分析：var_name + value 与知识库匹配
    改进: 先做格式模式兜底检测，再 KB 向量分析（避免 KB 未知时漏报高危格式）
    """
    value = item.get("value", "")

    # ═══ 高危格式兜底检测（改进2/改进10）═════════════════════════════════
    risk_result = _detect_high_risk_format(value)
    if risk_result:
        return risk_result
    # ════════════════════════════════════════════════════════════════════

    kb = _load_kb_embeddings()
    if not kb:
        return RiskResult(risk="Potential", reason="向量分析：知识库为空，降级为 Potential", var_name=var_name)

    # 组合文本：变量名 + value 前50字符
    value_snippet = item.get("value", "")[:50]
    combined_text = f"{var_name} {value_snippet}"

    emb = _compute_embedding(combined_text)
    if emb is None:
        return RiskResult(risk="Potential", reason="向量分析：无法计算向量，降级为 Potential", var_name=var_name)

    best_sim = -1.0
    best_kb_item = None
    for kb_item in kb:
        kb_emb = kb_item.get("embedding")
        if kb_emb:
            sim = _cosine_sim(emb, kb_emb)
            if sim > best_sim:
                best_sim = sim
                best_kb_item = kb_item

    if best_kb_item is None:
        return RiskResult(risk="Potential", reason="向量分析：未匹配到知识库条目，降级为 Potential", var_name=var_name)

    if best_sim >= _SIM_THRESHOLD:
        kb_risk = best_kb_item.get("risk", "Potential")
        return RiskResult(
            risk=kb_risk,
            reason=f"向量分析：相似度 {best_sim:.3f} ≥ {_SIM_THRESHOLD}，匹配 KB 条目 '{best_kb_item.get('description', '')}'",
            var_name=var_name
        )
    else:
        return RiskResult(
            risk="Potential",
            reason=f"向量分析：相似度 {best_sim:.3f} < {_SIM_THRESHOLD}，降级为 Potential",
            var_name=var_name
        )


def _classify_vector_texts(text_var_pairs: List[tuple[str, str]]) -> Dict[str, RiskResult]:
    """批量向量分类，返回 text -> RiskResult。"""
    if not text_var_pairs:
        return {}

    kb = _load_kb_embeddings()
    if not kb:
        return {
            text: RiskResult(risk="Potential", reason="向量分析：知识库为空，降级为 Potential", var_name=var_name)
            for text, var_name in text_var_pairs
        }

    kb_matrix = _get_kb_matrix()
    texts = [text for text, _ in text_var_pairs]
    embeddings = _compute_embeddings(texts)
    if embeddings is None:
        return {
            text: RiskResult(risk="Potential", reason="向量分析：无法计算向量，降级为 Potential", var_name=var_name)
            for text, var_name in text_var_pairs
        }

    sims = embeddings @ kb_matrix.T
    best_idx = np.argmax(sims, axis=1)
    best_sim = sims[np.arange(len(texts)), best_idx]

    results = {}
    for i, (text, var_name) in enumerate(text_var_pairs):
        kb_item = kb[int(best_idx[i])]
        sim = float(best_sim[i])
        if sim >= _SIM_THRESHOLD:
            kb_risk = kb_item.get("risk", "Potential")
            results[text] = RiskResult(
                risk=kb_risk,
                reason=f"向量分析：相似度 {sim:.3f} ≥ {_SIM_THRESHOLD}，匹配 KB 条目 '{kb_item.get('description', '')}'",
                var_name=var_name,
            )
        else:
            results[text] = RiskResult(
                risk="Potential",
                reason=f"向量分析：相似度 {sim:.3f} < {_SIM_THRESHOLD}，降级为 Potential",
                var_name=var_name,
            )
    return results


# ============================================================================
# JWT 专项分析
# ============================================================================

JWT_HIGH_RISK_ISS: frozenset = frozenset({
    "auth0", "okta", "google", "facebook", "amazon", "microsoft",
    "apple", "github", "gitlab", "heroku", "firebase",
})

JWT_HIGH_RISK_SCOPE_PATTERNS: list = [
    re.compile(r"\badmin\b", re.I),
    re.compile(r"\broad\b", re.I),
    re.compile(r"\b privileged\b", re.I),
    re.compile(r"\bwrite\b.*\bwrite\b", re.I),
    re.compile(r"\bdelete\b", re.I),
    re.compile(r"\bmanage\b", re.I),
    re.compile(r"\bowner\b", re.I),
    re.compile(r"\bsuperuser\b", re.I),
]


def _parse_jwt_payload(value: str) -> Optional[Dict]:
    """解析 JWT payload"""
    if not (value.startswith("eyJ") and "." in value):
        return None
    try:
        parts = value.split(".")
        payload_b64 = parts[1]
        rem = len(payload_b64) % 4
        if rem:
            payload_b64 += "=" * (4 - rem)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None


def _classify_jwt(item: Dict[str, Any]) -> RiskResult:
    """JWT 专项分析"""
    value = item.get("value", "")
    payload = _parse_jwt_payload(value)
    if payload is None:
        return RiskResult(risk="Potential", reason="JWT 解析失败，降级为 Potential")

    # 已过期 → 按用户要求直接归类为 FalsePositive
    exp = payload.get("exp", 0)
    try:
        exp_ts = float(exp)
    except (TypeError, ValueError):
        exp_ts = 0.0
    if exp_ts and exp_ts < time.time():
        return RiskResult(risk="FalsePositive", reason=f"JWT 已过期 (exp={exp})")

    reasons = []

    # alg=none → Critical
    alg = payload.get("alg", "")
    if alg.lower() == "none":
        return RiskResult(risk="Critical", reason="JWT alg=none（严重安全漏洞）")

    # 高危 iss
    iss = payload.get("iss", "")
    if iss:
        for risky_iss in JWT_HIGH_RISK_ISS:
            if risky_iss in iss.lower():
                reasons.append(f"JWT 高危签发者: {iss}")
                break

    # 高危 scope/permissions
    for field in ("scope", "scopes", "permissions", "roles", "scp"):
        val = payload.get(field)
        if not val:
            continue
        if isinstance(val, list):
            val_str = " ".join(str(v) for v in val)
        else:
            val_str = str(val)
        for pattern in JWT_HIGH_RISK_SCOPE_PATTERNS:
            if pattern.search(val_str):
                reasons.append(f"JWT 高危 scope/permissions: {val_str[:100]}")
                break

    if reasons:
        return RiskResult(risk="Critical", reason="; ".join(reasons))

    # 含敏感字段
    sensitive_fields = ("pwd", "password", "secret", "private", "key", "token")
    for sf in sensitive_fields:
        if sf in str(payload).lower():
            return RiskResult(risk="Potential", reason=f"JWT 包含敏感字段: {sf}")

    return RiskResult(risk="Potential", reason="JWT 内容无明显高危特征")


# ============================================================================
# 核心分类入口
# ============================================================================

def _entropy(s: str) -> float:
    """计算字符串香农熵"""
    if not s:
        return 0.0
    counter = {}
    for c in s:
        counter[c] = counter.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log(cnt / n, 2) for cnt in counter.values())


# 改进1: Uri 误报过滤 — 常见 URL path 词
URI_FP_PATH_WORDS: frozenset = frozenset({
    "lancetcountdown", "suppliersupport", "privacy", "scuola", "oncologia",
    "esmo", "gearage", "policy", "rezeptsammlungen", "home", "about",
    "contact", "login", "signup", "admin", "assets", "static", "media",
    "images", "css", "js", "api", "index", "main", "app", "user",
    "data", "config", "content", "docs", "faq", "help", "terms",
    "conditions", "blog", "news", "shop", "products", "services",
})


def _classify_item(item: Dict[str, Any]) -> RiskResult:
    """
    对单条 hit_dict 条目进行风险分类。

    逻辑：
      1. 非 generic/jwt → 查 Potential 列表；命中 → Potential；未命中 → Critical
      2. generic/jwt    → 变量名黑名单三分类（FP / Critical / 模糊）
      3. 模糊变量名      → 向量分析（含高危格式兜底）
    """
    rule_name = item.get("rule_name", "")
    series = item.get("series", "")
    value = item.get("value", "")

    # ── 非 generic/jwt 分支 ───────────────────────────────────────────────
    if series not in ("generic", "jwt") and rule_name not in ("jwt", "jwt-base64"):
        # ═══ 改进1: Uri 误报过滤（series=uri 且 rule_name=Uri）═════════════
        if series == "uri" and rule_name == "Uri":
            high_risk = _detect_high_risk_format(value)
            if high_risk:
                return high_risk
            # 1. 长度过短 → FP
            if len(value) < 8:
                return RiskResult(risk="FalsePositive", reason="Uri: value长度<8，非密钥")
            # 2. 纯小写字母词且较短 → FP（英文单词 / URL path）
            if re.match(r'^[a-z]+$', value) and len(value) < 15:
                return RiskResult(risk="FalsePositive", reason=f"Uri: 纯字母词 '{value}'，非密钥")
            # 3. 常见 URL path 词 → FP
            if value.lower() in URI_FP_PATH_WORDS:
                return RiskResult(risk="FalsePositive", reason=f"Uri: URL path 词 '{value}'，非密钥")
            # 4. 熵值过低 → FP
            if _entropy(value) < 3.5:
                return RiskResult(risk="FalsePositive", reason=f"Uri: 熵值 {_entropy(value):.2f}<3.5，非高随机密钥")
        frontend_public = _detect_frontend_public_key(item)
        if frontend_public:
            return frontend_public
        if series == "gcp":
            high_risk = _detect_high_risk_format(value)
            if high_risk:
                return high_risk
        # ════════════════════════════════════════════════════════════════════
        if rule_name in POTENTIAL_RULES:
            return RiskResult(risk="Potential", reason=f"命中 Potential 规则列表: {rule_name}")
        else:
            return RiskResult(risk="Critical", reason=f"未命中 Potential 列表，默认 Critical: {rule_name}")

    # ── generic/jwt 分支 ───────────────────────────────────────────────────
    var_name = _get_var_name_from_hit(item)

    if series == "generic":
        frontend_public = _detect_frontend_public_key(item, var_name)
        if frontend_public:
            return frontend_public
        high_risk = _detect_high_risk_format(value)
        if high_risk:
            high_risk.var_name = var_name
            return high_risk
        if _is_obvious_non_secret_value(value):
            return RiskResult(risk="FalsePositive", reason=f"value 为代码片段/函数调用: {value[:40]}", var_name=var_name)

    # 2a: 变量名明确无害 → FalsePositive
    # ═══ 改进3: 黑名单+value联合判断，排除 JS 代码片段等误判 ══════════════
    if var_name in BLACKLIST_FP_VAR_NAMES:
        return RiskResult(risk="FalsePositive", reason=f"变量名无害: {var_name}", var_name=var_name)
    # ════════════════════════════════════════════════════════════════════

    # 2b: 变量名明确危害 → Critical
    if var_name in BLACKLIST_CRITICAL_VAR_NAMES:
        return RiskResult(risk="Critical", reason=f"变量名高危: {var_name}", var_name=var_name)

    # 2c: jwt 专项分析
    if series == "jwt" or rule_name in ("jwt", "jwt-base64"):
        return _classify_jwt(item)

    # 2d: 模糊变量名 → 向量分析（含高危格式兜底）
    return _classify_by_vector(var_name, item)


def _get_var_name_from_hit(item: Dict[str, Any]) -> str:
    """从 hit_dict 条目中提取变量名"""
    if item.get("series") == "generic":
        prefix = item.get("prefix", "")
        if prefix:
            return _normalize_var_name(prefix)
        match_text = item.get("match", "")
        extracted = _extract_var_name_from_match(match_text, item.get("value", ""))
        if extracted:
            return extracted
    if item.get("series") == "jwt" or item.get("rule_name") in ("jwt", "jwt-base64"):
        value = item.get("value", "")
        if value.startswith("eyJ") and "." in value:
            payload = _parse_jwt_payload(value)
            if payload:
                key_fields = []
                for k in ("iss", "sub", "aud", "scope", "permissions", "role", "admin"):
                    if k in payload:
                        key_fields.append(k)
                        if payload[k]:
                            key_fields.append(str(payload[k])[:50])
                return " ".join(key_fields)
        return value[:50]
    return ""


def _prepare_item_for_classification(item: Dict[str, Any]) -> tuple[Optional[RiskResult], Optional[str], Optional[str]]:
    """
    返回:
      (direct_result, None, None) 表示可直接分类
      (None, var_name, vector_text) 表示需进入向量分类
    """
    rule_name = item.get("rule_name", "")
    series = item.get("series", "")
    value = item.get("value", "")

    if series not in ("generic", "jwt") and rule_name not in ("jwt", "jwt-base64"):
        if series == "uri" and rule_name == "Uri":
            high_risk = _detect_high_risk_format(value)
            if high_risk:
                return high_risk, None, None
            if len(value) < 8:
                return RiskResult(risk="FalsePositive", reason="Uri: value长度<8，非密钥"), None, None
            if re.match(r'^[a-z]+$', value) and len(value) < 15:
                return RiskResult(risk="FalsePositive", reason=f"Uri: 纯字母词 '{value}'，非密钥"), None, None
            if value.lower() in URI_FP_PATH_WORDS:
                return RiskResult(risk="FalsePositive", reason=f"Uri: URL path 词 '{value}'，非密钥"), None, None
            entropy_value = _entropy(value)
            if entropy_value < 3.5:
                return RiskResult(risk="FalsePositive", reason=f"Uri: 熵值 {entropy_value:.2f}<3.5，非高随机密钥"), None, None
        frontend_public = _detect_frontend_public_key(item)
        if frontend_public:
            return frontend_public, None, None
        if series == "gcp":
            high_risk = _detect_high_risk_format(value)
            if high_risk:
                return high_risk, None, None
        if rule_name in POTENTIAL_RULES:
            return RiskResult(risk="Potential", reason=f"命中 Potential 规则列表: {rule_name}"), None, None
        return RiskResult(risk="Critical", reason=f"未命中 Potential 列表，默认 Critical: {rule_name}"), None, None

    var_name = _get_var_name_from_hit(item)
    if series == "generic":
        frontend_public = _detect_frontend_public_key(item, var_name)
        if frontend_public:
            return frontend_public, None, None
        high_risk = _detect_high_risk_format(value)
        if high_risk:
            high_risk.var_name = var_name
            return high_risk, None, None
        if _is_obvious_non_secret_value(value):
            return RiskResult(risk="FalsePositive", reason=f"value 为代码片段/函数调用: {value[:40]}", var_name=var_name), None, None

    if var_name in BLACKLIST_FP_VAR_NAMES:
        return RiskResult(risk="FalsePositive", reason=f"变量名无害: {var_name}", var_name=var_name), None, None
    if var_name in BLACKLIST_CRITICAL_VAR_NAMES:
        return RiskResult(risk="Critical", reason=f"变量名高危: {var_name}", var_name=var_name), None, None
    if series == "jwt" or rule_name in ("jwt", "jwt-base64"):
        return _classify_jwt(item), None, None

    vector_text = f"{var_name} {value[:50]}"
    return None, var_name, vector_text


def classify_batch(hit_dict: List[Dict[str, Any]]) -> List[RiskResult]:
    """批量分类，模糊 generic 统一走批量向量分析。"""
    results: List[Optional[RiskResult]] = [None] * len(hit_dict)
    vector_text_to_indices: Dict[str, List[int]] = {}
    vector_text_to_var_name: Dict[str, str] = {}
    direct_count = 0

    for idx, item in enumerate(hit_dict):
        direct_result, var_name, vector_text = _prepare_item_for_classification(item)
        if direct_result is not None:
            results[idx] = direct_result
            direct_count += 1
            continue
        if vector_text is None or var_name is None:
            results[idx] = RiskResult(risk="Potential", reason="分类准备失败，降级为 Potential", var_name="")
            direct_count += 1
            continue
        vector_text_to_indices.setdefault(vector_text, []).append(idx)
        vector_text_to_var_name[vector_text] = var_name

    vector_hit_total = sum(len(indices) for indices in vector_text_to_indices.values())
    unique_vector_texts = list(vector_text_to_indices.keys())
    if unique_vector_texts:
        print(
            f"[5.5/7] 风险分类拆分: 直接规则 {direct_count} 条, 向量命中 {vector_hit_total} 条, 唯一文本 {len(unique_vector_texts)} 条",
            flush=True,
        )
        total_batches = (len(unique_vector_texts) + _VECTOR_EMBED_BATCH_SIZE - 1) // _VECTOR_EMBED_BATCH_SIZE
        progress_interval = max(1, total_batches // 10)
        processed_texts = 0
        covered_hits = 0

        for batch_no, start in enumerate(range(0, len(unique_vector_texts), _VECTOR_EMBED_BATCH_SIZE), 1):
            batch_texts = unique_vector_texts[start:start + _VECTOR_EMBED_BATCH_SIZE]
            batch_pairs = [(text, vector_text_to_var_name[text]) for text in batch_texts]
            batch_results = _classify_vector_texts(batch_pairs)
            for text in batch_texts:
                res = batch_results[text]
                indices = vector_text_to_indices[text]
                for idx in indices:
                    results[idx] = res
                covered_hits += len(indices)
            processed_texts += len(batch_texts)
            if batch_no == 1 or batch_no % progress_interval == 0 or batch_no == total_batches:
                print(
                    f"[5.5/7] 风险分类进度: unique_text {processed_texts}/{len(unique_vector_texts)}, 覆盖hit {covered_hits}/{vector_hit_total}",
                    flush=True,
                )

    return [res if res is not None else RiskResult(risk="Potential", reason="分类结果缺失，降级为 Potential") for res in results]


def add_risk_label(hit_dict: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    为 hit_dict 添加风险标签字段。
    每个条目新增字段:
      risk_label  - Critical / Potential / FalsePositive
      risk_reason - 分类原因
      var_name    - generic/jwt 变量名

    FalsePositive 条��会被过滤掉不返回。
    """
    results = classify_batch(hit_dict)
    out = []
    for item, res in zip(hit_dict, results):
        if res.risk == "FalsePositive":
            continue
        item["risk_label"] = res.risk
        item["risk_reason"] = res.reason
        item["var_name"] = res.var_name
        out.append(item)
    return out
