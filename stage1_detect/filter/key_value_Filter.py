import sys
from config import Paths
import time
import base64
import json

from base_func import *
import multiprocessing
from multiprocessing import Pool, Manager
from tqdm import tqdm
import re
import wordninja

# 模块级预编译：避免每个 key_value 调用都重新编译
_TRAILING_NONALPHA_RE = re.compile(r'[^a-zA-Z]*$')

# ── JWT/HubSpot 误报过滤器 ────────────────────────────────────────────────
# 无害 tracking token payload 中的常见字段（出现则大概率非认证密钥）
_JWT_HARMLESS_PAYLOAD_FIELDS = frozenset([
    'org.tracking', 'org.analytics', 'org.tracker', 'tracking', 'analytics',
    'client_id', 'client_secret', 'oauth', 'scopes', 'scope',
])

# JWT无害 payload 示例（用于快速比对 base64 decode 后内容）
_JWT_HARMLESS_PATTERNS = [
    'org.tracking', 'org.analytics', 'tracking', 'analytics',
    '"role":"tracking"', '"role":"analytics"',
    'org.sentry', 'bugsnag', 'rollbar', 'datadog',
]

# HubSpot 误报 key 前缀（formId/formID 等是前端公开配置，非密钥）
_HUBSPOT_HARMLESS_KEY_PREFIXES = frozenset([
    'hubspotformid', 'hubspot_formid', 'formid', 'form_id',
    'hubspotportal', 'portal', 'hubspotpageid', 'pageid',
])


def _decode_jwt_payload(token: str) -> dict | None:
    """解码 JWT payload（不验证签名），返回 dict 或 None"""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    try:
        payload_b64 = parts[1]
        # URL-safe base64 -> 标准 base64
        payload_b64 = payload_b64.replace('-', '+').replace('_', '/')
        # 补齐 padding
        padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return None


def _is_harmless_jwt(token: str) -> bool:
    """判断 JWT 是否为无害 token（如 tracking/analytics token）"""
    payload = _decode_jwt_payload(token)
    if not payload:
        return False
    # 检查常见无害字段
    payload_str = json.dumps(payload).lower()
    if any(pat.lower() in payload_str for pat in _JWT_HARMLESS_PATTERNS):
        return True
    # 检查 scope/role 中是否包含 tracking 类关键词
    scope = payload.get('scope', '') or payload.get('scopes', [])
    if isinstance(scope, list):
        scope_str = ' '.join(scope).lower()
    else:
        scope_str = str(scope).lower()
    if any(f in scope_str for f in _JWT_HARMLESS_PAYLOAD_FIELDS):
        return True
    # 检查 roles 数组中是否有 org.* 前缀（常见 tracking/analytics 服务 token）
    roles = payload.get('roles', [])
    if isinstance(roles, list):
        roles_str = ' '.join(str(r) for r in roles).lower()
        if any(f in roles_str for f in _JWT_HARMLESS_PAYLOAD_FIELDS):
            return True
        if any(isinstance(r, str) and r.startswith('org.') for r in roles):
            return True
    return False


def _is_harmless_hubspot_key(key_lower: str) -> bool:
    """判断 HubSpot key 是否为无害的表单/页面配置（而非 API Key）"""
    # 移除常见分隔符后再检查
    key_clean = re.sub(r'[\s_\-.]+', '', key_lower)
    return any(
        key_clean.startswith(prefix) for prefix in _HUBSPOT_HARMLESS_KEY_PREFIXES
    )

# 进程级 wordninja 模型缓存（避免重复加载）
_wordninja_model = None

def _get_wordninja_model():
    global _wordninja_model
    if _wordninja_model is None:
        import wordninja
        _wordninja_model = wordninja
    return _wordninja_model

# ── Process-level lazy cache for static data files ──────────────────────────
_word_list_cache          = None
_sorted_end_right_cache   = None
_confusion_words_cache    = None
_file_extention_cache     = None
_list_right_merged_cache  = None   # list_right base + sorted_end_right keys

def _load_word_list():
    global _word_list_cache
    if _word_list_cache is None:
        _word_list_cache = read_json(Paths.WORD_LIST)
    return _word_list_cache

def _load_sorted_end_right():
    global _sorted_end_right_cache, _list_right_merged_cache
    if _sorted_end_right_cache is None:
        _sorted_end_right_cache = read_json(Paths.SORTED_END_RIGHT)
        # pre-compute the merged list_right so we never repeat the extend()
        _list_right_merged_cache = [
            "Oid","author","hash",'Fingerprint','keyword','checksum','addr','type','id'
        ] + [key for key in _sorted_end_right_cache]
    return _sorted_end_right_cache

def _load_confusion_words():
    global _confusion_words_cache
    if _confusion_words_cache is None:
        _confusion_words_cache = load_txt(Paths.CONFUSION_WORDS)
    return _confusion_words_cache

def _load_file_extension():
    global _file_extention_cache
    if _file_extention_cache is None:
        _file_extention_cache = load_txt(Paths.FILE_EXTENSION)
    return _file_extention_cache

# ── Static data lists (cheap to recreate; keep here for readability) ─────────
WHOLE_VALUE_LIST   = ["templateid:","@tmp","@example",'example',"@test","@hostname",
                       'test:test','example.com','@somewhere','_key','@url',
                       'hello:world@',"****@localhost","127.0.0.1:443@"]
VALUE_PLACEHOLDER  = ["changeit","changeme","change","guest","printf","return","test",
                       "user",'pass',"password","username","secret",'test','bar',
                       'foobar','api_secret','TOKEN','pwd','password','apikey',
                       "Parola","Parolan","Wachtwoord","Salasana","Pasahitza",
                       "boolean","Lozinka","before","blahblah"]
VALUE_MACHINE      = ["ca-pub-"]
LIST_LEFT          = ['PublicKey','public',"fake",'input','put','enter',"invalid"]
WHOLE_KEY_LIST     = ["formkey","?key"," h1","GPG key","SAPageKey","pubkey","key_hex",
                       "fake_",'Password_label','Password_action','Password_msg',
                       "git-tree","_id"," id",'sha256','-sha','sha1',' h1','keyword',
                       'apiUsername','PublicKey','public','.js','.py','.yaml','_type',
                       '_addr','.txt']

# 全小写版：避免每个 count_matching_words 调用里重复 lower()
WHOLE_KEY_LIST_LOWER  = [k.lower() for k in WHOLE_KEY_LIST]
VALUE_PLACEHOLDER_LOWER = [v.lower() for v in VALUE_PLACEHOLDER]
WHOLE_VALUE_LIST_LOWER  = [v.lower() for v in WHOLE_VALUE_LIST]
VALUE_MACHINE_LOWER     = [v.lower() for v in VALUE_MACHINE]
LIST_LEFT_LOWER         = [v.lower() for v in LIST_LEFT]

def count_matching_words(input_string, filter_key_lower):
    input_lower = input_string.lower()
    return sum(1 for key in filter_key_lower if key in input_lower)

def filter_prefix(key_list_lower, left_splited_list_lower, right_splited_list_lower,
                  confusion_list_lower, list_left_lower, list_right_lower, prefix_lower):
    for tmp in confusion_list_lower:
        if tmp in key_list_lower and prefix_lower in tmp:
            return True
    for tmp in list_left_lower:
        if tmp in left_splited_list_lower:
            return True
    for tmp in list_right_lower:
        if tmp in right_splited_list_lower:
            return True
    return False
def split_words(secret_match,word_list):
     
    tokens = re.split(r'[._-]', secret_match)
    tokens = [token.rstrip() for token in tokens if len(token)>=2]  # 删除空字符串
    # 进一步拆解
    new_tokens = []
    wordninja = _get_wordninja_model()
    for token in tokens:
        if token not in word_list and len(token)>3:
            split_tokens = [split_token for split_token in  wordninja.split(token)if len(split_token)>=2]
            new_tokens.extend(split_tokens)
        else:
            new_tokens.append(token)
    return new_tokens
# def split_string_by_word(s, word):
#     if word in s:
#         parts = s.split(word)
#         left_part = parts[0]
#         right_part = word.join(parts[1:])
#         return left_part, word, right_part
#     else:
#         return s, '', ''

def split_string_by_word(s, word):
    if not word:  # Check if the word is empty
        return s, '', ''  # Return the input string and empty strings
    if word in s:
        parts = s.split(word)
        left_part = parts[0]
        right_part = word.join(parts[1:])
        return left_part, word, right_part
    else:
        return s, '', ''

def get_sub(a,b):
    # 查找b在a中的起始位置  
    start_index = a.find(b)  
    # 如果b是a的子串  
    if start_index != -1:  
        # 提取b之前的那部分字符串  
        return a[:start_index]  
    else:  
        # 如果b不是a的子串，可以设置一个默认值或抛出异常  
        return a

def key_value_filter_single(single_hit):
    word_list          = _load_word_list()
    sorted_end_right   = _load_sorted_end_right()   # ensures _list_right_merged_cache is ready
    confusion_list     = _load_confusion_words()
    file_extention     = _load_file_extension()
    list_right         = _list_right_merged_cache   # pre-built once

    tmp = single_hit

    # ── JWT 无害 token 过滤 ─────────────────────────────────────────────
    rn = tmp.get('rule_name', '')
    if 'jwt' in rn.lower():
        if _is_harmless_jwt(tmp.get('value', '')):
            return False

    # ── HubSpot FormId 误报过滤 ─────────────────────────────────────────
    # hubspotFormId / formId 等是前端公开配置，不是认证密钥
    if 'hubspot' in rn.lower():
        match_val = tmp.get('match', '')
        # 提取 key 部分（match 中 value 之前的内容）
        value_val = tmp.get('value', '')
        if value_val and match_val:
            key_part = get_sub(match_val, value_val)
            key_part_lower = key_part.lower().replace(':', '').replace('\\', '').replace('"', '')
            if _is_harmless_hubspot_key(key_part_lower):
                return False

    # ── need_keyvalue + match != value path ───────────────────────────────────
    if tmp['need_keyvalue'] and tmp['match'] != tmp['value']:
        key_value = get_sub(tmp['match'], tmp['value'])
        key_value = _TRAILING_NONALPHA_RE.sub('', key_value)
        if any(key_value.endswith(ext) for ext in file_extention):
            return False

        pre_left, _, pre_right = split_string_by_word(key_value, tmp['prefix'])
        key_list_sp   = split_words(key_value, word_list)
        left_sp       = split_words(pre_left, word_list)
        right_sp      = split_words(pre_right, word_list)

        # pre-lower once per call instead of N times inside filter_prefix
        kl_l  = [t.lower() for t in key_list_sp]
        ls_l  = [t.lower() for t in left_sp]
        rs_l  = [t.lower() for t in right_sp]
        cl_l  = [t.lower() for t in confusion_list]
        ll_l  = LIST_LEFT_LOWER
        lr_l  = [t.lower() for t in list_right]
        pf_l  = tmp['prefix'].lower() if tmp['prefix'] else ''

        if (filter_prefix(kl_l, ls_l, rs_l, cl_l, ll_l, lr_l, pf_l)
                or count_matching_words(key_value, WHOLE_KEY_LIST_LOWER)
                or count_matching_words(tmp['value'], VALUE_MACHINE_LOWER)):
            return False

    # ── non-generic, match != value path ──────────────────────────────────────
    elif tmp['match'] != tmp['value']:
        if not ('password' in rn or 'Jdbc' in rn or 'Uri' in rn or 'jwt' in rn):
            key_value = get_sub(tmp['match'], tmp['value'])
            key_value = _TRAILING_NONALPHA_RE.sub('', key_value)
            if any(key_value.endswith(ext) for ext in file_extention):
                return False

    # ── human secrets: placeholder check ─────────────────────────────────────
    if tmp['is_mechanical'] == 'human':
        rn = tmp['rule_name']
        if 'password' in rn or 'Jdbc' in rn or 'Uri' in rn:
            if (count_matching_words(tmp['value'], VALUE_PLACEHOLDER_LOWER)
                    + count_matching_words(tmp['match'], WHOLE_VALUE_LIST_LOWER)) >= 1:
                return False
        else:
            if (count_matching_words(tmp['value'], VALUE_PLACEHOLDER_LOWER)
                    + count_matching_words(tmp['match'], WHOLE_VALUE_LIST_LOWER)) >= 2:
                return False

    return True


def multiprocess(batch,share_dict):
    for tmp in tqdm(batch):
        if key_value_filter_single(tmp):
            share_dict.append(tmp)

if __name__ == '__main__':
#     tmp= {'file': '<PATH>',
#   'value': 'guest',
#   'match': "Password=guest'",
#   'prefix': 'Password',
#   'rule_name': 'generic-password',
#   'is_mechanical': 'human',
#   'series': 'generic',
#   'filter_count': [],
#   'word_weight': 0,
#   'line_start': 154,
#   'line_end': 154,
#   'col_start': 54,
#   'col_end': 69,
#   'index_start': 6823,
#   'index_end': 6830,
#   'regex': '(?i)(?:[0-9a-z]{0,20})(?:[\\-_ .]{0,1})(passwd|password|pwd)(?:[0-9a-z\\-_\\t .]{0,20})(?:[ |\\t|\\r|\\f|\\v|\']|[ |\\t|\\r|\\f|\\v|"]){0,3}(?:=|>|:{1,3}=|\\|\\|:|<=|=>|:|\\?=)(?:\'|\\"| |\\t|\\r|\\f|\\v|=|\\x60){0,5}([0-9a-z\\-_.=!@#$%^&*+~\\(\\{\\}\\)]{5,150})(?:[\'|\\"|\\n|\\r|\\s|\\x60|;]|$)'}
#     print(key_value_filter_single(tmp))
    manager = Manager()
    single_dict = manager.list()
    num_cores = 35
    hit_dict=read_json("<PATH>论文分析/PyPI/all_pypi_res_infos.json")[:100]
    batch_size=len(hit_dict)//num_cores
    pool = Pool(processes=num_cores)
    for i in range(num_cores):
        start_idx = i * batch_size
        end_idx = (i + 1) * batch_size if i < num_cores - 1 else len(hit_dict)
        batch_files = hit_dict[start_idx:end_idx]
        pool.apply_async(multiprocess, (batch_files, single_dict))
    pool.close()
    pool.join()
    result_single_dict = list(single_dict)
    
    #print("test time",time.time()-time1)
    print(f"length:{len(hit_dict)}")
    
    save_root='./test'
    save_name="all_pypi_res_infos_KeyvalueFix_2"
    save_dict2bin(result_single_dict,save_name,save_root)  
    write_json(f'./test/{save_name}.json',result_single_dict)