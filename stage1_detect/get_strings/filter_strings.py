import sys
import os
import re
from difflib import SequenceMatcher
from jellyfish import jaro_winkler_similarity

# 过滤掉 Python surrogate characters (\ud800-\udfff) 以及其他非法 Unicode 字符
# 这些字符会导致 jellyfish / SequenceMatcher 在内部编码时报 UnicodeEncodeError
_SURROGATE_RE = re.compile(
    r'[\ud800-\udfff\ufdd0-\ufdef\ufffe-\uffff\ufeff\u200b\u200c\u200d]'
)


def _sanitize(s):
    """移除字符串中所有非法的 Unicode 码点（surrogate、non-character 等），避免编码错误。"""
    return _SURROGATE_RE.sub('', s)


project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from get_strings.csv_get import extract_csv
from get_strings.general_get import exract_pattern
from get_strings.go_get import extract_go
from get_strings.ipynb_get import extract_ipynb
from get_strings.java_get import extract_java
from get_strings.json_get import extract_json
from get_strings.plist_get import extract_plist
from get_strings.py_get import extract_python
from get_strings.xml_get import extract_xml
from get_strings.yaml_get import extract_yaml
from get_strings.js_get import extract_js

from base_func import read_dict_bin, read_json
from urllib.parse import urlparse


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


# 移除非字母数字字符并转换为单行字符串
def preprocess_secret(secret):
    secret = _sanitize(secret)
    secret = ''.join(e for e in secret if e.isalnum() or e.isspace())
    secret = secret.replace(' ', '')  # 移除空格
    return secret
# 计算秘密的相似性得分
def calculate_sequence_similarity(secret1, secret2):
    secret1 = preprocess_secret(secret1)
    secret2 = preprocess_secret(secret2)
    matcher = SequenceMatcher(None, secret1, secret2)
    similarity = matcher.ratio()
    return similarity
#重写密钥比较，这里可以运行子串了，因为之前就过滤掉了，并且有些程序分析代码里面有些变量是json，特殊情况多
def compare_secret_substr(str1, str2):
    s1 = _sanitize(str1)
    s2 = _sanitize(str2)
    if jaro_winkler_similarity(s1, s2) >= 0.7:
        return True
    if calculate_sequence_similarity(s1, s2) >= 0.6:  #第二个耗时长
        return True
    return False

def _matches_hit(tmp_hit, tmp_str):
    """Return 2-tuple (is_match, keep_filter_hidt)."""
    if tmp_hit['value'] == tmp_str['value']:
        return (True, True)   # exact match → add to filter_hidt
    if (compare_secret_substr(tmp_hit['value'], tmp_str['value'])
            or (tmp_hit['value'] in tmp_str['value'] and not is_valid_url(tmp_str['value']))):
        return (True, False)  # similar/substr → skip
    return (False, False)    # not a match → continue looking


def filter_strings(file_path, hit_dict):
    construt_flag = True    #看文件是否是已有严格结构的提取还是通用提取
    try:
        if file_path.endswith('.java'):
            strings = extract_java(file_path)
        elif file_path.endswith('.ipynb'):
            strings = extract_ipynb(file_path)
        elif file_path.endswith('.yaml'):
            strings = extract_yaml(file_path)
        elif file_path.endswith('.xml'):
            strings = extract_xml(file_path)
        elif file_path.endswith(('.js', '.jsx', '.ts')):
            strings = extract_js(file_path)  # js报错影响不到python那边获取
        elif file_path.endswith('.csv'):
            strings = extract_csv(file_path)
        elif file_path.endswith('.go'):
            strings = extract_go(file_path)
        elif file_path.endswith('.json'):
            strings = extract_json(file_path)
        elif file_path.endswith('.plist'):
            strings = extract_plist(file_path)
        elif file_path.endswith('.py'):
            strings = extract_python(file_path)
        else:
            construt_flag = False
            strings = exract_pattern(file_path)

        if strings is None:
            raise ValueError("strings cannot be None.")

    except Exception:
        construt_flag = False
        strings = exract_pattern(file_path)

    # keep only entries that actually have a 'value' key
    strings_value = [s for s in strings if 'value' in s]

    if not construt_flag:
        return hit_dict   # no structured parsing available, return as-is

    filter_hidt = []
    # fast-path: pre-group strings by line so we only compare same-line entries
    from collections import defaultdict
    lines_map = defaultdict(list)
    for s in strings_value:
        lines_map[s['line_start']].append(s)

    skip_series = {'jdbc', 'private', 'uri', 'jwt'}

    for tmp in hit_dict:
        series = tmp['series']
        rule_name = tmp['rule_name']
        if series in skip_series or "url" in rule_name:
            filter_hidt.append(tmp)
            continue

        line_strs = lines_map.get(tmp['line_start'], [])
        kept = False   # True → do NOT add tmp (it's filtered)
        for tmp1 in line_strs:
            is_match, add_to_filter = _matches_hit(tmp, tmp1)
            if is_match:
                if add_to_filter:
                    filter_hidt.append(tmp)
                kept = True
                break   # one match is enough

        if not kept:
            filter_hidt.append(tmp)

    return filter_hidt
if __name__ == '__main__':
    file_path="<PATH>"
    hit_dict=read_json('<PATH>')
    filter_hidt=filter_strings(file_path,hit_dict)
    print(len(filter_hidt))


    
        
