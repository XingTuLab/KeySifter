"""
采用Github项目过滤
文件结构:不规则（根据GitHub官网下载的项目来遍历所有文件）
需要遍历每个文件，所有文件都要扫描并且每一个文件都需要被所有正则表达式扫描，并且如果一个文件要从头扫描到尾，如果存在多个匹配项的话，都要进行匹配。（一个文件可能出现多个密钥）
"""
import multiprocessing
import os

from multiprocessing import Pool, Manager
import re
import time
from base_func import entropy, read_json,multi_unescape
import pandas as pd
from filter.filter_multireason import check_multi_reason
from filter.key_value_Filter import key_value_filter_single
from filter.filter_pattern_word import filter_pattern_word_single
from get_files import get_files
from urllib.parse import urlparse     #urlparse
from filter.filter_substr import combine_substr
from get_strings.filter_strings import filter_strings
from logger import setup_logger
from save_state import *
import signal
from tqdm import tqdm  # 导入tqdm库

# 定义超时处理函数 #每个文件30s
def handler(signum, frame):
    raise TimeoutError("File processing exceeded time limit")

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
words_list=read_json(os.path.join(_DATA_DIR, 'fixed_top_english_words_mixed_500000.json'))
patterns = []
with open(os.path.join(_DATA_DIR, 'patterns.txt'), "r") as f:
    patterns = f.readlines()
    patterns = [pattern.strip() for pattern in patterns]

"""
正则表达式 r"[0-9a-zA-Z]{32}" 的意思是匹配由数字和字母组成、长度为 32 的字符串。让我们逐个解释该正则表达式的不同部分：

[0-9a-zA-Z]: 这是一个字符类（character class），表示匹配一个数字或字母。[0-9] 表示匹配任意一个数字，[a-zA-Z] 表示匹配任意一个字母（不区分大小写）。
{32}: 这是一个量词（quantifier），表示前面的字符或字符类必须连续出现 32 次。
"""
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


def _get_rule(rule_info):
    """优先复用预编译正则，避免每个文件重复编译。"""
    rule = rule_info.get("compiled")
    if rule is not None:
        return rule
    try:
        return re.compile(rule_info["regex"])
    except Exception:
        return None

def detect_encoding(file_path):
    with open(file_path, "rb") as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result["encoding"]
def scan_project_tf(rules_single,file_list,log_path):
    logger_instance = setup_logger(log_path)
    single_dict=[]
    
    for file_path in tqdm(file_list):
        
        file_value_set=set()
        hit_num=0
        hit_dict=[]
        try:
            with open(file_path, 'r',encoding='utf-8') as f:
                raw_str = f.read()
            content = multi_unescape(raw_str)
                #content.encode().decode('unicode_escape')
            # ————————————单因素————————————
            for rule_info in rules_single:
                rule_name=rule_info['rule_name']
                rule_pattern =rule_info['regex']
                rule = _get_rule(rule_info)
                if rule is None:
                    continue
                if len(hit_dict)>100000:
                    break        
                for match in rule.finditer(content):
                    start, end = match.start(), match.end()

                    # 获取匹配项所在行的行号
                    line_start = content.count('\n', 0, start) + 1
                    line_end = content.count('\n', 0, end) + 1
                    col_start = start - content.rfind('\n', 0, start)
                    col_end = end - content.rfind('\n', 0, end)
                    # print(f"Found '{rule_name}' at position {line_start}-{line_end}: {match.group(0)}")
                    # Print previous five lines and following five lines
                    
                    value=match.group(1) if rule.groups==1 else match.group(0)
                    if rule_info['series']=='private':
                        if len(value)<100:
                            continue
                    """if rule.groups==1:
                        if "(?i)(?:" not in rule_pattern and "(?i:(?" not in rule_pattern:
                            value=match.group(0)
                        else:
                            value=match.group(1)
                    else:
                        value=match.group(0)
                    if value==None:
                            continue      #只匹配到了前缀"""
                    #对于有熵的机械密钥
                    if 'entropy'in rule_info:
                        if entropy(value)<rule_info['entropy']:
                            continue
                    
                    """if file_path+value in file_value_set:
                        continue
                    else:
                        file_value_set.add(file_path+value)"""

                    hit_dict.append({
                    "file": file_path,
                    'value': value,
                    'match':match.group(),
                    "rule_name": rule_name,  #规则名
                    "is_mechanical": rule_info["is_mechanical"],  #规则类别
                    "series":rule_info["series"]   ,   #规则大类
                    "filter_count":[],
                    "word_weight":0,
                    "line_start": line_start,
                    "line_end": line_end,
                    "col_start":col_start,
                    "col_end":col_end,
                    "index_start": start,
                    "index_end": end,
                    "regex":rule_pattern
                    })
                    hit_num+=1
 
        except Exception as e:
            # print(f"{file_path}不能读取")
            pass 

        hit_dict_check_multi=check_multi_reason(hit_dict)
        hit_dict_single,duplicate_,belong_sub=combine_substr(hit_dict_check_multi)
        hit_dict_single=filter_strings(file_path,hit_dict_single)
        
        result_hit_dict=[]
        for tmp in  hit_dict_single:
            if tmp['series']!="certification":
                result_hit_dict.append(tmp)

                
        #记录一下已经扫描的，防止出现中断以定位
        info={"scaned_file_path":file_path,"hit":len(hit_dict)}
        info=str(info)
        logger_instance.info(info)

        single_dict.extend(result_hit_dict)
    return single_dict

def scan_filelist_tf(rules_single,file_list,single_dict,duplicate_dict,shared_variable,log_path):
    
    # 设置超时时间为30秒
    timeout_seconds = 300
    
    logger_instance = setup_logger(log_path)
    for file_path in tqdm(file_list):
        
        file_value_set=set()
        hit_num=0
        hit_dict=[]
        shared_variable.value += 1
        if(shared_variable.value%3000)==0:
            print("Inside the function:", shared_variable.value)
        try:
             # 设置超时处理器
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout_seconds)  # 开启30秒超时计时器
            
            with open(file_path, 'r',encoding='utf-8') as f:
                raw_str = f.read()
                #content.encode().decode('unicode_escape')
            content = multi_unescape(raw_str)
            # ————————————单因素————————————
            for rule_info in rules_single:
                rule_name=rule_info['rule_name']
                rule_pattern =rule_info['regex']
                rule = _get_rule(rule_info)
                if rule is None:
                    continue

                for match in rule.finditer(content):
                    
                    start, end=match.span(1) if rule.groups==1 else match.span(0) 
                    if rule_info["series"]=='jdbc' or rule_info['series'] == 'private' or rule_info['series']=='uri' or rule_info['series']=='jwt':
                        start, end = match.start(), match.end()
                    # 获取匹配项所在行的行号
                    line_start = content.count('\n', 0, start) + 1
                    line_end = content.count('\n', 0, end) + 1
                    col_start = start - content.rfind('\n', 0, start)
                    col_end = end - content.rfind('\n', 0, end)
                    # print(f"Found '{rule_name}' at position {line_start}-{line_end}: {match.group(0)}")
                    # Print previous five lines and following five lines

                    if rule_info['series'] !="uri":         
                        value=match.group(1) if rule.groups==1 else match.group(0) 
                        
                        
                    else:
                        # 解析URL
                        parsed_url = urlparse(match.group(0))
                        # 获取用户名和密码
                        user_info = parsed_url.username, parsed_url.password
                        # 打印用户名和密码
                        value=user_info[1]
                        if value==None:  #检测的url没密钥————https://localhost:3000/jqueryui@1.2.3
                            continue
                        """#排除掉地址:端口的情况——上面那个已经解决了
                        uri_pattern= r"^[a-zA-Z]+:\/\/(?:\d{1,3}\.){3}\d{1,3}:(\d+)"
                        match_uri = re.match(uri_pattern,match.group())
                        if match_uri:
                            continue"""
                        
                    prefix=""
                    if rule_info['series']=='generic':
                        prefix=match.group(1)
                        value=match.group(2)
                        if len(value) == 42 and value.startswith("0x"):         #表示地址的特例
                            continue
                        key_value=get_sub(match.group(),value)
                        key_value = re.sub(r'[^a-zA-Z]*$', '', key_value)  
                        start=start+len(key_value)
                        
                    if rule_info['series']=='private':
                        if len(value)<128:    #https://chatgpt.com/share/672d7258-1c74-8009-8e14-20fe8133da72长度
                            continue
                            # value=re.split('-----',value)[0]  #尾部可能有
                            
                        if len(value)<256 and 'ECC' in match.group():
                            continue
                        if len(value)<256 and 'RSA' in match.group():
                            continue
                    if value is None:
                        continue
                    if len(value)<5:
                        continue
                    #对于有熵的机械密钥
                    if 'entropy'in rule_info:
                        if entropy(value)<rule_info['entropy']:
                            continue
                    #有前缀的value是为了方便过滤去除了前缀如AKIA，我必须加上才是正确的token
                    if rule_info['series']=='generic'or rule_info['series']=="uri" or rule_info['series']=="jdbc":
                        whole_secret_value=value
                    else:
                        whole_secret_value=match.group().strip()
                        
                    secret_hit={
                    "file": file_path,
                    "whole_secret_value": whole_secret_value,
                    'value': value,
                    'match':match.group(),
                    'prefix':prefix,
                    "rule_name": rule_name,  #规则名
                    "is_mechanical": rule_info["is_mechanical"],  #规则类别
                    "series":rule_info["series"]   ,   #规则大类
                    "filter_count":[],
                    "word_weight":0,
                    "line_start": line_start,
                    "line_end": line_end,
                    "col_start":col_start,
                    "col_end":col_end,
                    "index_start": start,
                    "index_end": end,
                    "regex":rule_pattern,
                    "need_keyvalue":rule_info['need_keyvalue']
                    }
                    #key_value过滤___________________________
                    if not key_value_filter_single(secret_hit):
                        continue 
                    #key_value过滤___________________________
             
                    hit_dict.append(secret_hit)
                    hit_num+=1
            # write_json('./test/tmp/hit_dict1.json',hit_dict)
            hit_dict_check_multi=check_multi_reason(hit_dict)
            # write_json('./test/tmp/hit_dict2.json',hit_dict_check_multi)
            hit_dict_single,duplicate_,belong_sub=combine_substr(hit_dict_check_multi)
            # write_json('./test/tmp/hit_dict3.json',hit_dict_single)
            hit_dict_single=filter_strings(file_path,hit_dict_single)
            # write_json('./test/tmp/hit_dict4.json',hit_dict_single)

            result_hit_dict=[]
            for tmp in  hit_dict_single:
                if tmp['series']!="certification":
                    result_hit_dict.append(tmp)
            # write_json('./test/tmp/hit_dict5.json',result_hit_dict)        
            #记录一下已经扫描的，防止出现中断以定位
            info={"scaned_file_path":file_path,"hit":len(hit_dict)}
            info=str(info)
            logger_instance.info(info)

            single_dict.extend(result_hit_dict)

        except TimeoutError:
            print(f"Timeout occurred for file: {file_path}")
            logger_instance.info(f"Timeout occurred for file: {file_path}")
        except Exception as e:
            info = {"error": e, "scaned_file_path": file_path}
            print(info)
            logger_instance.info(str(info))
        finally:
            # 重置定时器
            signal.alarm(0)
    return   single_dict


def scan_single_file(args):
    """扫描单个文件，返回结果列表。args: (rules_single, file_path, log_path, timeout_seconds)"""
    if len(args) == 4:
        rules_single, file_path, log_path, timeout_seconds = args
    else:
        rules_single, file_path, log_path, timeout_seconds = args[0], args[1], args[2], 30

    hit_dict = []
    try:
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(int(timeout_seconds))
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_str = f.read()
        content = multi_unescape(raw_str)

        for rule_info in rules_single:
            rule_name = rule_info['rule_name']
            rule_pattern = rule_info['regex']
            rule = _get_rule(rule_info)
            if rule is None:
                continue
            if len(hit_dict) > 100000:
                break
            for match in rule.finditer(content):
                start, end = match.start(), match.end()
                if rule_info['series'] != 'uri':
                    value = match.group(1) if rule.groups >= 1 else match.group(0)
                else:
                    parsed_url = urlparse(match.group(0))
                    value = parsed_url.password
                    if value is None:
                        continue
                if value is None:
                    continue
                if rule_info['series'] == 'generic' and rule.groups >= 2:
                    value = match.group(2)
                if 'entropy' in rule_info:
                    if entropy(value) < rule_info['entropy']:
                        continue
                line_start = content.count('\n', 0, start) + 1
                line_end = content.count('\n', 0, end) + 1
                col_start = start - content.rfind('\n', 0, start)
                col_end = end - content.rfind('\n', 0, end)
                hit_dict.append({
                    "file": file_path,
                    'value': value,
                    'match': match.group(),
                    "rule_name": rule_name,
                    "is_mechanical": rule_info["is_mechanical"],
                    "series": rule_info["series"],
                    "filter_count": [],
                    "word_weight": 0,
                    "line_start": line_start,
                    "line_end": line_end,
                    "col_start": col_start,
                    "col_end": col_end,
                    "index_start": start,
                    "index_end": end,
                    "regex": rule_pattern
                })

        hit_dict = check_multi_reason(hit_dict)
        hit_dict, _, _ = combine_substr(hit_dict)
        hit_dict = filter_strings(file_path, hit_dict)
        result = [r for r in hit_dict if r['series'] != 'certification']
        return result
    except TimeoutError:
        return []
    except Exception:
        return []
    finally:
        signal.alarm(0)


def scan_batch_files(args):
    """扫描一批文件，返回 (file_list, results)。args: (rules_single, file_list, timeout_seconds, prefix_keywords)"""
    rules_single, file_list, timeout_seconds, prefix_keywords = args
    results = []
    for file_path in file_list:
        try:
            res = scan_single_file((rules_single, file_path, None, timeout_seconds))
            results.extend(res)
        except Exception:
            continue
    return file_list, results


if __name__ == '__main__':
    
    time1=time.time()
    
    
    #rules_single = read_dict_bin("<PATH>")
    rules_single=read_json("<PATH>")
    print(len(rules_single))
    Path="<PATH>"
    # file_list=get_files(Path,2000000)[:1000]
    a = read_json("<PATH>")
    file_list=[tmp["file"] for tmp in a]
    
    # file_list=["<PATH>"]
    save_root='./test/tmp'
    log_path='./test/tmp/log.json'
    manager = Manager()
    single_dict = manager.list()
    duplicate_dict=manager.list()
    num_cores = multiprocessing.cpu_count() - 5
    
    shared_variable = manager.Value('i', 0)
    batch_size=len(file_list)//num_cores
    pool = Pool(processes=num_cores)
    for i in range(num_cores):
        start_idx = i * batch_size
        end_idx = (i + 1) * batch_size if i < num_cores - 1 else len(file_list)
        batch_files = file_list[start_idx:end_idx]
        pool.apply_async(scan_filelist_tf, (rules_single,batch_files, single_dict,duplicate_dict,shared_variable,log_path))
    pool.close()
    pool.join()
    result_single_dict = list(single_dict)
    hit_dict=result_single_dict

    print("test time",time.time()-time1)
    print(f"length:{len(hit_dict)}")
    save_dict2bin(hit_dict,"hit_dict",save_root)  
    write_json('./test/tmp/hit_dict.json',hit_dict)
    #save_hit_dict_trufflehog(hit_dict,name='test_multipro',save_root=save_root)
