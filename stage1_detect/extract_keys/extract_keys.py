
import re
import time

from tqdm import tqdm
from base_func import *
import multiprocessing
import os

from multiprocessing import Pool, Manager



def scan_project_tf(hit_dict, rules_single, file_list, prefix_dict):
    for file_path in tqdm(file_list):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for rule_info in rules_single:
                rule_name=rule_info['rule_name']
                rule_pattern =rule_info['regex']
                try:
                    rule = re.compile(rule_pattern)
                except:
                    continue

                for match in rule.finditer(content):
                    prefix = match.group(1)
                    
                    if prefix not in prefix_dict:
                        prefix_dict[prefix] = 1  # Initialize count for new prefix
                    else:
                        prefix_dict[prefix] += 1  # Increment count for existing prefix
                    
                    # 只有第一次出现时，记录匹配信息
                    if prefix_dict[prefix] == 1:
                        start, end = match.start(), match.end()
                        # 获取匹配项所在行的行号
                        line_start = content.count('\n', 0, start) + 1
                        line_end = content.count('\n', 0, end) + 1
                        col_start = start - content.rfind('\n', 0, start)
                        col_end = end - content.rfind('\n', 0, end)
                        value = match.group(2)
                        if entropy(value)< 3.5 and "api-key"in rule_name :
                            continue
                        hit_dict.append({
                            "file": file_path,
                            'value': value,
                            'match': match.group(),
                            "rule_name": rule_name,  # 规则名
                            "is_mechanical": rule_info["is_mechanical"],  # 规则类别
                            "series": rule_info["series"],  # 规则大类
                            "filter_count": [],
                            "word_weight": 0,
                            "line_start": line_start,
                            "line_end": line_end,
                            "col_start": col_start,
                            "col_end": col_end,
                            "index_start": start,
                            "index_end": end,
                        })
        except Exception as e:
            info = {"error": e, "scanned_file_path": file_path}  # 保存这个e太大了
            #print(info)
    return hit_dict, prefix_dict


def get_files(path,size_limit):
    files = []
    # 判断是否为相对路径
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    
    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)  
            if file_size < size_limit:  
                files.append(file_path)
        elif os.path.isdir(file_path):
            files += get_files(file_path,size_limit)
    return files

if __name__ == '__main__':
    rules_single= [     {
        "rule_name": "generic-api-key",
        #"regex": """(?i)([0-9a-z]{0,20}[-_. ]?\w{1,20})(?:\s|['"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)\s*(['"\x60]?[0-9a-z\-_.=!@#$%^&*+~]{5,150}[?:'"\n\r\s\x60;]?)""",
        "regex": """(?i)([0-9a-z]{0,20}[\\-_ .]{0,1}[key|api|token|cred|secret|client|auth|access][0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:{1,3}=|\\|\\|:|<=|=>|:|\\?=)(?:'|\\\"|\\s|=|\\x60){0,5}([0-9a-z\\-_.=!@#$%^&*+~]{5,150})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)""",
        "is_mechanical": "machine",
        "series": "generic",
        "entropy" : 3.5
    },
     {
        "rule_name": "generic-api-pass",
        "regex": """(?i)([0-9a-z]{0,20}[\\-_ .]{0,1}[passwd|password|pwd][0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:{1,3}=|\\|\\|:|<=|=>|:|\\?=)(?:'|\\\"|\\s|=|\\x60){0,5}([0-9a-z\\-_.=!@#$%^&*+~]{5,150})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)""",
        "is_mechanical": "human",
        "series": "generic",
    }
    ]
    
    time1=time.time()
    manager = Manager()
    hit_dict = manager.list()
    prefix_dict=manager.dict()
    shared_variable = manager.Value('i', 0)
    num_cores = 30
    Path="<PATH>"
    file_list=get_files(Path,200000000)
    #file_list=['<PATH>']
    pool = Pool(processes=num_cores)
    batch_size=len(file_list)//num_cores
    for i in range(num_cores):
        start_idx = i * batch_size
        end_idx = (i + 1) * batch_size if i < num_cores - 1 else len(file_list)
        batch_files = file_list[start_idx:end_idx]
        pool.apply_async(scan_project_tf, (hit_dict,rules_single,batch_files,prefix_dict))
    pool.close()
    pool.join()
    print(time1-time.time())
    save_dict2bin(list(hit_dict),"pypi24_1_4_hit_dict_havekeys","./")
    save_dict2bin(dict(prefix_dict),"pypi24_1_4_prefix_dict_havekeys","./")