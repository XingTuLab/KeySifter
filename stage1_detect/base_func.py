import pandas as pd
import math
import json
import pickle
from jellyfish import jaro_winkler_similarity
import os
import shutil
import matplotlib.pyplot as plt
from tqdm import tqdm
#保存变量stats_dict to bin文件
def save_dict2bin(stats_dict,name,save_root):
    folder_path=save_root  #建立新的文件夹便于每次自动区分
    file_path = os.path.join(folder_path, f"{name}.bin")
    with open(file_path, 'wb') as f:
        pickle.dump(stats_dict, f)
def compare_secret(str1, str2):
    SequenceMatcher_similarity = calculate_similarity(str1, str2)
    if jaro_winkler_similarity(str1, str2) >= 0.8 or SequenceMatcher_similarity >= 0.8:
        return True
    else:
        return False
# 计算秘密的相似性得分
def calculate_similarity(secret1, secret2):
    secret1 = preprocess_secret(secret1)
    secret2 = preprocess_secret(secret2)
    matcher = SequenceMatcher(None, secret1, secret2)
    similarity = matcher.ratio()
    return similarity
def reamake_file_name(file_name):
    for i in range(10, 0,-1):
        target = f"target{i}"
        if target in file_name:
            file1_parts = file_name.split(target)[-1]
            return file1_parts
    return file_name
def load_txt(f):
    lines_list = []  
    with open(f, 'r', encoding='utf-8') as file:  
        for line in file:  
            lines_list.append(line.strip())  
    return lines_list
def read_dict_bin(path):
    # 从二进制文件中加载hit_dict
    with open(path, 'rb') as f:
        return pickle.load(f)
def read_json(p):
    with open(p, 'r') as file_a:
        data = json.load(file_a)
    return data
def write_json(p,value):
    with open(p, 'w') as file_a:
        json.dump(value, file_a, indent=4)
def add_token(p,value):
    tmp=read_json(p)
    tmp.extend(value)
    with open(p, 'w') as file_a:
        json.dump(tmp, file_a, indent=4)
    return tmp
def remove_token_to_False(p1,token,p2):
    data = read_json(p1)
    filtered_list = [item for item in data if item['value'] != token]
    hit_list = [item for item in data if item['value'] == token]
    write_json(p1,filtered_list)
    if len(hit_list)>0:
        add_token(p2,hit_list)
    return filtered_list,hit_list
    
def entropy(string):
    if not string:
        return 0.0
    counter = {}
    for character in string:
        counter[character] = counter.get(character, 0) + 1
    n = len(string)
    return -sum((count / n) * (math.log(count / n, 2)) for count in counter.values())
def filter_words(value):
    input_path = '<PATH>'
    df = pd.read_excel(input_path)
    # 使用 tolist() 函数将其转换为列表类型，并将其赋值给了 words_list 变量
    words_list = df['words'].tolist()
    if ('PRIVATE KEY' in value or 'http' in value ):
        return False
    for word in words_list:
        if word.lower() in value.lower():
            print(word)
            return True
    return False
def filter_patterns(value):
    with open('<PATH>', "r") as f:
        patterns = f.readlines()
        patterns = [pattern.strip() for pattern in patterns]
    for pattern in patterns:
        if ('PRIVATE KEY' in value) :       #对private key宽松一点
            if pattern in value:
                print(pattern)
                return True
            else:
                return False
        elif pattern.lower() in value.lower():
            print(pattern)
            return True
    return False
def filter(tokens):

    false_set=[]
    truth_set=[]
    for tmp in tokens:
        if filter_words(tmp['value']):
            false_set.append(tmp)
        elif filter_patterns(tmp['value']):
            false_set.append(tmp)
        else:
            truth_set.append(tmp)
    return false_set,truth_set

def analyse(tools_result,class_):
    # 将collect数据转换为pandas的DataFrame
    df = pd.DataFrame(tools_result)

    # 统计各个is_mechanical的数量
    is_mechanical_counts = df[class_].value_counts()

    # 设置pandas输出显示的最大行数和最大列数
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)

    # 打印各个is_mechanical的数量
    print(is_mechanical_counts)
    


def copy_files_with_structure(file_list, source_folder, target_folder):
    for file_path in file_list:
        # 计算源文件的绝对路径
        abs_file_path = os.path.join(source_folder, file_path)
        
        # 计算目标文件的绝对路径
        abs_target_path = os.path.join(target_folder, file_path)
        
        # 获取目标文件的父目录
        target_dir = os.path.dirname(abs_target_path)
        
        # 如果目标文件的父目录不存在，创建它
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        
        # 复制文件到目标文件夹
        shutil.copy2(abs_file_path, abs_target_path)

import codecs

import codecs

def multi_unescape(s, max_iterations=5):
    """
    迭代反转义字符串，直到稳定。自动处理各类编解码异常。
    优化：添加最大迭代次数限制，避免无限循环
    """
    # 快速路径：绝大多数文件不含转义字符
    if '\\' not in s and '%' not in s:
        return s
    prev = None
    iteration = 0
    while s != prev and iteration < max_iterations:
        prev = s
        iteration += 1
        try:
            encoded = s.encode('latin-1', 'replace')
            decoded = encoded.decode('unicode_escape', 'replace')
        except Exception:
            try:
                decoded = codecs.decode(s, 'unicode_escape', 'replace')
            except Exception:
                break
        s = decoded
    return s


import bisect

def build_line_starts(content):
    """预计算所有换行符的位置，返回行首偏移数组。O(n) 一次。"""
    starts = [0]
    for i, c in enumerate(content):
        if c == '\n':
            starts.append(i + 1)
    return starts

def position_to_line_col(line_starts, pos):
    """用二分查找计算 (line, col)，O(log n)。"""
    line = bisect.bisect_right(line_starts, pos)
    col = pos - line_starts[line - 1] + 1
    return line, col


if __name__ == '__main__':
    # 示例：
    raw_str = r'"env": "-e HF_TOKEN=\\\\" -e CIVITAI_TOKEN=\\\"63f7752187c687b9a20df56240567d16\\\""'
    unescaped = multi_unescape(raw_str)
    print(unescaped)
