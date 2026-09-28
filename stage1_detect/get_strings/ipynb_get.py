#暂时不用它了，其实用json提取了也没啥用，里面也是长文本
from get_strings.json_get import *


def extract_ipynb(ipynb_file_path):
    try:
        with open(ipynb_file_path, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
    except UnicodeDecodeError:
        try:
            with open(ipynb_file_path, 'r', encoding='latin-1') as file:
                json_data = json.load(file)
        except Exception:
            return []
    all_values_ = extract_leaf_values(json_data)
    result=set([tmp for tmp in all_values_ ])
    result_end=exract_strlist_position(result,ipynb_file_path)
    return result_end
if __name__ == '__main__':
    # 用法示例
    ipynb_file_path = "<PATH>"

    result=extract_ipynb(ipynb_file_path)
    print(result)

