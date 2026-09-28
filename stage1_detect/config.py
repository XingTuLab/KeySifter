import os

# 1. 确定项目根目录 (config.py 所在位置)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class Paths:
    """所有文件的路径管理"""
    DATA_DIR = os.path.join(ROOT_DIR, "data")
    
    # 词表文件
    WORD_LIST = os.path.join(DATA_DIR, "fixed_top_english_words_mixed_500000.json")
    
    # 过滤规则文件
    SORTED_END_RIGHT = os.path.join(DATA_DIR, "sorted_end_right_list_fasle_more20.json")
    
    # 文本资源
    CONFUSION_WORDS = os.path.join(DATA_DIR, "end_confuse_words.txt")
    FILE_EXTENSION = os.path.join(DATA_DIR, "file_extension.txt")
    
    # 正则相关
    REGEX_BIN = os.path.join(DATA_DIR, "regex", "regex_multiple_rulename.bin")
    DEFAULT_REGEX = os.path.join(DATA_DIR, "regex", "merged_regex_v4.json")
    regex_multiple=os.path.join(DATA_DIR, "regex", "regex_multiple_rulename.bin")
    password_model=os.path.join(ROOT_DIR, "password_model","password", "model_best.pth.tar")