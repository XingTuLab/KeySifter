import os
import zipfile

from base_func import write_json
from logger import setup_logger


def get_files(path, size_limit):
    """优化版本：先检查扩展名，避免无谓的 getsize 调用"""
    files = []
    
    binary_extensions = {
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'ico', 'svg',
        'mp4', 'mkv', 'avi', 'mov', 'flv', 'wmv', 'webm',
        'mp3', 'wav', 'ogg', 'flac', 'aac',
        'zip', 'tar', 'gz', 'rar', '7z', 'bz2',
        'exe', 'dll', 'so', 'bin', 'apk',
        'woff', 'woff2',
        'iso', 'dat', 'pak', 'crx'
    }
    
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    
    try:
        for file in os.listdir(path):
            file_path = os.path.join(path, file)
            
            if os.path.isfile(file_path):
                file_ext = os.path.splitext(file_path)[1].lower().lstrip('.')
                if file_ext in binary_extensions:
                    continue  # 直接跳过二进制文件

                try:
                    file_size = os.path.getsize(file_path)
                    if file_size < size_limit:
                        files.append(file_path)
                except (OSError, IOError):
                    continue
                    
            elif os.path.isdir(file_path):
                files += get_files(file_path, size_limit)
                
    except (OSError, IOError):
        pass
    
    return files
if __name__ == '__main__':
    p=get_files("<PATH>论文分析/GPt",20000000)
    write_json("./target_p.json",p)
