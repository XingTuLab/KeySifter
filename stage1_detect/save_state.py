import os
import pickle
import json

def make_result(resume_path=None):
    if resume_path:
        return resume_path
    # 判断当前目录是否有 stats 文件夹，没有则创建
    if not os.path.exists('./states'):
        os.makedirs('./states')
    folder_prefix = "result_"
    folder_count = 1

    # 检测结果文件夹的根目录，在当前目录下的 state 文件夹中
    root_folder_path = os.path.join(os.getcwd(), "states")

    while True:
        folder_name = folder_prefix + str(folder_count)
        folder_path = os.path.join(root_folder_path, folder_name)

        if not os.path.exists(folder_path):
            os.mkdir(folder_path)
            print(f"新建文件夹 {folder_path}")
            break
        folder_count += 1
    return folder_path
def write_json(p,value):
    with open(p, 'w') as file_a:
        json.dump(value, file_a, indent=4)
#保存变量stats_dict to bin文件
def save_dict2bin(stats_dict,name,save_root):
    folder_path=save_root  #建立新的文件夹便于每次自动区分
    file_path = os.path.join(folder_path, f"{name}.bin")
    with open(file_path, 'wb') as f:
        pickle.dump(stats_dict, f)

def read_dict_bin(path):
    # 从二进制文件中加载hit_dict
    with open(path, 'rb') as f:
        return pickle.load(f)

def save_temp_trufflehog(hit_dict, name, save_root):
    folder_path = save_root  # 建立新的文件夹便于每次自动区分
    # 定义一个字典来保存数据
    file_path = os.path.join(folder_path, f"{name}.json")
    # 将整个数据字典保存为JSON文件
    with open(file_path, "w") as fp:
        for item in hit_dict:
            json_str = json.dumps(item)
            fp.write(json_str + '\n')
    print(f"结果保存在{file_path}里")
#读取tmp
def load_temp_trufflehog(file_path):
    hit_dict = []  # 创建一个空列表来保存读取的数据
    with open(file_path, "r") as fp:
        for line in fp:
            # 逐行读取JSON数据并解析
            item = json.loads(line.strip())
            hit_dict.append(item)
    return hit_dict


#保存单个GitHub项目结果的json文件
def save_hit_dict_trufflehog(hit_dict, name, save_root):
    
    folder_path = save_root  # 建立新的文件夹便于每次自动区分
    # 定义一个字典来保存数据

    file_path_single = os.path.join(folder_path, f"{name}_single.json")
    # 将整个数据字典保存为JSON文件
    write_json(file_path_single,hit_dict)
    print(f"结果保存在{file_path_single}里")


def save_checkpoint_fast(checkpoint_data, save_root):
    file_path = os.path.join(save_root, "checkpoint_fast.json")
    with open(file_path, 'w') as f:
        json.dump(checkpoint_data, f)

def load_checkpoint_fast(save_root):
    file_path = os.path.join(save_root, "checkpoint_fast.json")
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r') as f:
        return json.load(f)


def save_scan_progress(scanned_files, save_root):
    file_path = os.path.join(save_root, "scan_progress.json")
    with open(file_path, 'w') as f:
        json.dump(sorted(set(scanned_files)), f, ensure_ascii=False)


def save_scan_progress_checkpoint(scanned_files, save_root):
    checkpoint_dir = os.path.join(save_root, "checkpoints")
    os.makedirs(checkpoint_dir, exist_ok=True)
    file_path = os.path.join(checkpoint_dir, "scan_progress_checkpoint.json")
    with open(file_path, 'w') as f:
        json.dump(sorted(set(scanned_files)), f, ensure_ascii=False)


def load_scan_progress(save_root):
    file_path = os.path.join(save_root, "scan_progress.json")
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def load_latest_checkpoint(save_root):
    checkpoint_dir = os.path.join(save_root, "checkpoints")
    if not os.path.isdir(checkpoint_dir):
        return None, []

    latest_hit_dict = None
    latest_scanned = []

    checkpoint_hit = os.path.join(checkpoint_dir, "hit_dict_checkpoint.bin")
    checkpoint_progress = os.path.join(checkpoint_dir, "scan_progress_checkpoint.json")
    if os.path.exists(checkpoint_hit):
        latest_hit_dict = read_dict_bin(checkpoint_hit)
    if os.path.exists(checkpoint_progress):
        with open(checkpoint_progress, 'r') as f:
            data = json.load(f)
        if isinstance(data, list):
            latest_scanned = data
    if latest_hit_dict is not None or latest_scanned:
        return latest_hit_dict, latest_scanned

    max_progress = -1
    for name in os.listdir(checkpoint_dir):
        if name.startswith("scan_progress_") and name.endswith(".json"):
            suffix = name[len("scan_progress_"):-len(".json")]
            if suffix.isdigit():
                max_progress = max(max_progress, int(suffix))
    if max_progress >= 0:
        progress_path = os.path.join(checkpoint_dir, f"scan_progress_{max_progress}.json")
        with open(progress_path, 'r') as f:
            data = json.load(f)
        if isinstance(data, list):
            latest_scanned = data

        hit_path = os.path.join(checkpoint_dir, f"hit_dict_{max_progress}.bin")
        if os.path.exists(hit_path):
            latest_hit_dict = read_dict_bin(hit_path)

    return latest_hit_dict, latest_scanned
