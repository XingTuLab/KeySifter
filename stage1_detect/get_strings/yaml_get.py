import yaml
import json
import warnings

from get_strings.json_get import *
def extract_yaml(yaml_file_path):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            with open(yaml_file_path, 'r', encoding='utf-8') as yaml_file:
                yaml_data = yaml.load(yaml_file, Loader=yaml.FullLoader)
        except UnicodeDecodeError:
            try:
                with open(yaml_file_path, 'r', encoding='latin-1') as yaml_file:
                    yaml_data = yaml.load(yaml_file, Loader=yaml.FullLoader)
            except Exception:
                return []
        except Exception:
            try:
                with open(yaml_file_path, 'r', encoding='latin-1') as yaml_file:
                    yaml_data = yaml.load(yaml_file, Loader=yaml.FullLoader)
            except Exception:
                return []

    json_data = json.loads(json.dumps(yaml_data, indent=2, default=str))
    all_values_ = extract_leaf_values(json_data)
    result = set([tmp for tmp in all_values_])
    result_end = exract_strlist_position(result, yaml_file_path)
    return result_end

if __name__ == '__main__':
    yaml_file_path = "<PATH>"

    yaml_strings=extract_yaml(yaml_file_path)

    print(yaml_strings)
    print(len(yaml_strings))