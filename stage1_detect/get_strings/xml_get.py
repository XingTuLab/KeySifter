import xmltodict
import json
from get_strings.json_get import *
def xml_file_to_json(xml_file_path):
    try:
        with open(xml_file_path, 'r', encoding='utf-8') as file:
            xml_content = file.read()
    except UnicodeDecodeError:
        try:
            with open(xml_file_path, 'r', encoding='latin-1') as file:
                xml_content = file.read()
        except Exception:
            return {}
    xml_dict = xmltodict.parse(xml_content, force_list=False, dict_constructor=dict)
    json_result = json.loads(json.dumps(xml_dict))
    return json_result

def extract_xml(xml_file_path):
    json_data = xml_file_to_json(xml_file_path)
    all_values_ = extract_leaf_values(json_data)

    result=set([tmp for tmp in all_values_ ])
    result_end=exract_strlist_position(result,xml_file_path)
    return result_end
if __name__ == '__main__':
    # 示例XML文件路径
    xml_file_path = '<PATH>'

    json_result = extract_xml(xml_file_path)

    # 打印转换后的JSON对象
    print(json_result)
