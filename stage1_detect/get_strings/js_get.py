import json
import subprocess
import os
def extract_js(file_path):
    current_path = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.abspath(os.path.join(current_path, 'execute_js.js'))
    try:
        result = subprocess.run(['node', script_path,file_path], capture_output=True, text=True, check=True)
        output = json.loads(result.stdout)
        return output
    except Exception as e:
        # print(f"Error: {e}")  # 解析错误不影响核心功能，静默处理
        return None

if __name__ == '__main__':
    file_path="<PATH>"
    output = extract_js(file_path)

    print(output)