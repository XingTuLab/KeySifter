"""
此文件设置为命令行运行，设置参数
"""
import os
import sys
import time
import re
import multiprocessing
from multiprocessing import Pool, Manager, Lock
import json

# 禁用 tqdm 的输出，避免多进程时每个进程都显示进度条
os.environ["TQDM_DISABLE"] = "1"

import warnings
warnings.filterwarnings("ignore")

# 1. 获取 main_arg.py 所在的绝对路径（即项目根目录）
project_root = os.path.dirname(os.path.abspath(__file__))
workspace_root = os.path.dirname(os.path.dirname(project_root))

# 2. 把这个路径强行插入到 Python 的搜索路径列表（sys.path）的最前面
sys.path.insert(0, project_root)

from password_model.predict import filter_password
import argparse
from save_state import *  # 导入保存函数
from save_state import save_checkpoint_fast, load_checkpoint_fast
from hit_git_tf import scan_single_file as scan_single_file_main, scan_filelist_tf, scan_batch_files  # 核心扫描函数
from get_files import  get_files
from filter.filter_pattern_word import filter_pattern_word, filter_pattern_word_single
from filter.filter_similarstr import combine_similarstr
from base_func import *
global log_path
from logger import setup_logger
from risk_classifier import add_risk_label
import pyfiglet

# 优化开关：默认启用优化版本
USE_OPTIMIZED_VERSION = True

# 进程安全的文件追加器（优化版：批量缓冲）
class SafeFileAppender:
    """线程/进程安全的文件追加器 - 优化版批量缓冲"""
    def __init__(self, filepath, buffer_size=500):
        self.filepath = filepath
        self.lock = Lock()
        self.buffer_size = buffer_size
        self.buffer = []
        # 如果文件存在且有内容，先计算已有行数
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                self.line_count = sum(1 for _ in f)
        else:
            self.line_count = 0
    
    def append(self, items):
        """追加多个结果到文件（带批量缓冲）"""
        if not items:
            return self.line_count
        
        self.buffer.extend(items)
        
        # 达到缓冲区大小时一次性写入
        if len(self.buffer) >= self.buffer_size:
            self._flush()
        
        return self.line_count
    
    def _flush(self):
        """实际写入文件"""
        if not self.buffer:
            return
        with self.lock:
            with open(self.filepath, 'a') as f:
                for item in self.buffer:
                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
            self.line_count += len(self.buffer)
            self.buffer = []
    
    def close(self):
        """关闭时刷新缓冲区"""
        self._flush()


def scan_single_file_collect(args):
    """扫描单个文件并返回结果（用于收集模式）"""
    rules, filepath, log_path, timeout_seconds, prefix_keywords = args
    results = scan_single_file_main(args[:4] if len(args) >= 5 else args)
    return results, filepath


def result_key(item):
	"""用于恢复场景的命中结果去重 key。"""
	return (
		item.get("file", ""),
		item.get("rule_name", ""),
		item.get("value", ""),
		item.get("index_start"),
		item.get("index_end"),
	)


def load_scan_results_jsonl(path):
	results = []
	seen = set()
	duplicate_count = 0
	with open(path, 'r') as f:
		for line in f:
			if not line.strip():
				continue
			item = json.loads(line)
			key = result_key(item)
			if key in seen:
				duplicate_count += 1
				continue
			seen.add(key)
			results.append(item)
	return results, duplicate_count


if __name__ == '__main__':
	banner = pyfiglet.figlet_format("SecretDetection")
	banner2 = """
	------------------- secret detection pipeline -------------------
	"""
	print(banner)
	print(banner2)
	parser = argparse.ArgumentParser(description='运行检查GitHub项目密钥的参数')

	parser.add_argument('--path', dest='path', type=str, help='输入需要检验的文件根路径', default="<PATH>论文分析/重构bench/")
	parser.add_argument('--path_json', dest='path_json', type=str, help='输入预先收集好的文件路径 JSON 列表', default=None)
	parser.add_argument('--mode', dest='mode', type=str, help='扫描模式，分为:scan和,entropy', default="scan")
	parser.add_argument('--entropy_path', dest='entropy_path', type=str, help='熵使用的路径', default="./data/entropy_result.bin")
	parser.add_argument('--regex', dest='regex', type=str, help='正则表达式', default="./data/regex/merged_regex_v5.json")
	parser.add_argument('--save_name', dest='save_name', type=str, help='保存文件名字，方便区分', default="all_result")
	parser.add_argument('--pre_loc', dest='pre_loc', type=str, help='Continue with previous testing loc——pre_test_root', default="None")
	parser.add_argument('--hit_dict', dest='hit_dict', type=str, help=' previous hit_dict', default="None")
	parser.add_argument('--size_limit', dest='size_limit', type=int, help='faster size_limit of file', default=10 * 1024 * 1024)
	parser.add_argument('--core_num', dest='core_num', type=int, help=' nums of core', default=max(1, multiprocessing.cpu_count() - 5))
	parser.add_argument('--timeout_seconds', dest='timeout_seconds', type=int, help='timeout_seconds',
						default=60)
	parser.add_argument('--resume', dest='resume', type=str, help='断点续扫：指定 states/result_X 目录继续扫描', default=None)
	parser.add_argument('--checkpoint_interval', dest='checkpoint_interval', type=int, help='保存检查点的百分比间隔', default=10)
	parser.add_argument('--no-optimize', dest='no_optimize', action='store_true', help='禁用优化版本，使用原始版本')
	args = parser.parse_args()
	print(f"检测文件路径：{args.path}")
	if args.path_json:
		print(f"检测路径列表：{args.path_json}")
	print(f"检测模式：{args.mode}")
	if not args.no_optimize:
		print("[优化模式] 预编译正则 + 动态 chunksize")
	#print(f"检测平均熵权重：{args.entropy_path}")
	#判断运行模式

	# 处理断点续扫
	scanned_files = set()
	existing_result_count = 0
	existing_hit_dict = None
	checkpoint_scanned = []
	if args.resume:
		# 断点续扫模式
		save_root = make_result(args.resume)

		# 优先加载最新的检查点进度（scan_progress_checkpoint.json）
		checkpoint_dir = os.path.join(args.resume, "checkpoints")
		checkpoint_progress_file = os.path.join(checkpoint_dir, "scan_progress_checkpoint.json")
		if os.path.exists(checkpoint_progress_file):
			checkpoint_scanned = read_json(checkpoint_progress_file)
			scanned_files = set(checkpoint_scanned)
			print(f"已从检查点加载进度: {len(scanned_files)} 个已扫描文件", flush=True)
		else:
			# 回退：加载原始进度文件
			scanned_files = set(load_scan_progress(args.resume))
			print(f"已加载扫描进度: {len(scanned_files)} 个文件已扫描", flush=True)

		# 尝试加载检查点结果（hit_dict）
		result_dir = args.resume
		# 优先加载 hit_dict_checkpoint.bin（最新格式）
		checkpoint_hit = os.path.join(checkpoint_dir, "hit_dict_checkpoint.bin")
		if os.path.exists(checkpoint_hit):
			existing_hit_dict = read_dict_bin(checkpoint_hit)
			existing_result_count = len(existing_hit_dict)
			print(f"已加载检查点结果: {existing_result_count} 个结果", flush=True)
		else:
			# 回退：加载带数字编号的检查点
			existing_hit_dict, checkpoint_scanned = load_latest_checkpoint(args.resume)
			if existing_hit_dict and len(existing_hit_dict) > 0:
				existing_result_count = len(existing_hit_dict)
				# 更新已扫描文件集合
				scanned_files.update(checkpoint_scanned)
				print(f"已加载检查点: {existing_result_count} 个结果, {len(scanned_files)} 个已扫描文件", flush=True)

		# 如果仍然没有结果，尝试加载最终结果文件
		if existing_hit_dict is None:
			single_file = os.path.join(result_dir, "all_result_single.json")
			if os.path.exists(single_file):
				existing_hit_dict = read_json(single_file)
				existing_result_count = len(existing_hit_dict)
				print(f"已从最终结果加载: {existing_result_count} 个结果")
			else:
				reduced_file = os.path.join(result_dir, "all_result_reduced_single.json")
				if os.path.exists(reduced_file):
					existing_hit_dict = read_json(reduced_file)
					existing_result_count = len(existing_hit_dict)
					print(f"已从简化结果加载: {existing_result_count} 个结果")

		# 从 scan_results.jsonl 加载已有结果（去重）
		result_file = os.path.join(save_root, "scan_results.jsonl")
		if os.path.exists(result_file) and existing_hit_dict is not None:
			print(f"正在加载已有的扫描结果...", flush=True)
			# 已有结果中的文件路径集合
			existing_files = {r.get('file', '') for r in existing_hit_dict if r}
			existing_file_set = set(existing_files)
			new_results = []
			new_file_count = 0
			with open(result_file, 'r') as f:
				for line in f:
					if line.strip():
						r = json.loads(line)
						if r.get('file', '') not in existing_file_set:
							new_results.append(r)
							new_file_count += 1
			if new_results:
				existing_hit_dict.extend(new_results)
				existing_result_count = len(existing_hit_dict)
				print(f"从 scan_results.jsonl 追加 {new_file_count} 条新结果，共 {existing_result_count} 条")

		print(f"断点续扫：已扫描 {len(scanned_files)} 个文件，已有 {existing_result_count} 个结果")
	else:
		save_root = make_result()  # 建立新的文件夹便于每次自动区分

	log_path = os.path.join(save_root, "log.json")
	logger_instance = setup_logger(log_path)
	logger_instance.info(f"--mode:{args.mode},--path:{args.path},--path_json:{args.path_json},--regex:{args.regex}, --entropy_path:{args.entropy_path}, --save_name:{args.save_name},--pre_loc{args.pre_loc},--size_limit:{args.size_limit},--resume:{args.resume},--checkpoint_interval:{args.checkpoint_interval}")

	if args.path_json:
		file_list = read_json(args.path_json)
		if not isinstance(file_list, list):
			raise ValueError(f"path_json 必须是 JSON list: {args.path_json}")
	else:
		file_list=get_files(args.path,args.size_limit)
	#file_list=get_files('<PATH>',args.size_limit)
	#file_list=["./test/totest.py"]
	#file_list=read_dict_bin("./test/file_set.bin")
	#file_list=read_json("<PATH>")
	# file_list=read_json("./test/xiaorong.json")
	# file_list=read_json("<PATH>结果分析/vx_files.json")
	#file_list=list(file_list)
	print(f"文件长度：{len(file_list)}")
	
	#判别模式是计算熵还是扫面
	if args.mode == "scan":
		time1=time.time()
		start_time = time.time()
		total_processed_files = 0

		# 加载前缀列表
		prefix_registry_path = os.environ.get(
			"PREFIX_REGISTRY_PATH",
			os.path.join(workspace_root, "web100", "rag", "web_secret", "databaserag", "whole_project", "kb_builder", "prefix_registry.json")
		)
		prefix_registry = read_json(prefix_registry_path)
		prefix_keywords = [p["prefix"] for p in prefix_registry.get("prefixes", [])]
		result_file = os.path.join(save_root, "scan_results.jsonl")
		hit_dict_cache = os.path.join(save_root, "hit_dict.bin")
		filtered_cache = os.path.join(save_root, "origin_filtered.bin")
		fast_checkpoint = load_checkpoint_fast(save_root) if args.resume else None
		scan_completed_from_checkpoint = (
			bool(fast_checkpoint)
			and fast_checkpoint.get("total_files", 0) > 0
			and fast_checkpoint.get("processed_files", 0) >= fast_checkpoint.get("total_files", 0)
			and os.path.exists(result_file)
		)

		if (args.regex).endswith('.bin'):
			rules_single = read_dict_bin(args.regex)
		elif (args.regex).endswith('.json'):
			rules_single = read_json(args.regex)
		else:
			rules_single = []

		if not args.no_optimize:
			for rule in rules_single:
				if 'compiled' not in rule:
					try:
						rule['compiled'] = re.compile(rule['regex'])
					except:
						rule['compiled'] = None
			print(f"[优化] 已预编译 {len(rules_single)} 条正则规则")

		if scan_completed_from_checkpoint and not scanned_files:
			scanned_files = set(file_list)
			print(f"检测到已完成扫描的检查点: {save_root}", flush=True)
			print(f"将直接复用 {result_file} 进入后处理，不再重复扫描 {len(scanned_files)} 个文件", flush=True)

		# 过滤掉已扫描的文件
		if scanned_files:
			remaining_files = [f for f in file_list if f not in scanned_files]
			print(f"文件总数：{len(file_list)}，已扫描：{len(scanned_files)}，剩余：{len(remaining_files)}")
			file_list = remaining_files
		else:
			print(f"文件总数：{len(file_list)}，剩余：{len(file_list)}")

		if not file_list:
			print("所有文件已扫描完成！")
			num_cores = int(args.core_num)
			total_processed_files = (
				fast_checkpoint.get("processed_files", 0) if fast_checkpoint
				else len(scanned_files)
			)
			hit_dict = []
			if args.resume and os.path.exists(hit_dict_cache):
				print(f"[{time.strftime('%H:%M:%S')}] 从已有 hit_dict.bin 恢复扫描结果...", flush=True)
				hit_dict = read_dict_bin(hit_dict_cache)
				print(f"[{time.strftime('%H:%M:%S')}] 已恢复 {len(hit_dict)} 条扫描结果", flush=True)
			elif os.path.exists(result_file):
				print(f"[{time.strftime('%H:%M:%S')}] 从已有 scan_results.jsonl 恢复扫描结果...", flush=True)
				hit_dict, duplicate_count = load_scan_results_jsonl(result_file)
				print(f"[{time.strftime('%H:%M:%S')}] 已恢复 {len(hit_dict)} 条扫描结果, 去重 {duplicate_count} 条", flush=True)
			elif existing_hit_dict is not None:
				hit_dict = existing_hit_dict
				print(f"[{time.strftime('%H:%M:%S')}] 未找到 scan_results.jsonl，回退使用已有结果 {len(hit_dict)} 条", flush=True)
		else:
			# 进程数改为 90（原为 30）：增大 batch_size 后每个进程工作量翻 20 倍，
			# 锁争用大幅减少，可充分利用 CPU 算力
			requested_cores = int(args.core_num)
			if requested_cores > 90:
				num_cores = 90
				print(f"[优化] 请求 {requested_cores} 核 → 使用 {num_cores} 核", flush=True)
			else:
				num_cores = requested_cores
			
			print(f"[{time.strftime('%H:%M:%S')}] 正在创建 {num_cores} 个工作进程...", flush=True)
			pool = Pool(processes=num_cores, maxtasksperchild=10)

			total_files = len(file_list)
			
			# 创建结果文件追加器（增大缓冲减少锁频率）
			file_appender = SafeFileAppender(result_file, buffer_size=1000)

			next_checkpoint = [args.checkpoint_interval]
			checkpoint_every_batches = 1 if total_files <= 20000 else 20

			# === 批量处理优化：每个任务处理多个文件 ===
			# 关键优化：batch_size 需要在"减少进程返回频率"和"充分利用多核"之间平衡
			# 实测单文件平均 ~0.3s（含 filter_strings），batch_size 过大导致只有 1 个 worker 拿到任务
			# 目标：每个 batch 在单 worker 上耗时 30-60s，使 90 个 worker 能并行处理多批
			# 公式：target = 45s / 0.3s_per_file ≈ 150 文件，用 max(100, ...) 留缓冲
			batch_size = max(100, min(200, total_files // max(4, num_cores)))
			num_batches = (total_files + batch_size - 1) // batch_size
			# 将文件列表分成批次
			batches = [file_list[i*batch_size:(i+1)*batch_size] for i in range(num_batches)]
			# 构建批量任务（同时传入 prefix_keywords 避免每个进程重复读 JSON）
			task_list = [(rules_single, batch, args.timeout_seconds, prefix_keywords) for batch in batches]
			# chunksize=1：每个 worker 每次只拿 1 个 batch，主循环能及时拿到进度反馈
			# 多进程本身已保证并行，chunksize 不需要增大
			optimal_chunksize = 1
			print(f"[{time.strftime('%H:%M:%S')}] 批量模式: {num_batches} 批次 x {batch_size} 文件/批, 进程数={num_cores}, chunksize={optimal_chunksize}, checkpoint_every_batches={checkpoint_every_batches}", flush=True)
			results_iter = pool.imap_unordered(scan_batch_files, task_list, chunksize=optimal_chunksize)

			start_time = time.time()
			processed_count = 0       # 已返回的结果条数（用于统计 hit 数）
			result_count = existing_result_count

			print(f"[{time.strftime('%H:%M:%S')}] 开始扫描 {total_files} 个文件...", flush=True)
			print("-" * 80, flush=True)
			print(f"[{time.strftime('%H:%M:%S')}] 扫描进度: 0% (0/{total_files}) 速度:0.0文件/秒", flush=True)
			
			processed_files = 0  # 已处理文件的累计数（用于进度）
			for i, batch_payload in enumerate(results_iter):
				if isinstance(batch_payload, tuple) and len(batch_payload) == 2:
					batch_files, batch_results = batch_payload
				else:
					batch_files, batch_results = [], batch_payload

				if batch_files:
					scanned_files.update(batch_files)
					processed_files += len(batch_files)
				else:
					processed_files = min(processed_files + batch_size, total_files)

				processed_count += len(batch_results) if isinstance(batch_results, list) else 0
				if batch_results:
					result_count += len(batch_results)
					file_appender.append(batch_results)

				percent = int((processed_files / total_files) * 100) if total_files > 0 else 0
				current_time = time.time()
				elapsed_time = current_time - start_time
				files_per_sec = processed_files / elapsed_time if elapsed_time > 0 else 0
				remaining_files = total_files - processed_files
				eta_seconds = remaining_files / files_per_sec if files_per_sec > 0 else 0
				if eta_seconds < 60:
					eta_str = f"{int(eta_seconds)}秒"
				elif eta_seconds < 3600:
					eta_str = f"{int(eta_seconds/60)}分"
				else:
					eta_str = f"{eta_seconds/3600:.1f}小时"

				# 每批或每 5 批打印一次进度（用 i 判断，避免受 processed_files 步长影响）
				if i == 0 or files_per_sec > 0:
					display_file = ("..." + file_list[min(processed_files - 1, total_files - 1)][-37:]) if processed_files <= total_files and len(file_list[min(processed_files - 1, total_files - 1)]) > 40 else ""
					current_info = f" 当前:{display_file}" if display_file else ""
					print(f"[{time.strftime('%H:%M:%S')}] 扫描进度: {percent}% ({processed_files}/{total_files}) 速度:{files_per_sec:.1f}文件/秒 ETA:{eta_str}{current_info}", flush=True)

				# 小规模尾扫时每批落盘，避免中断后回退太多。
				if (i + 1) % checkpoint_every_batches == 0 or (i + 1) == num_batches:
					last_file = batch_files[-1] if batch_files else (
						file_list[min(processed_files - 1, total_files - 1)] if processed_files > 0 else None
					)
					checkpoint_data = {
						"total_files": total_files,
						"processed_files": processed_files,
						"processed_count": processed_count,
						"last_file": last_file,
						"percent": percent,
						"batch_index": i + 1,
						"total_batches": num_batches,
						"scanned_files": len(scanned_files),
					}
					save_checkpoint_fast(checkpoint_data, save_root)
					save_scan_progress(scanned_files, save_root)
					save_scan_progress_checkpoint(scanned_files, save_root)
					file_appender._flush()

			# 主循环结束，关闭进程池
			pool.close()
			pool.join()
			total_processed_files = processed_files  # 总共处理的文件数

			# 从文件加载新扫描的结果
			hit_dict = []
			if os.path.exists(result_file):
				print(f"[{time.strftime('%H:%M:%S')}] 正在加载扫描结果...", flush=True)
				hit_dict, duplicate_count = load_scan_results_jsonl(result_file)
				print(f"[{time.strftime('%H:%M:%S')}] 已加载 {len(hit_dict)} 条扫描结果, 去重 {duplicate_count} 条", flush=True)

		save_scan_progress(scanned_files, save_root)

		# 合并之前已有的结果（existing_hit_dict 在 resume 时已加载）
		if existing_hit_dict is not None and len(existing_hit_dict) > 0:
			# 去重：根据 file 字段去重
			existing_files = {r.get('file', '') for r in existing_hit_dict if r}
			new_unique = [r for r in hit_dict if r.get('file', '') not in existing_files]
			hit_dict = existing_hit_dict + new_unique
			print(f"[{time.strftime('%H:%M:%S')}] 合并结果: 之前 {len(existing_hit_dict)} + 新增 {len(new_unique)} = 共 {len(hit_dict)} 条")

		# 打印最终进度
		if scan_completed_from_checkpoint and total_processed_files > 0:
			print(f"\n扫描阶段已完成! 复用已有结果继续后处理: 共处理 {total_processed_files} 个文件, 命中 {len(hit_dict)} 条结果")
		else:
			elapsed_time = time.time() - start_time
			avg_speed = total_processed_files / elapsed_time if elapsed_time > 0 else 0
			print(f"\n扫描完成! 共处理 {total_processed_files} 个文件, 命中 {len(hit_dict)} 条结果, 耗时 {elapsed_time:.1f} 秒, 平均速度 {avg_speed:.1f} 文件/秒")

		# 删除中间检查点
		import shutil
		checkpoint_dir = os.path.join(save_root, "checkpoints")
		if os.path.exists(checkpoint_dir):
			shutil.rmtree(checkpoint_dir)
			print("已清理中间检查点")

	if args.resume and os.path.exists(filtered_cache):
		print(f"[恢复] 检测到已有 origin_filtered.bin，跳过初筛阶段: {filtered_cache}", flush=True)
		filtered = read_dict_bin(filtered_cache)
		print(f"hit:{len(filtered)}")
	else:
		print(f"length_single_dict:{len(hit_dict)}")
		#hit_dict = scan_project_tf(file_list)
		save_dict2bin(hit_dict,"hit_dict",save_root)        #方便后续继续运行

		words_list=read_json('./data/fixed_top_english_words_mixed_500000.json')
		patterns = []
		with open('./data/patterns.txt', "r") as f:
			patterns = f.readlines()
		patterns = [pattern.strip() for pattern in patterns]
		batch_size=len(hit_dict)//num_cores
		tmp_filter=[]
		filtered=[]
		with Pool(processes=num_cores) as pool:
			for i in range(num_cores):
				start_idx = i * batch_size
				end_idx = (i + 1) * batch_size if i < num_cores - 1 else len(hit_dict)
				batch_files = hit_dict[start_idx:end_idx]
				tmp_filter.append(pool.apply_async(filter_pattern_word, (batch_files,words_list,patterns,rules_single,log_path)))
			pool.close()
			pool.join()
		for tmp in tmp_filter:
			tmp=tmp.get()
			filtered.extend(tmp)
		#filtered = filter_pattern_word(hit_dict, args.entropy_path, log_path,rules_single)  # 熵过滤器
		print(f"hit:{len(filtered)}")
		save_dict2bin(filtered,"origin_filtered",save_root)        #保存结果

	pass_dict=[]
	token_dict=[]
	for tmp in filtered:
		if 'pass' in tmp['rule_name']:
			pass_dict.append(tmp)
		else:
			token_dict.append(tmp)
	print(f"[5.0/7] 密码候选二次过滤 ... pass候选:{len(pass_dict)} 非pass:{len(token_dict)}", flush=True)
	result=list(token_dict)
	if pass_dict:
		password_workers = max(1, min(num_cores, len(pass_dict)))
		batch_size = max(1, (len(pass_dict) + password_workers - 1) // password_workers)
		pass_batches = [pass_dict[i:i + batch_size] for i in range(0, len(pass_dict), batch_size)]
		kept_pass = 0
		progress_interval = max(1, len(pass_batches) // 10)
		print(f"[5.0/7] 启动密码过滤进程池: workers={password_workers}, batches={len(pass_batches)}, batch_size≈{batch_size}", flush=True)
		with Pool(processes=password_workers) as pool:
			for idx, tmp in enumerate(pool.imap_unordered(filter_password, pass_batches, chunksize=1), 1):
				kept_pass += len(tmp)
				result.extend(tmp)
				if idx == 1 or idx % progress_interval == 0 or idx == len(pass_batches):
					print(f"[5.1/7] 密码过滤进度: {idx}/{len(pass_batches)} 批, 保留pass结果 {kept_pass} 条", flush=True)
	else:
		print("[5.0/7] 无 pass 候选，跳过密码过滤", flush=True)

	print(f"[5.2/7] 相似串合并前: {len(result)} 条", flush=True)
	t3=time.time()
	result=combine_similarstr(result)
	print(f"[5.3/7] 相似串合并后: {len(result)} 条, 耗时 {time.time()-t3:.1f}s", flush=True)
	#——————————————
	# 阶段5: 风险分类
	print(f"[5.5/7] 风险分类 ...", flush=True)
	t4=time.time()
	result_before_classify = result
	result = add_risk_label(result)
	elapsed4 = time.time() - t4
	dropped_fp = len(result_before_classify) - len(result)
	print(f"    风险分类完成: {len(result_before_classify)} -> {len(result)} 条（过滤 FP {dropped_fp} 条）, 耗时 {elapsed4:.1f}s", flush=True)
	logger_instance.info(f"risk_classify:{len(result)}, dropped_fp:{dropped_fp}")
	# 风险分类统计
	risk_stats = {}
	for tmp in result:
		label = tmp.get("risk_label", "Unknown")
		risk_stats[label] = risk_stats.get(label, 0) + 1
	print(f"    风险分布: {risk_stats}")

	save_hit_dict_trufflehog(result,args.save_name,save_root)  #保存结果状态

	for tmp in result:
		tmp.pop("prefix", None)
		tmp.pop("is_mechanical", None)			
		tmp.pop("filter_count", None)
		tmp.pop("word_weight", None)			
		tmp.pop("col_start", None)
		tmp.pop("col_end", None)
		tmp.pop("index_start", None)
		tmp.pop("index_end", None)
		tmp.pop("regex", None)
		tmp.pop("need_keyvalue", None)

	save_hit_dict_trufflehog(result,args.save_name+"_reduced",save_root)  #保存结果状态
	#print("测试结束——————————————————————————")
	logger_instance.info(f"time_wasted:{time.time()-time1}")

	#hf——————————————
	ddd=[]
	jwt=[]

	for tmp in result:
		if tmp['rule_name']=='jwt' or "eyJh" in tmp['value']:
			jwt.append(tmp)
		else:
			ddd.append(tmp)
	write_json(os.path.join(save_root,"hflog_reduced_others.json"),ddd)    
	write_json(os.path.join(save_root,"hflog_reduced_jwt.json"),jwt)
