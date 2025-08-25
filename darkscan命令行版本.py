import os
import sys
import csv
import json
import re
import threading
import signal
import shutil
import subprocess
import time  # 添加time模块导入
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urljoin

# 确保中文显示正常
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 检查并安装缺失的依赖
def install_missing_dependencies():
    required_packages = {
        "requests": "requests",
        "bs4": "beautifulsoup4",
        "schedule": "schedule"
    }
    
    missing = []
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print(f"检测到缺失的依赖包: {', '.join(missing)}")
        print("正在自动安装，请稍候...")
        
        # 使用pip安装缺失的包
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                "--upgrade pip",
                *missing
            ])
            print("依赖包安装完成")
        except subprocess.CalledProcessError as e:
            print(f"依赖包安装失败: {e}")
            print("请手动安装以下包后重试:")
            print(f"pip install {' '.join(missing)}")
            sys.exit(1)

# 先检查并安装依赖
install_missing_dependencies()

# 现在导入需要的库
import requests
from bs4 import BeautifulSoup
import schedule

# 获取脚本所在目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 配置文件路径
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
DEFAULT_RULES_PATH = os.path.join(SCRIPT_DIR, "rules.txt")
RULES_DIR = os.path.join(SCRIPT_DIR, "rules")
SCAN_RESULTS_DIR = os.path.join(SCRIPT_DIR, "scan_results")
BASE_CONTENTS_DIR = os.path.join(SCRIPT_DIR, "base_contents")

# 全局状态跟踪与锁
global_state = {
    "is_terminated": False,
    "current_url": None,
    "processed_urls": 0,
    "total_urls": 0,
    "results": [],
    "start_time": None,
    "active_threads": 0,
    "save_lock": threading.Lock()  # 用于文件保存的锁
}
state_lock = threading.Lock()  # 状态锁定义

# 线程安全的日志锁
log_lock = threading.Lock()

def print_darkscan_banner():
    """打印DarkScan图案和作者信息"""
    banner = r"""
                           .---.        .-----------
                          /     \  __  /    ------
                         / /     \(  )/    -----
                        //////   ' \/ `   ---
                       //// / // :    : ---
                      // /   /  /`    '--
                     //          //..\\
                        _____//..//
                       /     '     `'.
                      /  /         \  \
                     /  /           \  \
                    /  /             \  \
                   /  /               \  \
                  /  /                 \  \
                 /  /                   \  \
                /  /                     \  \
               /  /                       \  \
              /  /                         \  \
             /  /                           \  \
            /  /                             \  \
+-----------------------------------------------------------+
|                      DarkScan Tool                        |
|                     Author: p1r07                        |
|            支持强制终止与状态保存的优化版本               |
+-----------------------------------------------------------+
    """
    print(banner)

def print_main_menu():
    """打印主菜单（数字选择模式）"""
    print("\n" + "="*60)
    print("                     功能菜单                     ")
    print("="*60)
    print("1. 快速扫描 (只分析一级子链接)")
    print("2. 深度扫描 (可自定义分析深度)")
    print("3. 初始化基准内容 (用于篡改检测)")
    print("4. 配置扫描参数 (线程数、超时等)")
    print("5. 加载自定义规则文件")
    print("6. 定时扫描设置")
    print("7. 配置威胁情报API密钥")
    print("8. 查看扫描历史")
    print("0. 退出程序")
    print("="*60)
    
    try:
        choice = int(input("请选择功能 (0-8): ").strip())
        if 0 <= choice <= 8:
            return choice
        else:
            print("请输入0-8之间的数字")
            return None
    except ValueError:
        print("请输入有效的数字")
        return None

def handle_termination(signum, frame):
    """处理强制终止信号（兼容Windows和Unix系统，修复资源释放问题）"""
    # 双重检查终止状态，避免重复处理
    with state_lock:
        if global_state["is_terminated"]:
            print("\n再次收到终止信号，强制退出...")
            # 使用os._exit代替sys.exit，避免触发额外清理
            os._exit(1)
            
        # 根据系统显示不同的终止提示
        if sys.platform.startswith('win32'):
            print("\n" + "="*60)
            print(f"[!] 收到终止信号 (Ctrl+C)，正在保存当前状态...")
        else:
            print("\n" + "="*60)
            print(f"[!] 收到终止信号 (Ctrl+Z)，正在保存当前状态...")
            
        global_state["is_terminated"] = True
    
    # 输出当前分析状态
    with state_lock:
        elapsed_time = datetime.now() - global_state["start_time"] if global_state["start_time"] else 0
        print("\n当前分析状态:")
        print(f"总URL数: {global_state['total_urls']}")
        print(f"已处理: {global_state['processed_urls']}/{global_state['total_urls']}")
        print(f"当前处理: {global_state['current_url'] or '无'}")
        print(f"活跃线程: {global_state['active_threads']}")
        print(f"已分析链接数: {len(global_state['results'])}")
        print(f"运行时间: {str(elapsed_time)}")
    
    # 保存当前结果（使用专用锁确保线程安全）
    save_path = None
    if global_state["results"]:
        try:
            with global_state["save_lock"]:
                save_path = save_scan_results(global_state["results"], "interrupted_scan")
            if save_path:
                print(f"\n[!] 中间结果已保存至: {save_path}")
            else:
                print("\n[!] 尝试保存结果失败")
        except Exception as e:
            print(f"\n[!] 保存结果时发生错误: {str(e)}")
    else:
        print("\n[!] 暂无结果可保存")
    
    print("\n程序已安全终止")
    # 使用os._exit避免触发其他异常
    os._exit(0)

def get_unique_filename(base_dir, base_name, extension):
    """生成唯一的文件名，若存在同名文件则添加计数器"""
    try:
        if not os.path.exists(base_dir):
            os.makedirs(base_dir, exist_ok=True)  # 使用exist_ok避免目录创建冲突
            
        if base_name.endswith(f".{extension}"):
            base_name = base_name[:-len(f".{extension}")]
    
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{base_name}_{timestamp}.{extension}"
        file_path = os.path.join(base_dir, filename)
        
        counter = 1
        while os.path.exists(file_path):
            filename = f"{base_name}_{timestamp}_{counter}.{extension}"
            file_path = os.path.join(base_dir, filename)
            counter += 1
            if counter > 1000:
                raise Exception("无法生成唯一的文件名，已尝试1000次")
        
        return file_path
    except Exception as e:
        print(f"生成唯一文件名失败: {str(e)}")
        # 生成一个应急文件名
        emergency_filename = f"emergency_save_{os.getpid()}.{extension}"
        return os.path.join(base_dir, emergency_filename)

def save_scan_results(results, base_filename="scan_results"):
    """保存扫描结果为CSV文件，增强错误处理"""
    try:
        file_path = get_unique_filename(SCAN_RESULTS_DIR, base_filename, "csv")
        
        # 验证目录可写性
        if not os.access(os.path.dirname(file_path), os.W_OK):
            raise Exception(f"目录不可写: {os.path.dirname(file_path)}")
        
        fieldnames = [
            "检测时间", "父级URL", "链接类型", "原始链接", "绝对链接",
            "HTTP状态码", "递归深度", "URL规则匹配项", "内容规则匹配项",
            "标签文本内容", "是否匹配URL规则", "是否匹配内容规则",
            "是否恶意", "威胁情报详情"
        ]
        
        # 尝试写入文件，使用临时文件再重命名的方式确保原子性
        temp_file = f"{file_path}.tmp"
        with open(temp_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # 确保所有字段都存在
                row_data = {}
                for field in fieldnames:
                    # 根据字段名映射到结果中的键
                    if field == "检测时间":
                        row_data[field] = result.get("timestamp", "")
                    elif field == "父级URL":
                        row_data[field] = result.get("parent_url", "")
                    elif field == "链接类型":
                        row_data[field] = result.get("link_type", "")
                    elif field == "原始链接":
                        row_data[field] = result.get("original_link", "")
                    elif field == "绝对链接":
                        row_data[field] = result.get("absolute_link", "")
                    elif field == "HTTP状态码":
                        row_data[field] = result.get("status_code", "")
                    elif field == "递归深度":
                        row_data[field] = result.get("depth", "")
                    elif field == "URL规则匹配项":
                        row_data[field] = ", ".join(result.get("url_matches", []))
                    elif field == "内容规则匹配项":
                        row_data[field] = ", ".join(result.get("content_matches", []))
                    elif field == "标签文本内容":
                        row_data[field] = result.get("tag_content", "")
                    elif field == "是否匹配URL规则":
                        row_data[field] = "是" if result.get("is_rule_match", False) else "否"
                    elif field == "是否匹配内容规则":
                        row_data[field] = "是" if result.get("is_content_match", False) else "否"
                    elif field == "是否恶意":
                        row_data[field] = "是" if result.get("is_malicious", False) else "否"
                    elif field == "威胁情报详情":
                        row_data[field] = "\n".join(result.get("threat_info", []))
                    else:
                        row_data[field] = ""
                
                writer.writerow(row_data)
        
        # 临时文件写入成功后，重命名为目标文件（原子操作）
        if os.path.exists(file_path):
            os.remove(file_path)
        os.rename(temp_file, file_path)
        
        return file_path
    except Exception as e:
        print(f"保存扫描结果失败: {str(e)}")
        # 清理临时文件
        if 'temp_file' in locals() and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        return None

def log(message, url=None):
    """线程安全的日志输出"""
    with log_lock:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if url:
            print(f"[{timestamp}] [{url}] {message}")
        else:
            print(f"[{timestamp}] {message}")

def load_config():
    """加载配置文件"""
    config = {
        "virustotal_api_key": "",
        "weibu_api_key": "",
        "qiankong_api_key": "",
        "max_depth": 1,  # 默认只分析一级子链接
        "timeout": 15,
        "default_threads": 5,
        "schedule_interval": 60,
        "regex_flags": re.IGNORECASE,
        "rules_files": ["rules.txt"]
    }
    
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            print(f"加载配置文件失败: {str(e)}，使用默认配置")
    
    return config

def save_config(config):
    """保存配置到文件"""
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        print(f"配置已保存到 {CONFIG_PATH}")
    except Exception as e:
        print(f"保存配置文件失败: {str(e)}")

def load_urls_from_file(file_path=None):
    """从文件加载URL列表"""
    if not file_path:
        # 查找可能的URL文件
        possible_files = ["urls.txt", "websites.txt", "site_list.txt"]
        for fname in possible_files:
            test_path = os.path.join(SCRIPT_DIR, fname)
            if os.path.exists(test_path):
                file_path = test_path
                break
        
        # 如果没有找到，创建默认文件
        if not file_path:
            file_path = os.path.join(SCRIPT_DIR, "urls.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("# 请在此文件中添加URL，每行一个\n")
                f.write("https://example.com\n")
            print(f"已创建默认URL文件: {file_path}，请编辑后重新运行")
            return []
    
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                url = line.strip()
                if not url or url.startswith('#'):
                    continue
                if not url.startswith(('http://', 'https://')):
                    print(f"警告: 第{line_num}行URL格式不正确，已跳过: {url}")
                    continue
                urls.append(url)
        print(f"从 {os.path.basename(file_path)} 加载了 {len(urls)} 个URL")
        return urls
    except Exception as e:
        print(f"加载URL文件失败: {str(e)}")
        return []

def get_page_content(url, timeout=15):
    """获取网页内容，增加重试机制"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    
    # 最多重试2次
    for attempt in range(3):
        try:
            # 检查是否已收到终止信号
            with state_lock:
                if global_state["is_terminated"]:
                    return None
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=True,
                verify=True  # 验证SSL证书
            )
            response.raise_for_status()
            return {
                "content": response.text,
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers)
            }
        except requests.exceptions.SSLError:
            log(f"SSL证书错误，尝试跳过验证...", url)
            try:
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=timeout, 
                    allow_redirects=True,
                    verify=False  # 跳过SSL验证
                )
                return {
                    "content": response.text,
                    "final_url": response.url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "warning": "SSL验证已跳过"
                }
            except Exception as e:
                if attempt < 2:
                    time.sleep(1)  # 短暂延迟后重试
                    continue
                log(f"SSL错误: {str(e)}", url)
                return None
        except Exception as e:
            if attempt < 2:
                time.sleep(1)  # 短暂延迟后重试
                continue
            log(f"获取页面失败: {str(e)}", url)
            return None

def extract_links_from_tags(soup, base_url):
    """从HTML标签提取链接，增加过滤机制"""
    links = []
    tags = {
        'a': 'href',
        'script': 'src',
        'img': 'src',
        'iframe': 'src',
        'link': 'href',
        'form': 'action'
    }
    
    seen_links = set()  # 用于去重
    
    for tag, attr in tags.items():
        elements = soup.find_all(tag)
        for elem in elements:
            if attr in elem.attrs:
                original_link = elem[attr].strip()
                if not original_link or original_link in seen_links:
                    continue
                    
                seen_links.add(original_link)
                absolute_link = urljoin(base_url, original_link)
                
                # 过滤邮件链接和javascript链接
                if absolute_link.startswith(('mailto:', 'javascript:')):
                    continue
                    
                links.append({
                    'original_link': original_link,
                    'absolute_link': absolute_link,
                    'tag': tag,
                    'element': str(elem),
                    'text_content': elem.get_text(strip=True)
                })
    
    return links

def load_rules(config):
    """加载检测规则"""
    # 确保规则目录存在
    if not os.path.exists(RULES_DIR):
        os.makedirs(RULES_DIR, exist_ok=True)
    
    # 确保默认规则文件存在
    if not os.path.exists(DEFAULT_RULES_PATH):
        with open(DEFAULT_RULES_PATH, 'w', encoding='utf-8') as f:
            f.write("# 暗链检测规则文件\n")
            f.write("# 每行一条规则，格式：类型:内容\n")
            f.write("keyword:赌博\n")
            f.write("keyword:色情\n")
            f.write("domain:bad.example.com\n")
            f.write("regex:.*?malicious.*?\n")
    
    rules = {
        "keywords": [],
        "domains": [],
        "regex_patterns": [],
        "content_keywords": []
    }
    
    # 加载所有指定的规则文件
    for filename in config["rules_files"]:
        if os.path.isabs(filename):
            file_path = filename
        else:
            file_path = os.path.join(RULES_DIR, filename)
            if not os.path.exists(file_path):
                file_path = os.path.join(SCRIPT_DIR, filename)
        
        if not os.path.exists(file_path):
            print(f"规则文件 {filename} 不存在，已跳过")
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    if ':' in line:
                        rule_type, rule_content = line.split(':', 1)
                        rule_type = rule_type.strip().lower()
                        rule_content = rule_content.strip()
                        
                        if rule_type == 'keyword':
                            rules["keywords"].append(rule_content)
                        elif rule_type == 'domain':
                            rules["domains"].append(rule_content)
                        elif rule_type == 'regex':
                            rules["regex_patterns"].append(rule_content)
                        elif rule_type == 'content_keyword':
                            rules["content_keywords"].append(rule_content)
            print(f"已加载规则文件: {os.path.basename(file_path)}")
        except Exception as e:
            print(f"加载规则文件 {filename} 失败: {str(e)}")
    
    # 去重处理
    for key in rules:
        rules[key] = list(set(rules[key]))
        
    return rules

def match_rules(link_info, rules, config):
    """规则匹配逻辑"""
    url_matches = []
    content_matches = []
    
    # URL匹配
    link = link_info["absolute_link"]
    parsed = urlparse(link)
    
    # 关键词匹配
    for keyword in rules["keywords"]:
        if keyword.lower() in link.lower():
            url_matches.append(f"关键词: {keyword}")
    
    # 域名匹配
    for domain in rules["domains"]:
        if domain.lower() in parsed.netloc.lower():
            url_matches.append(f"域名: {domain}")
    
    # 正则匹配
    for pattern in rules["regex_patterns"]:
        try:
            if re.search(pattern, link, config["regex_flags"]):
                url_matches.append(f"正则: {pattern}")
        except re.error as e:
            log(f"无效正则表达式: {pattern} ({str(e)})", link)
    
    # 内容匹配
    for keyword in rules["content_keywords"]:
        if keyword.lower() in link_info["text_content"].lower():
            content_matches.append(f"内容关键词: {keyword}")
    
    return url_matches, content_matches

def analyze_child_link(link_info, parent_url, depth, max_depth, rules, config):
    """分析子链接，增加线程状态跟踪"""
    # 检查是否已收到终止信号
    with state_lock:
        if global_state["is_terminated"]:
            return []
        global_state["active_threads"] += 1
    
    try:
        if depth > max_depth:
            return []
        
        log(f"分析子链接 (深度: {depth}): {link_info['absolute_link'][:50]}...", parent_url)
        
        page_data = get_page_content(link_info["absolute_link"], config["timeout"])
        if not page_data:
            return []
        
        # 规则匹配
        url_matches, content_matches = match_rules(link_info, rules, config)
        is_rule_match = len(url_matches) > 0
        is_content_match = len(content_matches) > 0
        
        # 简化的恶意链接判断
        is_malicious = is_rule_match and is_content_match
        threat_info = []
        if is_malicious:
            threat_info.append("匹配规则判定为恶意链接")
        
        result = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "parent_url": parent_url,
            "link_type": f"{link_info['tag']}标签",
            "original_link": link_info["original_link"],
            "absolute_link": link_info["absolute_link"],
            "status_code": page_data.get("status_code", "未知"),
            "depth": depth,
            "url_matches": url_matches,
            "content_matches": content_matches,
            "tag_content": link_info["text_content"],
            "is_rule_match": is_rule_match,
            "is_content_match": is_content_match,
            "is_malicious": is_malicious,
            "threat_info": threat_info
        }
        
        # 如果未达到最大深度且不是终止状态，继续分析下一级
        results = [result]
        if depth < max_depth:
            try:
                soup = BeautifulSoup(page_data["content"], "html.parser")
                child_links = extract_links_from_tags(soup, page_data["final_url"])
                
                # 限制子链接分析数量，防止过度蔓延
                max_child_analyze = 20  # 每个页面最多分析20个子链接
                child_links = child_links[:max_child_analyze]
                
                for child_link in child_links:
                    with state_lock:
                        if global_state["is_terminated"]:
                            break
                    child_results = analyze_child_link(
                        child_link, 
                        link_info["absolute_link"], 
                        depth + 1, 
                        max_depth,
                        rules,
                        config
                    )
                    results.extend(child_results)
            except Exception as e:
                log(f"解析子链接内容失败: {str(e)}", link_info["absolute_link"])
        
        return results
    finally:
        # 确保线程计数正确减少
        with state_lock:
            global_state["active_threads"] -= 1

def run_single_scan(url, max_depth, rules, config):
    """扫描单个URL，增加状态跟踪"""
    with state_lock:
        if global_state["is_terminated"]:
            return []
    
    log("开始检测...", url)
    
    # 更新当前URL状态
    with state_lock:
        global_state["current_url"] = url
    
    page_data = get_page_content(url, config["timeout"])
    if not page_data:
        with state_lock:
            global_state["processed_urls"] += 1
            global_state["current_url"] = None
        return []
    
    try:
        soup = BeautifulSoup(page_data["content"], "html.parser")
        links = extract_links_from_tags(soup, page_data["final_url"])
        log(f"提取到 {len(links)} 个链接", url)
    except Exception as e:
        log(f"解析HTML失败: {str(e)}", url)
        with state_lock:
            global_state["processed_urls"] += 1
            global_state["current_url"] = None
        return []
    
    # 多线程分析链接
    results = []
    # 根据链接数量动态调整线程数
    link_threads = min(5, max(1, len(links) // 3))
    
    with ThreadPoolExecutor(max_workers=link_threads) as executor:
        futures = [executor.submit(
            analyze_child_link, 
            link, 
            url, 
            1, 
            max_depth,
            rules,
            config
        ) for link in links]
        
        for future in as_completed(futures):
            with state_lock:
                if global_state["is_terminated"]:
                    executor.shutdown(wait=False)
                    break
            try:
                link_results = future.result()
                results.extend(link_results)
            except Exception as e:
                log(f"链接分析失败: {str(e)}", url)
    
    # 更新处理状态
    with state_lock:
        global_state["processed_urls"] += 1
        global_state["current_url"] = None
        global_state["results"].extend(results)
    
    log("检测完成", url)
    return results

def run_batch_scan(urls, max_depth, config):
    """批量扫描URL，增加进度显示和异常处理"""
    # 加载规则
    rules = load_rules(config)
    
    # 初始化全局状态
    with state_lock:
        global_state["start_time"] = datetime.now()
        global_state["total_urls"] = len(urls)
        global_state["processed_urls"] = 0
        global_state["results"] = []
        global_state["is_terminated"] = False
        global_state["active_threads"] = 0
    
    # 根据系统显示不同的终止提示
    if sys.platform.startswith('win32'):
        termination_hint = "Ctrl+C"
    else:
        termination_hint = "Ctrl+Z"
    
    print(f"\n开始批量扫描，共 {len(urls)} 个URL，使用 {config['default_threads']} 个线程，最大深度: {max_depth}")
    print(f"提示: 按 {termination_hint} 可强制终止并保存当前结果\n")
    
    # 启动进度显示线程
    def progress_monitor():
        while True:
            with state_lock:
                processed = global_state["processed_urls"]
                total = global_state["total_urls"]
                current_url = global_state["current_url"]
                is_terminated = global_state["is_terminated"]
                
            if total == 0:
                progress = 0
            else:
                progress = (processed / total) * 100
                
            print(f"\r扫描进度: {processed}/{total} ({progress:.1f}%) 当前: {current_url[:50] if current_url else '准备中'}", end="")
            
            if is_terminated or processed >= total:
                break
                
            time.sleep(1)
    
    progress_thread = threading.Thread(target=progress_monitor, daemon=True)
    progress_thread.start()
    
    try:
        with ThreadPoolExecutor(max_workers=config["default_threads"]) as executor:
            futures = {executor.submit(run_single_scan, url, max_depth, rules, config): url for url in urls}
            
            for future in as_completed(futures):
                with state_lock:
                    if global_state["is_terminated"]:
                        executor.shutdown(wait=False, cancel_futures=True)  # 取消所有未完成的任务
                        break
                url = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log(f"URL扫描失败: {str(e)}", url)
    except Exception as e:
        print(f"扫描过程出错: {str(e)}")
        # 如果发生异常且未终止，则标记为终止
        with state_lock:
            if not global_state["is_terminated"]:
                global_state["is_terminated"] = True
    
    # 等待进度线程结束
    progress_thread.join()
    print()  # 换行
    
    # 扫描完成后保存结果
    with state_lock:
        if not global_state["is_terminated"] and global_state["results"]:
            save_path = save_scan_results(global_state["results"])
            if save_path:
                print(f"\n扫描完成，结果已保存至: {save_path}")
                
                # 打印简要统计
                malicious_count = sum(1 for link in global_state["results"] if link["is_malicious"])
                print(f"发现 {malicious_count} 个可疑恶意链接")
            else:
                print("\n扫描完成，但保存结果失败")
    
    return global_state["results"]

def init_base_contents(urls, config):
    """初始化基准内容，用于后续篡改检测"""
    if not os.path.exists(BASE_CONTENTS_DIR):
        os.makedirs(BASE_CONTENTS_DIR, exist_ok=True)
    
    success_count = 0
    print(f"开始初始化 {len(urls)} 个URL的基准内容...")
    
    with ThreadPoolExecutor(max_workers=config["default_threads"]) as executor:
        futures = {executor.submit(get_page_content, url, config["timeout"]): url for url in urls}
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                page_data = future.result()
                if page_data and "content" in page_data:
                    # 生成安全的文件名
                    parsed_url = urlparse(url)
                    filename = f"{parsed_url.netloc.replace(':', '_')}.html"
                    file_path = os.path.join(BASE_CONTENTS_DIR, filename)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(page_data["content"])
                    
                    success_count += 1
                    log(f"已保存基准内容", url)
            except Exception as e:
                log(f"初始化基准内容失败: {str(e)}", url)
    
    print(f"基准内容初始化完成，成功 {success_count}/{len(urls)}")
    return success_count

def view_scan_history():
    """查看扫描历史"""
    if not os.path.exists(SCAN_RESULTS_DIR) or not os.listdir(SCAN_RESULTS_DIR):
        print("暂无扫描历史记录")
        return
    
    print("\n===== 扫描历史 =====")
    # 获取并按时间排序所有结果文件
    files = []
    for fname in os.listdir(SCAN_RESULTS_DIR):
        if fname.endswith(".csv"):
            fpath = os.path.join(SCAN_RESULTS_DIR, fname)
            ftime = os.path.getctime(fpath)
            files.append((-ftime, fname, fpath))  # 负号用于倒序排序
    
    # 按时间倒序排列
    files.sort()
    
    # 显示最近10条记录
    for i, (_, fname, fpath) in enumerate(files[:10], 1):
        fsize = os.path.getsize(fpath) / 1024  # KB
        fdate = datetime.fromtimestamp(os.path.getctime(fpath)).strftime('%Y-%m-%d %H:%M')
        print(f"{i}. {fname} ({fsize:.1f}KB) - {fdate}")
    
    # 允许查看特定记录详情
    try:
        choice = input("\n请输入要查看的记录编号 (0返回): ").strip()
        if choice == '0':
            return
            
        idx = int(choice) - 1
        if 0 <= idx < len(files[:10]):
            _, fname, fpath = files[idx]
            print(f"\n查看记录: {fname}")
            print("-"*60)
            
            # 读取并显示前5条记录
            with open(fpath, 'r', encoding='utf-8-sig') as f:
                reader = csv.reader(f)
                headers = next(reader)  # 表头
                print(", ".join(headers[:5]) + "...")  # 只显示部分表头
                
                count = 0
                for row in reader:
                    if count >= 5:  # 只显示前5条
                        print("...")
                        break
                    print(", ".join(row[:5]) + "...")  # 只显示部分内容
                    count += 1
            
            print("-"*60)
            print(f"文件路径: {fpath}")
    except (ValueError, IndexError):
        print("无效的选择")

def setup_scheduled_scan(config):
    """设置定时扫描"""
    print("\n===== 定时扫描设置 =====")
    print(f"当前设置: 每 {config['schedule_interval']} 分钟扫描一次")
    
    try:
        interval = input("请输入新的扫描间隔(分钟，0取消定时): ").strip()
        if not interval:
            return
            
        interval = int(interval)
        if interval == 0:
            config["schedule_interval"] = 0
            save_config(config)
            print("已取消定时扫描")
            return
            
        if interval < 5:
            print("扫描间隔不能小于5分钟")
            return
            
        config["schedule_interval"] = interval
        save_config(config)
        
        # 显示定时扫描信息
        print(f"定时扫描已设置为每 {interval} 分钟一次")
        print("提示: 请保持程序运行以启用定时扫描功能")
        
        # 启动定时任务
        def scheduled_job():
            print(f"\n===== 定时扫描开始 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) =====")
            urls = load_urls_from_file()
            if urls:
                run_batch_scan(urls, config["max_depth"], config)
            else:
                print("未找到有效的URL，定时扫描取消")
        
        # 立即执行一次，然后按间隔执行
        scheduled_job()
        schedule.every(interval).minutes.do(scheduled_job)
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n用户中断，定时扫描停止")
            
    except ValueError:
        print("请输入有效的数字")

def main():
    # 确保必要目录存在
    for dir_path in [SCAN_RESULTS_DIR, RULES_DIR, BASE_CONTENTS_DIR]:
        try:
            os.makedirs(dir_path, exist_ok=True)
        except Exception as e:
            print(f"创建目录 {dir_path} 失败: {str(e)}")
            print("程序可能无法正常运行，建议检查目录权限")
    
    # 根据操作系统类型注册不同的信号处理器
    try:
        if sys.platform.startswith('win32'):
            # Windows系统使用SIGINT (Ctrl+C)
            signal.signal(signal.SIGINT, handle_termination)
        else:
            # 类Unix系统使用SIGTSTP (Ctrl+Z)
            signal.signal(signal.SIGTSTP, handle_termination)
    except Exception as e:
        print(f"信号处理初始化警告: {str(e)}")
        print("强制终止功能可能无法正常工作")
    
    print_darkscan_banner()
    config = load_config()
    
    while True:
        try:
            choice = print_main_menu()
            if choice is None:
                continue
            
            if choice == 0:
                print("感谢使用，再见！")
                break
            
            elif choice == 1:
                # 快速扫描（一级子链接）
                urls = load_urls_from_file()
                if urls:
                    run_batch_scan(urls, max_depth=1, config=config)
            
            elif choice == 2:
                # 深度扫描（自定义深度）
                try:
                    depth = int(input("请输入最大扫描深度 (1-5): ").strip())
                    if not 1 <= depth <= 5:
                        print("深度必须在1-5之间")
                        continue
                except ValueError:
                    print("请输入有效的数字")
                    continue
                
                urls = load_urls_from_file()
                if urls:
                    run_batch_scan(urls, max_depth=depth, config=config)
            
            elif choice == 3:
                # 初始化基准内容
                urls = load_urls_from_file()
                if urls:
                    init_base_contents(urls, config)
            
            elif choice == 4:
                # 配置扫描参数
                print("\n===== 扫描参数配置 =====")
                try:
                    threads = input(f"请输入默认线程数 (当前: {config['default_threads']}): ").strip()
                    if threads:
                        threads = int(threads)
                        if threads > 0 and threads <= 20:  # 限制最大线程数
                            config["default_threads"] = threads
                        else:
                            print("线程数必须在1-20之间")
                except ValueError:
                    print("线程数输入无效，保持默认值")
                
                try:
                    timeout = input(f"请输入超时时间(秒) (当前: {config['timeout']}): ").strip()
                    if timeout:
                        timeout = int(timeout)
                        if timeout > 0 and timeout <= 60:  # 限制超时范围
                            config["timeout"] = timeout
                        else:
                            print("超时时间必须在1-60之间")
                except ValueError:
                    print("超时时间输入无效，保持默认值")
                
                try:
                    depth = input(f"请输入默认扫描深度 (当前: {config['max_depth']}): ").strip()
                    if depth:
                        depth = int(depth)
                        if depth > 0 and depth <= 5:
                            config["max_depth"] = depth
                        else:
                            print("扫描深度必须在1-5之间")
                except ValueError:
                    print("扫描深度输入无效，保持默认值")
                
                save_config(config)
            
            elif choice == 5:
                # 加载自定义规则文件
                print("\n===== 加载自定义规则 =====")
                file_path = input("请输入规则文件路径 (直接回车查看当前规则): ").strip()
                
                if file_path and os.path.exists(file_path):
                    if os.path.basename(file_path) not in config["rules_files"]:
                        config["rules_files"].append(os.path.basename(file_path))
                        # 复制文件到规则目录
                        try:
                            dest_path = os.path.join(RULES_DIR, os.path.basename(file_path))
                            shutil.copy2(file_path, dest_path)
                            save_config(config)
                            print(f"已添加并加载规则文件: {os.path.basename(file_path)}")
                        except Exception as e:
                            print(f"复制规则文件失败: {str(e)}")
                    else:
                        print("该规则文件已加载")
                else:
                    # 显示当前加载的规则
                    print("当前加载的规则文件:")
                    for i, fname in enumerate(config["rules_files"], 1):
                        print(f"{i}. {fname}")
                    
                    # 允许删除规则文件
                    try:
                        del_choice = input("输入编号删除规则文件 (0跳过): ").strip()
                        if del_choice and del_choice != '0':
                            idx = int(del_choice) - 1
                            if 0 <= idx < len(config["rules_files"]):
                                removed = config["rules_files"].pop(idx)
                                save_config(config)
                                print(f"已删除规则文件: {removed}")
                    except (ValueError, IndexError):
                        print("无效的选择")
            
            elif choice == 6:
                # 定时扫描设置
                setup_scheduled_scan(config)
            
            elif choice == 7:
                # 配置API密钥
                print("\n===== API密钥配置 =====")
                print("提示: 留空表示不修改当前值")
                
                vt_key = input(f"VirusTotal API密钥 (当前: {'***' if config['virustotal_api_key'] else '未设置'}): ").strip()
                if vt_key:
                    config["virustotal_api_key"] = vt_key
                
                wb_key = input(f"微步在线API密钥 (当前: {'***' if config['weibu_api_key'] else '未设置'}): ").strip()
                if wb_key:
                    config["weibu_api_key"] = wb_key
                
                qk_key = input(f"奇安信API密钥 (当前: {'***' if config['qiankong_api_key'] else '未设置'}): ").strip()
                if qk_key:
                    config["qiankong_api_key"] = qk_key
                4
                save_config(config)
            
            elif choice == 8:
                # 查看扫描历史
                view_scan_history()
        except Exception as e:
            print(f"菜单操作出错: {str(e)}")
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断，程序退出")
    except Exception as e:
        print(f"\n程序出错: {str(e)}")
        # 出错时尝试保存当前结果
        try:
            if global_state["results"]:
                save_path = save_scan_results(global_state["results"], "error_recovery")
                print(f"错误恢复: 已保存当前结果至 {save_path}")
        except:
            print("错误恢复: 保存当前结果失败")
    # 确保程序彻底退出
    os._exit(0)
    