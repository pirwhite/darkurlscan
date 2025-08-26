import os
import sys
import csv
import json
import re
import threading
import signal
import shutil
import subprocess
import time
from difflib import Differ, SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urljoin

# 确保中文显示正常
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 终端颜色代码，用于美化输出
class Color:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
        print(f"{Color.YELLOW}检测到缺失的依赖包: {', '.join(missing)}{Color.RESET}")
        print(f"{Color.CYAN}正在自动安装，请稍候...{Color.RESET}")
        
        # 使用pip安装缺失的包
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                "--upgrade pip",
                *missing
            ])
            print(f"{Color.GREEN}依赖包安装完成{Color.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Color.RED}依赖包安装失败: {e}{Color.RESET}")
            print(f"请手动安装以下包后重试:")
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
TAMPER_RESULTS_DIR = os.path.join(SCRIPT_DIR, "tamper_results")

# 全局状态跟踪与锁
global_state = {
    "is_terminated": False,
    "current_url": None,
    "processed_urls": 0,
    "total_urls": 0,
    "results": [],
    "tamper_results": [],
    "start_time": None,
    "active_threads": 0,
    "save_lock": threading.Lock()  # 用于文件保存的锁
}
state_lock = threading.Lock()  # 状态锁定义

# 线程安全的日志锁
log_lock = threading.Lock()

def print_darkscan_banner():
    """打印DarkScan图案和作者信息"""
    banner = f"""{Color.CYAN}
                           .---.        .-----------
                          /     \\  __  /    ------
                         / /     \\(  )/    -----
                        //////   ' \\/ `   ---
                       //// / // :    : ---
                      // /   /  /`    '--
                     //          //..\\\\
                        _____//..//
                       /     '     `'.
                      /  /         \\  \\
                     /  /           \\  \\
                    /  /             \\  \\
                   /  /               \\  \\
                  /  /                 \\  \\
                 /  /                   \\  \\
                /  /                     \\  \\
+-----------------------------------------------------------+
|                      DarkScan Tool                        |
|                     Author: p1r07                        |
|     支持自动补全协议+同时探活+篡改检测(父链接和子链接)      |
+-----------------------------------------------------------+
    {Color.RESET}"""
    print(banner)

def print_main_menu():
    """打印主菜单"""
    print(f"\n{Color.BOLD}{'='*60}{Color.RESET}")
    print(f"{Color.CYAN}{' ' * 20}功能菜单{' ' * 20}{Color.RESET}")
    print(f"{Color.BOLD}{'='*60}{Color.RESET}")
    print(f"{Color.GREEN}1. {Color.RESET}快速扫描 (分析一级子链接 + 同时进行篡改检测)")
    print(f"{Color.GREEN}2. {Color.RESET}深度扫描 (可自定义分析深度)")
    print(f"{Color.GREEN}3. {Color.RESET}初始化基准内容 (用于篡改检测)")
    print(f"{Color.GREEN}4. {Color.RESET}单独运行HTML篡改检测 (父链接和子链接)")
    print(f"{Color.GREEN}5. {Color.RESET}配置扫描参数 (线程数、超时等)")
    print(f"{Color.GREEN}6. {Color.RESET}加载自定义规则文件")
    print(f"{Color.GREEN}7. {Color.RESET}定时扫描设置")
    print(f"{Color.GREEN}8. {Color.RESET}配置威胁情报API密钥")
    print(f"{Color.GREEN}9. {Color.RESET}查看扫描历史")
    print(f"{Color.RED}0. {Color.RESET}退出程序")
    print(f"{Color.BOLD}{'='*60}{Color.RESET}")
    
    try:
        choice = int(input(f"{Color.YELLOW}请选择功能 (0-9): {Color.RESET}").strip())
        if 0 <= choice <= 9:
            return choice
        else:
            print(f"{Color.RED}请输入0-9之间的数字{Color.RESET}")
            return None
    except ValueError:
        print(f"{Color.RED}请输入有效的数字{Color.RESET}")
        return None

def handle_termination(signum, frame):
    """处理强制终止信号（兼容Windows和Unix系统）"""
    # 双重检查终止状态，避免重复处理
    with state_lock:
        if global_state["is_terminated"]:
            print(f"\n{Color.RED}再次收到终止信号，强制退出...{Color.RESET}")
            os._exit(1)
            
        # 根据系统显示不同的终止提示
        if sys.platform.startswith('win32'):
            print(f"\n{Color.BOLD}{'='*60}{Color.RESET}")
            print(f"{Color.YELLOW}[!] 收到终止信号 (Ctrl+C)，正在保存当前状态...{Color.RESET}")
        else:
            print(f"\n{Color.BOLD}{'='*60}{Color.RESET}")
            print(f"{Color.YELLOW}[!] 收到终止信号 (Ctrl+Z)，正在保存当前状态...{Color.RESET}")
            
        global_state["is_terminated"] = True
    
    # 输出当前分析状态
    with state_lock:
        elapsed_time = datetime.now() - global_state["start_time"] if global_state["start_time"] else 0
        print(f"\n{Color.CYAN}当前分析状态:{Color.RESET}")
        print(f"总URL数: {global_state['total_urls']}")
        print(f"已处理: {global_state['processed_urls']}/{global_state['total_urls']}")
        print(f"当前处理: {global_state['current_url'] or '无'}")
        print(f"活跃线程: {global_state['active_threads']}")
        print(f"已分析链接数: {len(global_state['results'])}")
        print(f"检测到篡改数: {len(global_state['tamper_results'])}")
        print(f"运行时间: {str(elapsed_time)}")
    
    # 保存当前结果 - 无论结果如何都保存
    save_path = None
    try:
        with global_state["save_lock"]:
            save_path = save_scan_results(global_state["results"], "interrupted_scan")
        if save_path:
            print(f"\n{Color.GREEN}[!] 扫描结果已保存至: {save_path}{Color.RESET}")
        else:
            print(f"\n{Color.RED}[!] 尝试保存扫描结果失败{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}[!] 保存扫描结果时发生错误: {str(e)}{Color.RESET}")
    
    # 保存篡改检测结果 - 无论结果如何都保存
    tamper_save_path = None
    try:
        with global_state["save_lock"]:
            tamper_save_path = save_tamper_results(global_state["tamper_results"], "interrupted_tamper")
        if tamper_save_path:
            print(f"\n{Color.GREEN}[!] 篡改检测结果已保存至: {tamper_save_path}{Color.RESET}")
        else:
            print(f"\n{Color.RED}[!] 尝试保存篡改检测结果失败{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}[!] 保存篡改检测结果时发生错误: {str(e)}{Color.RESET}")
    
    if not global_state["results"] and not global_state["tamper_results"]:
        print(f"\n{Color.YELLOW}[!] 暂无结果可保存{Color.RESET}")
    
    print(f"\n{Color.GREEN}程序已安全终止{Color.RESET}")
    os._exit(0)

def ensure_directory_exists(file_path):
    """确保文件所在目录存在，如果不存在则创建"""
    try:
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"{Color.CYAN}已创建目录: {directory}{Color.RESET}")
        # 检查目录是否可写
        if not os.access(directory, os.W_OK):
            raise PermissionError(f"没有写入权限: {directory}")
        return True
    except Exception as e:
        print(f"{Color.RED}确保目录存在失败: {str(e)}{Color.RESET}")
        return False

def get_unique_filename(base_dir, base_name, extension):
    """生成唯一的文件名，若存在同名文件则添加计数器"""
    try:
        # 确保基础目录存在
        if not ensure_directory_exists(os.path.join(base_dir, "test.tmp")):
            # 如果基础目录无法创建或不可写，尝试使用用户主目录
            base_dir = os.path.join(os.path.expanduser("~"), "darkscan_results")
            print(f"{Color.YELLOW}切换到备用目录: {base_dir}{Color.RESET}")
            ensure_directory_exists(os.path.join(base_dir, "test.tmp"))
            
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
        print(f"{Color.RED}生成唯一文件名失败: {str(e)}{Color.RESET}")
        # 最后的备选方案：使用当前目录和进程ID生成文件名
        emergency_filename = f"darkscan_{os.getpid()}_{int(time.time())}.{extension}"
        return os.path.join(os.getcwd(), emergency_filename)

def save_scan_results(results, base_filename="scan_results"):
    """保存扫描结果为CSV文件，增强错误处理和兼容性，确保无论结果如何都保存"""
    try:
        file_path = get_unique_filename(SCAN_RESULTS_DIR, base_filename, "csv")
        print(f"{Color.CYAN}尝试保存扫描结果至: {file_path}{Color.RESET}")
        
        # 再次确保目录存在
        if not ensure_directory_exists(file_path):
            print(f"{Color.YELLOW}无法确保输出目录存在，尝试使用当前工作目录{Color.RESET}")
            file_path = os.path.join(os.getcwd(), os.path.basename(file_path))
            if not ensure_directory_exists(file_path):
                raise Exception("所有尝试的目录都不可写")
        
        fieldnames = [
            "检测时间", "父级URL", "原始URL", "HTTP状态", "HTTPS状态", 
            "有效URL", "链接类型", "原始链接", "绝对链接", "HTTP状态码", 
            "递归深度", "URL规则匹配项", "内容规则匹配项", "标签文本内容", 
            "是否匹配URL规则", "是否匹配内容规则", "是否恶意", "威胁情报详情"
        ]
        
        # 使用临时文件先写入，完成后再重命名，确保文件完整性
        temp_file = f"{file_path}.tmp"
        try:
            with open(temp_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    row_data = {}
                    for field in fieldnames:
                        if field == "检测时间":
                            row_data[field] = result.get("timestamp", "")
                        elif field == "父级URL":
                            row_data[field] = result.get("parent_url", "")
                        elif field == "原始URL":
                            row_data[field] = result.get("original_url", "")
                        elif field == "HTTP状态":
                            row_data[field] = result.get("http_status", "")
                        elif field == "HTTPS状态":
                            row_data[field] = result.get("https_status", "")
                        elif field == "有效URL":
                            row_data[field] = result.get("effective_url", "")
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
                    
                    # 处理可能的特殊字符
                    for key, value in row_data.items():
                        if isinstance(value, str):
                            # 替换可能导致问题的字符
                            row_data[key] = value.replace('\0', '').replace('\r', '')
                    
                    writer.writerow(row_data)
            
            # 验证临时文件是否创建成功
            if not os.path.exists(temp_file) or os.path.getsize(temp_file) == 0:
                # 即使没有数据，也要创建包含表头的文件
                with open(temp_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
            
            # 确保目标文件不存在
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"{Color.YELLOW}删除已有文件失败: {str(e)}，尝试重命名替代{Color.RESET}")
                    file_path = f"{file_path}.backup"
            
            # 重命名临时文件为目标文件
            os.rename(temp_file, file_path)
            
            # 验证文件是否保存成功
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                print(f"{Color.GREEN}扫描结果保存成功，文件大小: {os.path.getsize(file_path)} bytes{Color.RESET}")
                return file_path
            else:
                raise Exception("文件重命名后验证失败")
                
        except Exception as e:
            print(f"{Color.RED}写入临时文件失败: {str(e)}{Color.RESET}")
            # 尝试直接写入目标文件作为备选方案
            try:
                with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(fieldnames)
            except Exception as e2:
                print(f"{Color.RED}应急写入也失败: {str(e2)}{Color.RESET}")
                return None
        finally:
            # 清理临时文件
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
        
    except Exception as e:
        print(f"{Color.RED}保存扫描结果失败: {str(e)}{Color.RESET}")
        # 尝试最基础的保存方式 - 至少保存表头
        try:
            simple_path = os.path.join(os.getcwd(), f"scan_results_{int(time.time())}.csv")
            with open(simple_path, 'w', encoding='utf-8') as f:
                f.write("检测时间,父级URL,原始URL,HTTP状态,HTTPS状态,有效URL,是否恶意\n")
            print(f"{Color.YELLOW}紧急保存: 结果文件已创建至 {simple_path}{Color.RESET}")
            return simple_path
        except:
            print(f"{Color.RED}所有保存尝试都失败了{Color.RESET}")
            return None

def save_tamper_results(results, base_filename="tamper_results"):
    """保存篡改检测结果为CSV文件，增强错误处理和兼容性，确保无论结果如何都保存"""
    try:
        file_path = get_unique_filename(TAMPER_RESULTS_DIR, base_filename, "csv")
        print(f"{Color.CYAN}尝试保存篡改检测结果至: {file_path}{Color.RESET}")
        
        # 再次确保目录存在
        if not ensure_directory_exists(file_path):
            print(f"{Color.YELLOW}无法确保输出目录存在，尝试使用当前工作目录{Color.RESET}")
            file_path = os.path.join(os.getcwd(), os.path.basename(file_path))
            if not ensure_directory_exists(file_path):
                raise Exception("所有尝试的目录都不可写")
        
        fieldnames = [
            "检测时间", "原始URL", "HTTP状态", "HTTPS状态", "有效URL",
            "URL", "链接类型", "基准内容时间", "内容相似度", "差异大小",
            "差异比例(%)", "是否判定为篡改", "篡改类型", "主要差异描述"
        ]
        
        # 使用临时文件先写入，完成后再重命名
        temp_file = f"{file_path}.tmp"
        try:
            with open(temp_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    row_data = {
                        "检测时间": result.get("timestamp", ""),
                        "原始URL": result.get("original_url", ""),
                        "HTTP状态": result.get("http_status", ""),
                        "HTTPS状态": result.get("https_status", ""),
                        "有效URL": result.get("effective_url", ""),
                        "URL": result.get("url", ""),
                        "链接类型": result.get("link_type", "父链接"),
                        "基准内容时间": result.get("base_content_time", ""),
                        "内容相似度": f"{result.get('similarity', 0):.2f}",
                        "差异大小": result.get("diff_size", 0),
                        "差异比例(%)": f"{result.get('diff_percentage', 0):.2f}",
                        "是否判定为篡改": "是" if result.get("is_tampered", False) else "否",
                        "篡改类型": result.get("tamper_type", ""),
                        "主要差异描述": result.get("diff_description", "")
                    }
                    
                    # 处理可能的特殊字符
                    for key, value in row_data.items():
                        if isinstance(value, str):
                            row_data[key] = value.replace('\0', '').replace('\r', '')
                    
                    writer.writerow(row_data)
            
            # 验证临时文件 - 即使没有数据也要创建包含表头的文件
            if not os.path.exists(temp_file) or os.path.getsize(temp_file) == 0:
                with open(temp_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
            
            # 处理目标文件
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    file_path = f"{file_path}.backup"
            
            os.rename(temp_file, file_path)
            
            # 最终验证
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                print(f"{Color.GREEN}篡改检测结果保存成功，文件大小: {os.path.getsize(file_path)} bytes{Color.RESET}")
                return file_path
            else:
                raise Exception("文件重命名后验证失败")
                
        except Exception as e:
            print(f"{Color.RED}写入临时文件失败: {str(e)}{Color.RESET}")
            # 备选方案 - 至少保存表头
            try:
                with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(fieldnames)
                print(f"{Color.YELLOW}应急模式: 结果文件已创建至 {file_path}{Color.RESET}")
                return file_path
            except Exception as e2:
                print(f"{Color.RED}应急写入也失败: {str(e2)}{Color.RESET}")
                return None
        finally:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
        
    except Exception as e:
        print(f"{Color.RED}保存篡改检测结果失败: {str(e)}{Color.RESET}")
        # 最后的紧急保存 - 至少保存表头
        try:
            simple_path = os.path.join(os.getcwd(), f"tamper_results_{int(time.time())}.csv")
            with open(simple_path, 'w', encoding='utf-8') as f:
                f.write("检测时间,原始URL,HTTP状态,HTTPS状态,有效URL,URL,链接类型,是否判定为篡改\n")
            print(f"{Color.YELLOW}紧急保存: 结果文件已创建至 {simple_path}{Color.RESET}")
            return simple_path
        except:
            print(f"{Color.RED}所有保存尝试都失败了{Color.RESET}")
            return None

def log(message, url=None, level="info"):
    """线程安全的日志输出，增加日志级别和颜色"""
    with log_lock:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 根据日志级别选择颜色
        if level == "error":
            level_color = Color.RED
        elif level == "warning":
            level_color = Color.YELLOW
        elif level == "success":
            level_color = Color.GREEN
        elif level == "info":
            level_color = Color.CYAN
        else:
            level_color = Color.RESET
            
        if url:
            # 截断过长的URL
            display_url = url[:50] + "..." if len(url) > 53 else url
            print(f"{level_color}[{timestamp}] [{display_url}] {message}{Color.RESET}")
        else:
            print(f"{level_color}[{timestamp}] {message}{Color.RESET}")

def load_config():
    """加载配置文件"""
    config = {
        "virustotal_api_key": "",
        "weibu_api_key": "",
        "qiankong_api_key": "",
        "max_depth": 1,
        "timeout": 15,
        "default_threads": 5,
        "schedule_interval": 60,
        "regex_flags": re.IGNORECASE,
        "rules_files": ["rules.txt"],
        # 篡改检测配置
        "tamper_sensitivity": 0.85,  # 相似度阈值，低于此值判定为篡改
        "ignore_tags": ["script", "style", "meta", "link"],  # 忽略这些标签的变化
        "ignore_classes": [],  # 忽略具有这些class的元素变化
        "ignore_ids": [],  # 忽略具有这些id的元素变化
        "significant_changes": 50,  # 多少字符的变化被视为显著变化
        "tamper_scan_interval": 60  # 定时篡改检测间隔(分钟)
    }
    
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            print(f"{Color.RED}加载配置文件失败: {str(e)}，使用默认配置{Color.RESET}")
    
    return config

def save_config(config):
    """保存配置到文件"""
    try:
        # 先声明global再使用和修改变量
        global CONFIG_PATH
        
        # 检查目录
        if not ensure_directory_exists(CONFIG_PATH):
            print(f"{Color.YELLOW}配置文件目录不可写，尝试保存到用户主目录{Color.RESET}")
            CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".darkscan_config.json")
            
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        print(f"{Color.GREEN}配置已保存到 {CONFIG_PATH}{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}保存配置文件失败: {str(e)}{Color.RESET}")

def load_urls_from_file(file_path=None):
    """从文件加载URL列表，去除URL有效性限制"""
    if not file_path:
        possible_files = ["urls.txt", "websites.txt", "site_list.txt"]
        for fname in possible_files:
            test_path = os.path.join(SCRIPT_DIR, fname)
            if os.path.exists(test_path):
                file_path = test_path
                break
        
        if not file_path:
            file_path = os.path.join(SCRIPT_DIR, "urls.txt")
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# 请在此文件中添加URL，每行一个，支持域名形式（如example.com）\n")
                    f.write("example.com\n")
                    f.write("www.example.org\n")
                    f.write("https://test.example.net\n")
                print(f"{Color.GREEN}已创建默认URL文件: {file_path}，请编辑后重新运行{Color.RESET}")
            except Exception as e:
                print(f"{Color.RED}创建默认URL文件失败: {str(e)}{Color.RESET}")
                print("请手动创建urls.txt并添加URL")
            return []
    
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                url = line.strip()
                if not url or url.startswith('#'):
                    continue
                # 去除URL有效性限制，接受任何非空字符串作为URL
                urls.append(url)
        print(f"{Color.GREEN}从 {os.path.basename(file_path)} 加载了 {len(urls)} 个URL{Color.RESET}")
        return urls
    except Exception as e:
        print(f"{Color.RED}加载URL文件失败: {str(e)}{Color.RESET}")
        # 允许用户手动输入URL作为备选
        try:
            print(f"{Color.CYAN}请手动输入URL，每行一个，空行结束:{Color.RESET}")
            while True:
                url = input().strip()
                if not url:
                    break
                urls.append(url)
            print(f"{Color.GREEN}手动输入了 {len(urls)} 个URL{Color.RESET}")
            return urls
        except:
            return []

def get_page_content(url, timeout=15):
    """获取网页内容，增加重试机制"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    
    # 最多重试2次
    for attempt in range(3):
        try:
            with state_lock:
                if global_state["is_terminated"]:
                    return None
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=True,
                verify=True
            )
            response.raise_for_status()
            return {
                "content": response.text,
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers)
            }
        except requests.exceptions.SSLError:
            log(f"SSL证书错误，尝试跳过验证...", url, "warning")
            try:
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=timeout, 
                    allow_redirects=True,
                    verify=False
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
                    time.sleep(1)
                    continue
                log(f"SSL错误: {str(e)}", url, "error")
                return None
        except Exception as e:
            if attempt < 2:
                time.sleep(1)
                continue
            log(f"获取页面失败: {str(e)}", url, "error")
            return None

def complete_and_check_url(url, timeout=15):
    """补全URL的协议并同时探测http和https的存活情况"""
    results = {
        'original_url': url,
        'http': None,
        'https': None,
        'best_url': None,
        'http_status': '未尝试',
        'https_status': '未尝试'
    }
    
    # 检查URL是否已经包含协议
    if not url.startswith(('http://', 'https://')):
        # 尝试补全http和https并探活
        http_url = f"http://{url}"
        https_url = f"https://{url}"
        
        # 同时探测http和https
        with ThreadPoolExecutor(max_workers=2) as executor:
            http_future = executor.submit(get_page_content, http_url, timeout)
            https_future = executor.submit(get_page_content, https_url, timeout)
            
            try:
                http_result = http_future.result(timeout + 2)
                if http_result:
                    results['http'] = http_result
                    results['http_status'] = f"成功 ({http_result.get('status_code')})"
                else:
                    results['http_status'] = "失败"
            except Exception as e:
                results['http_status'] = f"错误: {str(e)[:30]}"
                
            try:
                https_result = https_future.result(timeout + 2)
                if https_result:
                    results['https'] = https_result
                    results['https_status'] = f"成功 ({https_result.get('status_code')})"
                else:
                    results['https_status'] = "失败"
            except Exception as e:
                results['https_status'] = f"错误: {str(e)[:30]}"
            
            # 选择存活的URL，如果都存活优先选择https
            if results['https']:
                results['best_url'] = https_url
            elif results['http']:
                results['best_url'] = http_url
    else:
        # URL已经包含协议，直接探测
        try:
            result = get_page_content(url, timeout)
            if result:
                if url.startswith('http://'):
                    results['http'] = result
                    results['http_status'] = f"成功 ({result.get('status_code')})"
                else:
                    results['https'] = result
                    results['https_status'] = f"成功 ({result.get('status_code')})"
                results['best_url'] = url
            else:
                if url.startswith('http://'):
                    results['http_status'] = "失败"
                else:
                    results['https_status'] = "失败"
        except Exception as e:
            if url.startswith('http://'):
                results['http_status'] = f"错误: {str(e)[:30]}"
            else:
                results['https_status'] = f"错误: {str(e)[:30]}"
    
    return results

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
    
    seen_links = set()
    
    for tag, attr in tags.items():
        elements = soup.find_all(tag)
        for elem in elements:
            if attr in elem.attrs:
                original_link = elem[attr].strip()
                if not original_link or original_link in seen_links:
                    continue
                    
                seen_links.add(original_link)
                absolute_link = urljoin(base_url, original_link)
                
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
    if not os.path.exists(RULES_DIR):
        try:
            os.makedirs(RULES_DIR, exist_ok=True)
        except Exception as e:
            print(f"{Color.RED}创建规则目录失败: {str(e)}{Color.RESET}")
    
    if not os.path.exists(DEFAULT_RULES_PATH):
        try:
            with open(DEFAULT_RULES_PATH, 'w', encoding='utf-8') as f:
                f.write("# 暗链检测规则文件\n")
                f.write("# 每行一条规则，格式：类型:内容\n")
                f.write("keyword:赌博\n")
                f.write("keyword:色情\n")
                f.write("domain:bad.example.com\n")
                f.write("regex:.*?malicious.*?\n")
            print(f"{Color.GREEN}已创建默认规则文件: {DEFAULT_RULES_PATH}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}创建默认规则文件失败: {str(e)}{Color.RESET}")
    
    rules = {
        "keywords": [],
        "domains": [],
        "regex_patterns": [],
        "content_keywords": []
    }
    
    for filename in config["rules_files"]:
        if os.path.isabs(filename):
            file_path = filename
        else:
            file_path = os.path.join(RULES_DIR, filename)
            if not os.path.exists(file_path):
                file_path = os.path.join(SCRIPT_DIR, filename)
        
        if not os.path.exists(file_path):
            print(f"{Color.YELLOW}规则文件 {filename} 不存在，已跳过{Color.RESET}")
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
            print(f"{Color.GREEN}已加载规则文件: {os.path.basename(file_path)}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}加载规则文件 {filename} 失败: {str(e)}{Color.RESET}")
    
    for key in rules:
        rules[key] = list(set(rules[key]))
        
    return rules

def match_rules(link_info, rules, config):
    """规则匹配逻辑"""
    url_matches = []
    content_matches = []
    
    link = link_info["absolute_link"]
    parsed = urlparse(link)
    
    for keyword in rules["keywords"]:
        if keyword.lower() in link.lower():
            url_matches.append(f"关键词: {keyword}")
    
    for domain in rules["domains"]:
        if domain.lower() in parsed.netloc.lower():
            url_matches.append(f"域名: {domain}")
    
    for pattern in rules["regex_patterns"]:
        try:
            if re.search(pattern, link, config["regex_flags"]):
                url_matches.append(f"正则: {pattern}")
        except re.error as e:
            log(f"无效正则表达式: {pattern} ({str(e)})", link, "error")
    
    for keyword in rules["content_keywords"]:
        if keyword.lower() in link_info["text_content"].lower():
            content_matches.append(f"内容关键词: {keyword}")
    
    return url_matches, content_matches

def analyze_child_link(link_info, parent_url, depth, max_depth, rules, config, perform_tamper_check=False):
    """分析子链接，增加线程状态跟踪，支持对一级子链接进行篡改检测"""
    with state_lock:
        if global_state["is_terminated"]:
            return []
        global_state["active_threads"] += 1
    
    try:
        if depth > max_depth:
            return []
        
        log(f"分析子链接 (深度: {depth}): {link_info['absolute_link']}", parent_url)
        
        # 对子链接进行协议补全和探活
        url_check = complete_and_check_url(link_info["absolute_link"], config["timeout"])
        if not url_check['best_url']:
            log(f"子链接无法访问: {link_info['absolute_link']}", parent_url, "warning")
            return []
        
        # 获取有效URL的页面内容
        page_data = url_check['https'] if url_check['https'] else url_check['http']
        
        # 对一级子链接进行篡改检测
        if perform_tamper_check and depth == 1:
            tamper_result = detect_tampering(
                url_check['best_url'], 
                page_data["content"], 
                config,
                link_type=f"子链接(深度:{depth})",
                original_url=link_info["absolute_link"],
                http_status=url_check['http_status'],
                https_status=url_check['https_status']
            )
            if tamper_result:
                with state_lock:
                    global_state["tamper_results"].append(tamper_result)
        
        url_matches, content_matches = match_rules(link_info, rules, config)
        is_rule_match = len(url_matches) > 0
        is_content_match = len(content_matches) > 0
        
        is_malicious = is_rule_match and is_content_match
        threat_info = []
        if is_malicious:
            threat_info.append("匹配规则判定为恶意链接")
        
        result = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "parent_url": parent_url,
            "original_url": link_info["absolute_link"],
            "http_status": url_check['http_status'],
            "https_status": url_check['https_status'],
            "effective_url": url_check['best_url'],
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
        
        results = [result]
        if depth < max_depth:
            try:
                soup = BeautifulSoup(page_data["content"], "html.parser")
                child_links = extract_links_from_tags(soup, page_data["final_url"])
                
                max_child_analyze = 20
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
                        config,
                        perform_tamper_check  # 只对一级子链接有效
                    )
                    results.extend(child_results)
            except Exception as e:
                log(f"解析子链接内容失败: {str(e)}", link_info["absolute_link"], "error")
        
        return results
    finally:
        with state_lock:
            global_state["active_threads"] -= 1

def preprocess_html(html_content, config):
    """预处理HTML内容，移除不需要比较的部分"""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        # 移除配置中指定忽略的标签
        for tag in config["ignore_tags"]:
            for element in soup.find_all(tag):
                element.decompose()
        
        # 移除配置中指定忽略的class
        for class_name in config["ignore_classes"]:
            for element in soup.find_all(class_=class_name):
                element.decompose()
        
        # 移除配置中指定忽略的id
        for id_name in config["ignore_ids"]:
            element = soup.find(id=id_name)
            if element:
                element.decompose()
        
        # 移除空白字符和空行，统一格式
        cleaned_html = re.sub(r'\s+', ' ', soup.prettify()).strip()
        return cleaned_html
    except Exception as e:
        print(f"{Color.RED}HTML预处理失败: {str(e)}{Color.RESET}")
        return html_content

def compare_html(base_content, current_content, config):
    """比较两个HTML内容的差异，返回相似度和差异信息"""
    # 预处理内容
    base_clean = preprocess_html(base_content, config)
    current_clean = preprocess_html(current_content, config)
    
    # 计算相似度
    matcher = SequenceMatcher(None, base_clean, current_clean)
    similarity = matcher.ratio()
    
    # 计算差异大小
    base_length = len(base_clean)
    current_length = len(current_clean)
    max_length = max(base_length, current_length)
    
    if max_length == 0:
        diff_percentage = 0
        diff_size = 0
    else:
        # 计算差异大小（编辑距离的近似值）
        diff_size = abs(base_length - current_length)
        # 计算差异百分比
        diff_percentage = (1 - similarity) * 100
    
    # 生成差异描述
    differ = Differ()
    diff = list(differ.compare(
        base_clean.splitlines(), 
        current_clean.splitlines()
    ))
    
    # 提取主要差异
    added = []
    removed = []
    for line in diff:
        if line.startswith('+ '):
            added.append(line[2:])
        elif line.startswith('- '):
            removed.append(line[2:])
    
    # 确定篡改类型
    tamper_type = ""
    if len(added) > 0 and len(removed) == 0:
        tamper_type = "新增内容"
    elif len(removed) > 0 and len(added) == 0:
        tamper_type = "删除内容"
    elif len(added) > 0 and len(removed) > 0:
        tamper_type = "内容修改"
    
    # 生成差异描述（限制长度）
    diff_description = ""
    if added:
        diff_description += f"新增 {len(added)} 行: {added[0][:100]}..."
    if removed:
        if diff_description:
            diff_description += " | "
        diff_description += f"删除 {len(removed)} 行: {removed[0][:100]}..."
    
    # 判定是否为篡改
    is_tampered = similarity < config["tamper_sensitivity"] or \
                  diff_size > config["significant_changes"]
    
    return {
        "similarity": similarity,
        "diff_size": diff_size,
        "diff_percentage": diff_percentage,
        "is_tampered": is_tampered,
        "tamper_type": tamper_type,
        "diff_description": diff_description,
        "added_lines": len(added),
        "removed_lines": len(removed)
    }

def detect_tampering(url, current_content, config, link_type="父链接", original_url=None, http_status=None, https_status=None):
    """检测单个URL是否被篡改，支持标记链接类型和协议状态"""
    # 获取基准内容
    parsed_url = urlparse(url)
    filename = f"{parsed_url.netloc.replace(':', '_')}_{hash(url)}.html"  # 使用哈希确保唯一性
    base_path = os.path.join(BASE_CONTENTS_DIR, filename)
    
    if not os.path.exists(base_path):
        log(f"未找到基准内容，跳过此URL的篡改检测", url, "warning")
        return None
    
    # 读取基准内容
    try:
        with open(base_path, 'r', encoding='utf-8') as f:
            base_content = f.read()
        base_time = datetime.fromtimestamp(os.path.getctime(base_path)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        log(f"读取基准内容失败: {str(e)}", url, "error")
        return None
    
    # 如果没有提供当前内容，则获取它
    if not current_content:
        # 进行协议补全和探活
        url_check = complete_and_check_url(url, config["timeout"])
        if not url_check['best_url']:
            log(f"无法访问URL: {url}", url, "error")
            return None
            
        page_data = url_check['https'] if url_check['https'] else url_check['http']
        current_content = page_data["content"]
        status_code = page_data.get("status_code", "未知")
        
        # 如果未提供，使用检测到的状态
        if http_status is None:
            http_status = url_check['http_status']
        if https_status is None:
            https_status = url_check['https_status']
        if original_url is None:
            original_url = url
    else:
        status_code = "已获取"
    
    # 比较内容
    comparison = compare_html(base_content, current_content, config)
    
    # 构建结果
    result = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "original_url": original_url or url,
        "http_status": http_status or "未检测",
        "https_status": https_status or "未检测",
        "effective_url": url,
        "url": url,
        "link_type": link_type,  # 标记是父链接还是子链接
        "base_content_time": base_time,
        "similarity": comparison["similarity"],
        "diff_size": comparison["diff_size"],
        "diff_percentage": comparison["diff_percentage"],
        "is_tampered": comparison["is_tampered"],
        "tamper_type": comparison["tamper_type"],
        "diff_description": comparison["diff_description"],
        "status_code": status_code
    }
    
    # 根据结果类型使用不同颜色的日志
    if comparison["is_tampered"]:
        log(f"内容相似度: {comparison['similarity']:.2f}, {Color.RED}检测到篡改{Color.RESET}", url, "warning")
    else:
        log(f"内容相似度: {comparison['similarity']:.2f}, {Color.GREEN}未检测到篡改{Color.RESET}", url, "success")
    
    return result

def run_tamper_detection(urls, config, include_children=True):
    """批量运行HTML篡改检测（父链接和子链接）"""
    # 确保结果目录存在
    os.makedirs(TAMPER_RESULTS_DIR, exist_ok=True)
    
    # 初始化全局状态
    with state_lock:
        global_state["start_time"] = datetime.now()
        global_state["total_urls"] = len(urls)
        global_state["processed_urls"] = 0
        global_state["tamper_results"] = []
        global_state["is_terminated"] = False
        global_state["active_threads"] = 0
    
    # 显示终止提示
    if sys.platform.startswith('win32'):
        termination_hint = "Ctrl+C"
    else:
        termination_hint = "Ctrl+Z"
    
    scan_scope = "父链接和一级子链接" if include_children else "仅父链接"
    print(f"\n{Color.BOLD}开始HTML篡改检测（{scan_scope}），共 {len(urls)} 个URL，使用 {config['default_threads']} 个线程{Color.RESET}")
    print(f"{Color.CYAN}相似度阈值: {config['tamper_sensitivity']}, 显著变化阈值: {config['significant_changes']}字符{Color.RESET}")
    print(f"{Color.YELLOW}提示: 按 {termination_hint} 可强制终止并保存当前结果{Color.RESET}\n")
    
    # 启动进度显示线程
    def progress_monitor():
        while True:
            with state_lock:
                processed = global_state["processed_urls"]
                total = global_state["total_urls"]
                current_url = global_state["current_url"]
                is_terminated = global_state["is_terminated"]
                tamper_count = sum(1 for r in global_state["tamper_results"] if r["is_tampered"])
                
            if total == 0:
                progress = 0
            else:
                progress = (processed / total) * 100
                
            # 使用进度条美化显示
            bar_length = 30
            filled_length = int(bar_length * progress / 100)
            progress_bar = f"{'#' * filled_length}{'-' * (bar_length - filled_length)}"
                
            print(f"\r{Color.BOLD}检测进度: {processed}/{total} ({progress:.1f}%) [{progress_bar}] 已发现篡改: {tamper_count} {Color.RESET} 当前: {current_url[:50] if current_url else '准备中'}", end="")
            
            if is_terminated or processed >= total:
                break
                
            time.sleep(1)
    
    progress_thread = threading.Thread(target=progress_monitor, daemon=True)
    progress_thread.start()
    
    try:
        with ThreadPoolExecutor(max_workers=config["default_threads"]) as executor:
            futures = []
            
            for url in urls:
                # 提交父链接检测任务，先进行协议补全和探活
                futures.append(executor.submit(process_tamper_parent_url, url, config))
                
                # 如果需要，同时检测一级子链接
                if include_children:
                    futures.append(executor.submit(detect_child_tampering, url, config))
            
            for future in as_completed(futures):
                with state_lock:
                    if global_state["is_terminated"]:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                try:
                    result = future.result()
                    if result and isinstance(result, list):
                        # 处理子链接的多个结果
                        with state_lock:
                            global_state["tamper_results"].extend(result)
                    elif result:
                        # 处理父链接的单个结果
                        with state_lock:
                            global_state["tamper_results"].append(result)
                except Exception as e:
                    log(f"URL篡改检测失败: {str(e)}", level="error")
                finally:
                    with state_lock:
                        global_state["processed_urls"] += 1
    except Exception as e:
        print(f"{Color.RED}篡改检测过程出错: {str(e)}{Color.RESET}")
        with state_lock:
            if not global_state["is_terminated"]:
                global_state["is_terminated"] = True
    
    # 等待进度线程结束
    progress_thread.join()
    print()
    
    # 保存结果 - 无论结果如何都保存
    with state_lock:
        save_path = save_tamper_results(global_state["tamper_results"])
        if save_path:
            tamper_count = sum(1 for r in global_state["tamper_results"] if r["is_tampered"])
            print(f"\n{Color.GREEN}篡改检测完成，结果已保存至: {save_path}{Color.RESET}")
            print(f"{Color.YELLOW}共检测到 {tamper_count} 个可能被篡改的页面{Color.RESET}")
        else:
            print(f"\n{Color.RED}篡改检测完成，但保存结果失败{Color.RESET}")
    
    return global_state["tamper_results"]

def process_tamper_parent_url(url, config):
    """处理父链接的篡改检测，先进行协议补全和探活"""
    log(f"开始检测父链接: {url}", url)
    
    # 进行协议补全和探活
    url_check = complete_and_check_url(url, config["timeout"])
    if not url_check['best_url']:
        log(f"父链接无法访问: {url}", url, "warning")
        # 即使无法访问，也记录结果
        return {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "original_url": url,
            "http_status": url_check['http_status'],
            "https_status": url_check['https_status'],
            "effective_url": url_check['best_url'],
            "url": url_check['best_url'] or url,
            "link_type": "父链接",
            "base_content_time": "N/A",
            "similarity": 0,
            "diff_size": 0,
            "diff_percentage": 0,
            "is_tampered": False,
            "tamper_type": "无法访问",
            "diff_description": "URL无法访问，无法进行篡改检测",
            "status_code": "无法访问"
        }
    
    # 检测篡改
    tamper_result = detect_tampering(
        url_check['best_url'], 
        None,  # 让函数自动获取内容
        config,
        link_type="父链接",
        original_url=url,
        http_status=url_check['http_status'],
        https_status=url_check['https_status']
    )
    
    return tamper_result

def detect_child_tampering(parent_url, config):
    """检测一级子链接的篡改情况，先进行协议补全和探活"""
    log(f"开始检测子链接的篡改情况", parent_url)
    
    # 进行协议补全和探活
    url_check = complete_and_check_url(parent_url, config["timeout"])
    if not url_check['best_url']:
        log(f"父链接无法访问，无法检测子链接: {parent_url}", parent_url, "warning")
        return []
    
    # 获取父页面内容
    page_data = url_check['https'] if url_check['https'] else url_check['http']
    
    # 提取一级子链接
    try:
        soup = BeautifulSoup(page_data["content"], "html.parser")
        child_links = extract_links_from_tags(soup, page_data["final_url"])
        log(f"提取到 {len(child_links)} 个子链接进行篡改检测", parent_url)
        
        # 限制子链接数量，避免过多检测
        max_children = 10
        child_links = child_links[:max_children]
    except Exception as e:
        log(f"解析HTML失败: {str(e)}", parent_url, "error")
        return []
    
    # 检测每个子链接
    results = []
    for link in child_links:
        with state_lock:
            if global_state["is_terminated"]:
                break
                
        # 对子链接进行协议补全和探活
        child_url_check = complete_and_check_url(link["absolute_link"], config["timeout"])
        if not child_url_check['best_url']:
            log(f"子链接无法访问: {link['absolute_link']}", parent_url, "warning")
            # 即使无法访问，也记录结果
            results.append({
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "original_url": link["absolute_link"],
                "http_status": child_url_check['http_status'],
                "https_status": child_url_check['https_status'],
                "effective_url": child_url_check['best_url'],
                "url": child_url_check['best_url'] or link["absolute_link"],
                "link_type": f"子链接({link['tag']})",
                "base_content_time": "N/A",
                "similarity": 0,
                "diff_size": 0,
                "diff_percentage": 0,
                "is_tampered": False,
                "tamper_type": "无法访问",
                "diff_description": "子链接无法访问，无法进行篡改检测",
                "status_code": "无法访问"
            })
            continue
            
        # 检测篡改
        tamper_result = detect_tampering(
            child_url_check['best_url'], 
            None,  # 让函数自动获取内容
            config,
            link_type=f"子链接({link['tag']})",
            original_url=link["absolute_link"],
            http_status=child_url_check['http_status'],
            https_status=child_url_check['https_status']
        )
        
        if tamper_result:
            results.append(tamper_result)
    
    return results

def run_single_scan(url, max_depth, rules, config, perform_tamper_check=False):
    """扫描单个URL，增加状态跟踪，篡改检测针对父链接和一级子链接"""
    with state_lock:
        if global_state["is_terminated"]:
            return []
    
    log("开始检测...", url)
    
    with state_lock:
        global_state["current_url"] = url
    
    # 进行协议补全和探活
    url_check = complete_and_check_url(url, config["timeout"])
    if not url_check['best_url']:
        log(f"URL无法访问: {url}", url, "error")
        # 即使无法访问，也记录结果
        result = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "parent_url": "N/A",
            "original_url": url,
            "http_status": url_check['http_status'],
            "https_status": url_check['https_status'],
            "effective_url": url_check['best_url'],
            "link_type": "父链接",
            "original_link": url,
            "absolute_link": url,
            "status_code": "无法访问",
            "depth": 0,
            "url_matches": [],
            "content_matches": [],
            "tag_content": "",
            "is_rule_match": False,
            "is_content_match": False,
            "is_malicious": False,
            "threat_info": ["URL无法访问"]
        }
        with state_lock:
            global_state["results"].append(result)
            global_state["processed_urls"] += 1
            global_state["current_url"] = None
        return [result]
    
    # 获取有效URL的页面内容
    page_data = url_check['https'] if url_check['https'] else url_check['http']
    
    # 如果需要，对父链接进行篡改检测
    if perform_tamper_check:
        tamper_result = detect_tampering(
            url_check['best_url'], 
            page_data["content"], 
            config,
            link_type="父链接",
            original_url=url,
            http_status=url_check['http_status'],
            https_status=url_check['https_status']
        )
        if tamper_result:
            with state_lock:
                global_state["tamper_results"].append(tamper_result)
    
    try:
        soup = BeautifulSoup(page_data["content"], "html.parser")
        links = extract_links_from_tags(soup, page_data["final_url"])
        log(f"提取到 {len(links)} 个链接", url)
    except Exception as e:
        log(f"解析HTML失败: {str(e)}", url, "error")
        with state_lock:
            global_state["processed_urls"] += 1
            global_state["current_url"] = None
        return []
    
    results = []
    link_threads = min(5, max(1, len(links) // 3))
    
    with ThreadPoolExecutor(max_workers=link_threads) as executor:
        futures = [executor.submit(
            analyze_child_link, 
            link, 
            url_check['best_url'], 
            1, 
            max_depth,
            rules,
            config,
            perform_tamper_check  # 对一级子链接进行篡改检测
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
                log(f"链接分析失败: {str(e)}", url, "error")
    
    with state_lock:
        global_state["processed_urls"] += 1
        global_state["current_url"] = None
        global_state["results"].extend(results)
    
    log("检测完成", url, "success")
    return results

def run_batch_scan(urls, max_depth, config, perform_tamper_check=False):
    """批量扫描URL，篡改检测针对父链接和一级子链接"""
    rules = load_rules(config)
    
    with state_lock:
        global_state["start_time"] = datetime.now()
        global_state["total_urls"] = len(urls)
        global_state["processed_urls"] = 0
        global_state["results"] = []
        # 如果要进行篡改检测，初始化篡改结果列表
        if perform_tamper_check:
            global_state["tamper_results"] = []
        global_state["is_terminated"] = False
        global_state["active_threads"] = 0
    
    if sys.platform.startswith('win32'):
        termination_hint = "Ctrl+C"
    else:
        termination_hint = "Ctrl+Z"
    
    # 显示扫描类型和参数
    scan_type = "快速扫描 + 篡改检测(父链接和一级子链接)" if perform_tamper_check else "深度扫描"
    print(f"\n{Color.BOLD}开始{scan_type}，共 {len(urls)} 个URL，使用 {config['default_threads']} 个线程，最大深度: {max_depth}{Color.RESET}")
    print(f"{Color.YELLOW}提示: 按 {termination_hint} 可强制终止并保存当前结果{Color.RESET}\n")
    
    def progress_monitor():
        while True:
            with state_lock:
                processed = global_state["processed_urls"]
                total = global_state["total_urls"]
                current_url = global_state["current_url"]
                is_terminated = global_state["is_terminated"]
                # 如果进行篡改检测，显示篡改计数
                tamper_count = sum(1 for r in global_state["tamper_results"] if r["is_tampered"]) if perform_tamper_check else 0
                malicious_count = sum(1 for link in global_state["results"] if link["is_malicious"])
                
            if total == 0:
                progress = 0
            else:
                progress = (processed / total) * 100
                
            # 使用进度条美化显示
            bar_length = 30
            filled_length = int(bar_length * progress / 100)
            progress_bar = f"{'#' * filled_length}{'-' * (bar_length - filled_length)}"
            
            # 进度信息包含篡改检测计数（如果启用）
            if perform_tamper_check:
                progress_text = f"\r{Color.BOLD}扫描进度: {processed}/{total} ({progress:.1f}%) [{progress_bar}] 可疑链接: {malicious_count} 已发现篡改: {tamper_count} {Color.RESET} 当前: {current_url[:50] if current_url else '准备中'}"
            else:
                progress_text = f"\r{Color.BOLD}扫描进度: {processed}/{total} ({progress:.1f}%) [{progress_bar}] 可疑链接: {malicious_count} {Color.RESET} 当前: {current_url[:50] if current_url else '准备中'}"
                
            print(progress_text, end="")
            
            if is_terminated or processed >= total:
                break
                
            time.sleep(1)
    
    progress_thread = threading.Thread(target=progress_monitor, daemon=True)
    progress_thread.start()
    
    try:
        with ThreadPoolExecutor(max_workers=config["default_threads"]) as executor:
            # 提交扫描任务，篡改检测针对父链接和一级子链接
            futures = {
                executor.submit(
                    run_single_scan, 
                    url, 
                    max_depth, 
                    rules, 
                    config,
                    perform_tamper_check  # 传递是否进行篡改检测的参数
                ): url for url in urls
            }
            
            for future in as_completed(futures):
                with state_lock:
                    if global_state["is_terminated"]:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                url = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log(f"URL扫描失败: {str(e)}", url, "error")
    except Exception as e:
        print(f"{Color.RED}扫描过程出错: {str(e)}{Color.RESET}")
        with state_lock:
            if not global_state["is_terminated"]:
                global_state["is_terminated"] = True
    
    progress_thread.join()
    print()
    
    # 保存结果 - 无论结果如何都保存
    with state_lock:
        # 保存扫描结果
        save_path = save_scan_results(global_state["results"])
        if save_path:
            print(f"\n{Color.GREEN}扫描完成，结果已保存至: {save_path}{Color.RESET}")
            
            malicious_count = sum(1 for link in global_state["results"] if link["is_malicious"])
            print(f"{Color.YELLOW}发现 {malicious_count} 个可疑恶意链接{Color.RESET}")
        else:
            print(f"\n{Color.RED}扫描完成，但保存扫描结果失败{Color.RESET}")
        
        # 如果进行了篡改检测，保存篡改检测结果
        if perform_tamper_check:
            tamper_save_path = save_tamper_results(global_state["tamper_results"])
            if tamper_save_path:
                tamper_count = sum(1 for r in global_state["tamper_results"] if r["is_tampered"])
                print(f"{Color.GREEN}篡改检测完成，结果已保存至: {tamper_save_path}{Color.RESET}")
                print(f"{Color.YELLOW}共检测到 {tamper_count} 个可能被篡改的页面{Color.RESET}")
            else:
                print(f"{Color.RED}篡改检测完成，但保存结果失败{Color.RESET}")
    
    return global_state["results"]

def init_base_contents(urls, config, include_children=True):
    """初始化基准内容，包括父链接和一级子链接，用于后续篡改检测"""
    # 先声明global再使用和修改变量
    global BASE_CONTENTS_DIR
    
    if not ensure_directory_exists(os.path.join(BASE_CONTENTS_DIR, "test.tmp")):
        print(f"{Color.YELLOW}基准内容目录不可写，尝试使用用户主目录{Color.RESET}")
        BASE_CONTENTS_DIR = os.path.join(os.path.expanduser("~"), "darkscan_base_contents")
        if not ensure_directory_exists(os.path.join(BASE_CONTENTS_DIR, "test.tmp")):
            print(f"{Color.RED}无法创建基准内容目录，初始化失败{Color.RESET}")
            return 0
    
    success_count = 0
    total_count = len(urls)
    child_count = 0
    
    print(f"{Color.CYAN}开始初始化 {len(urls)} 个URL的基准内容（包括父链接和一级子链接）...{Color.RESET}")
    
    # 进度显示
    def print_progress(current, total, url):
        progress = (current / total) * 100 if total > 0 else 0
        bar_length = 30
        filled_length = int(bar_length * progress / 100)
        progress_bar = f"{'#' * filled_length}{'-' * (bar_length - filled_length)}"
        print(f"\r{Color.BOLD}初始化进度: {current}/{total} ({progress:.1f}%) [{progress_bar}] {Color.RESET} 当前: {url[:50]}", end="")
    
    # 处理父链接
    for i, url in enumerate(urls, 1):
        print_progress(i, total_count, url)
        
        try:
            # 进行协议补全和探活
            url_check = complete_and_check_url(url, config["timeout"])
            if not url_check['best_url']:
                log(f"URL无法访问，无法保存基准内容: {url}", url, "warning")
                continue
                
            page_data = url_check['https'] if url_check['https'] else url_check['http']
            
            parsed_url = urlparse(url_check['best_url'])
            filename = f"{parsed_url.netloc.replace(':', '_')}_{hash(url_check['best_url'])}.html"  # 使用哈希确保唯一性
            file_path = os.path.join(BASE_CONTENTS_DIR, filename)
            
            # 尝试写入文件，带错误处理
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(page_data["content"])
                
                # 验证写入成功
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    success_count += 1
                    log(f"已保存基准内容 (HTTP: {url_check['http_status']}, HTTPS: {url_check['https_status']})", url, "success")
                    
                    # 如果需要，同时保存一级子链接的基准内容
                    if include_children:
                        try:
                            soup = BeautifulSoup(page_data["content"], "html.parser")
                            child_links = extract_links_from_tags(soup, page_data["final_url"])
                            
                            # 限制子链接数量
                            max_children = 10
                            child_links = child_links[:max_children]
                            child_count += len(child_links)
                            
                            # 为每个子链接保存基准内容
                            for child_link in child_links:
                                # 对子链接进行协议补全和探活
                                child_url_check = complete_and_check_url(child_link["absolute_link"], config["timeout"])
                                if not child_url_check['best_url']:
                                    log(f"子链接无法访问，无法保存基准内容: {child_link['absolute_link']}", url, "warning")
                                    continue
                                    
                                child_data = child_url_check['https'] if child_url_check['https'] else child_url_check['http']
                                child_filename = f"child_{hash(child_url_check['best_url'])}.html"
                                child_file_path = os.path.join(BASE_CONTENTS_DIR, child_filename)
                                
                                with open(child_file_path, 'w', encoding='utf-8') as f:
                                    f.write(child_data["content"])
                                
                                if os.path.exists(child_file_path) and os.path.getsize(child_file_path) > 0:
                                    success_count += 1
                                    log(f"已保存子链接基准内容 (HTTP: {child_url_check['http_status']}, HTTPS: {child_url_check['https_status']})", child_link["absolute_link"], "success")
                        except Exception as e:
                            log(f"处理子链接基准内容失败: {str(e)}", url, "warning")
            except Exception as e:
                log(f"写入基准内容失败: {str(e)}", url, "error")
        except Exception as e:
            log(f"初始化基准内容失败: {str(e)}", url, "error")
    
    print()  # 换行
    total_processed = total_count + child_count
    print(f"{Color.GREEN}基准内容初始化完成，成功 {success_count}/{total_processed} (父链接: {len(urls)}, 子链接: {child_count}){Color.RESET}")
    return success_count

def view_scan_history():
    """查看扫描历史，包括篡改检测结果"""
    all_files = []
    
    # 收集扫描结果
    if os.path.exists(SCAN_RESULTS_DIR):
        for fname in os.listdir(SCAN_RESULTS_DIR):
            if fname.endswith(".csv"):
                fpath = os.path.join(SCAN_RESULTS_DIR, fname)
                ftime = os.path.getctime(fpath)
                all_files.append((-ftime, "扫描", fname, fpath))
    
    # 收集篡改检测结果
    if os.path.exists(TAMPER_RESULTS_DIR):
        for fname in os.listdir(TAMPER_RESULTS_DIR):
            if fname.endswith(".csv"):
                fpath = os.path.join(TAMPER_RESULTS_DIR, fname)
                ftime = os.path.getctime(fpath)
                all_files.append((-ftime, "篡改检测", fname, fpath))
    
    if not all_files:
        print(f"{Color.YELLOW}暂无扫描历史记录{Color.RESET}")
        return
    
    print(f"\n{Color.BOLD}===== 历史记录 ====={Color.RESET}")
    all_files.sort()
    
    # 显示最近10条记录
    for i, (_, type_name, fname, fpath) in enumerate(all_files[:10], 1):
        try:
            fsize = os.path.getsize(fpath) / 1024
            fdate = datetime.fromtimestamp(os.path.getctime(fpath)).strftime('%Y-%m-%d %H:%M')
            print(f"{Color.GREEN}{i}. {Color.RESET}[{type_name}] {fname} ({fsize:.1f}KB) - {fdate}")
        except:
            print(f"{Color.GREEN}{i}. {Color.RESET}[{type_name}] {fname} (无法访问)")
    
    try:
        choice = input(f"\n{Color.YELLOW}请输入要查看的记录编号 (0返回): {Color.RESET}").strip()
        if choice == '0':
            return
            
        idx = int(choice) - 1
        if 0 <= idx < len(all_files[:10]):
            _, type_name, fname, fpath = all_files[idx]
            print(f"\n{Color.BOLD}查看{type_name}记录: {fname}{Color.RESET}")
            print(f"{Color.CYAN}{'-'*60}{Color.RESET}")
            
            try:
                with open(fpath, 'r', encoding='utf-8-sig') as f:
                    reader = csv.reader(f)
                    headers = next(reader)
                    print(f"{Color.BOLD}{', '.join(headers[:5]) + '...'}{Color.RESET}")
                    
                    count = 0
                    for row in reader:
                        if count >= 5:
                            print("...")
                            break
                        print(", ".join(row[:5]) + "...")
                        count += 1
            except Exception as e:
                print(f"{Color.RED}读取记录文件失败: {str(e)}{Color.RESET}")
                print(f"文件路径: {fpath}")
            
            print(f"{Color.CYAN}{'-'*60}{Color.RESET}")
            print(f"文件路径: {fpath}")
    except (ValueError, IndexError):
        print(f"{Color.RED}无效的选择{Color.RESET}")

def setup_scheduled_scan(config):
    """设置定时扫描，篡改检测针对父链接和一级子链接"""
    print(f"\n{Color.BOLD}===== 定时扫描设置 ====={Color.RESET}")
    print(f"{Color.GREEN}1. {Color.RESET}定时暗链扫描")
    print(f"{Color.GREEN}2. {Color.RESET}定时暗链扫描 + 篡改检测(父链接和一级子链接)")
    print(f"{Color.GREEN}3. {Color.RESET}定时HTML篡改检测（父链接和一级子链接，单独）")
    print(f"{Color.RED}0. {Color.RESET}返回")
    
    try:
        scan_type = input(f"{Color.YELLOW}请选择定时任务类型: {Color.RESET}").strip()
        if scan_type == '0':
            return
            
        if scan_type == '1':
            # 定时暗链扫描
            print(f"\n{Color.CYAN}当前暗链扫描设置: 每 {config['schedule_interval']} 分钟{Color.RESET}")
            interval = input(f"{Color.YELLOW}请输入新的扫描间隔(分钟，0取消): {Color.RESET}").strip()
            if interval == '0':
                config["schedule_interval"] = 0
                save_config(config)
                print(f"{Color.GREEN}已取消定时暗链扫描{Color.RESET}")
                return
                
            if interval:
                interval = int(interval)
                if interval < 5:
                    print(f"{Color.RED}扫描间隔不能小于5分钟{Color.RESET}")
                    return
                config["schedule_interval"] = interval
                save_config(config)
        
            print(f"{Color.GREEN}定时暗链扫描已设置为每 {config['schedule_interval']} 分钟一次{Color.RESET}")
            
            def scheduled_link_scan():
                print(f"\n{Color.BOLD}===== 定时暗链扫描开始 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ====={Color.RESET}")
                urls = load_urls_from_file()
                if urls:
                    run_batch_scan(urls, config["max_depth"], config, False)
                else:
                    print(f"{Color.YELLOW}未找到有效的URL，定时扫描取消{Color.RESET}")
            
            scheduled_link_scan()
            schedule.every(config["schedule_interval"]).minutes.do(scheduled_link_scan)
            
        elif scan_type == '2':
            # 定时暗链扫描 + 篡改检测(父链接和一级子链接)
            print(f"\n{Color.CYAN}当前组合扫描设置: 每 {config['schedule_interval']} 分钟{Color.RESET}")
            interval = input(f"{Color.YELLOW}请输入新的扫描间隔(分钟，0取消): {Color.RESET}").strip()
            if interval == '0':
                config["schedule_interval"] = 0
                save_config(config)
                print(f"{Color.GREEN}已取消定时组合扫描{Color.RESET}")
                return
                
            if interval:
                interval = int(interval)
                if interval < 5:
                    print(f"{Color.RED}扫描间隔不能小于5分钟{Color.RESET}")
                    return
                config["schedule_interval"] = interval
                save_config(config)
        
            print(f"{Color.GREEN}定时组合扫描已设置为每 {config['schedule_interval']} 分钟一次{Color.RESET}")
            
            def scheduled_combined_scan():
                print(f"\n{Color.BOLD}===== 定时组合扫描开始 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ====={Color.RESET}")
                urls = load_urls_from_file()
                if urls:
                    run_batch_scan(urls, 1, config, True)  # 快速扫描+篡改检测(父链接和一级子链接)
                else:
                    print(f"{Color.YELLOW}未找到有效的URL，定时扫描取消{Color.RESET}")
            
            scheduled_combined_scan()
            schedule.every(config["schedule_interval"]).minutes.do(scheduled_combined_scan)
            
        elif scan_type == '3':
            # 定时篡改检测（父链接和一级子链接，单独）
            print(f"\n{Color.CYAN}当前篡改检测设置: 每 {config['tamper_scan_interval']} 分钟{Color.RESET}")
            interval = input(f"{Color.YELLOW}请输入新的检测间隔(分钟，0取消): {Color.RESET}").strip()
            if interval == '0':
                config["tamper_scan_interval"] = 0
                save_config(config)
                print(f"{Color.GREEN}已取消定时篡改检测{Color.RESET}")
                return
                
            if interval:
                interval = int(interval)
                if interval < 5:
                    print(f"{Color.RED}检测间隔不能小于5分钟{Color.RESET}")
                    return
                config["tamper_scan_interval"] = interval
                save_config(config)
        
            print(f"{Color.GREEN}定时篡改检测已设置为每 {config['tamper_scan_interval']} 分钟一次{Color.RESET}")
            
            def scheduled_tamper_scan():
                print(f"\n{Color.BOLD}===== 定时篡改检测开始 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ====={Color.RESET}")
                urls = load_urls_from_file()
                if urls:
                    run_tamper_detection(urls, config, include_children=True)  # 检测父链接和一级子链接
                else:
                    print(f"{Color.YELLOW}未找到有效的URL，定时检测取消{Color.RESET}")
            
            scheduled_tamper_scan()
            schedule.every(config["tamper_scan_interval"]).minutes.do(scheduled_tamper_scan)
        
        print(f"{Color.YELLOW}提示: 请保持程序运行以启用定时功能{Color.RESET}")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            print(f"\n{Color.GREEN}用户中断，定时任务停止{Color.RESET}")
            
    except ValueError:
        print(f"{Color.RED}请输入有效的数字{Color.RESET}")

def main():
    # 初始化所有必要的目录
    for dir_path in [SCAN_RESULTS_DIR, RULES_DIR, BASE_CONTENTS_DIR, TAMPER_RESULTS_DIR]:
        try:
            ensure_directory_exists(os.path.join(dir_path, "test.tmp"))
        except Exception as e:
            print(f"{Color.RED}创建目录 {dir_path} 失败: {str(e)}{Color.RESET}")
            print(f"{Color.YELLOW}将尝试使用备用目录{Color.RESET}")
    
    try:
        if sys.platform.startswith('win32'):
            signal.signal(signal.SIGINT, handle_termination)
        else:
            signal.signal(signal.SIGTSTP, handle_termination)
    except Exception as e:
        print(f"{Color.YELLOW}信号处理初始化警告: {str(e)}{Color.RESET}")
        print(f"{Color.YELLOW}强制终止功能可能无法正常工作{Color.RESET}")
    
    print_darkscan_banner()
    config = load_config()
    
    while True:
        try:
            choice = print_main_menu()
            if choice is None:
                continue
            
            if choice == 0:
                print(f"{Color.GREEN}感谢使用，再见！{Color.RESET}")
                break
            
            elif choice == 1:
                # 快速扫描 + 篡改检测(父链接和一级子链接)
                urls = load_urls_from_file()
                if urls:
                    # 检查是否有基准内容
                    has_base_content = False
                    # 对每个URL进行协议补全后检查
                    for url in urls:
                        url_check = complete_and_check_url(url, config["timeout"])
                        if url_check['best_url']:
                            parsed_url = urlparse(url_check['best_url'])
                            filename = f"{parsed_url.netloc.replace(':', '_')}_{hash(url_check['best_url'])}.html"
                            base_path = os.path.join(BASE_CONTENTS_DIR, filename)
                            if os.path.exists(base_path):
                                has_base_content = True
                                break
                            
                    if not has_base_content:
                        print(f"{Color.YELLOW}未找到基准内容，将先初始化基准内容再进行扫描{Color.RESET}")
                        init_base_contents(urls, config)
                        
                    run_batch_scan(urls, max_depth=1, config=config, perform_tamper_check=True)
            
            elif choice == 2:
                # 深度扫描
                try:
                    depth = int(input(f"{Color.YELLOW}请输入最大扫描深度 (1-5): {Color.RESET}").strip())
                    if not 1 <= depth <= 5:
                        print(f"{Color.RED}深度必须在1-5之间{Color.RESET}")
                        continue
                except ValueError:
                    print(f"{Color.RED}请输入有效的数字{Color.RESET}")
                    continue
                
                urls = load_urls_from_file()
                if urls:
                    run_batch_scan(urls, max_depth=depth, config=config, perform_tamper_check=False)
            
            elif choice == 3:
                # 初始化基准内容(父链接和一级子链接)
                urls = load_urls_from_file()
                if urls:
                    init_base_contents(urls, config)
            
            elif choice == 4:
                # 单独运行HTML篡改检测(父链接和一级子链接)
                urls = load_urls_from_file()
                if urls:
                    # 检查是否有基准内容
                    has_base_content = False
                    # 对每个URL进行协议补全后检查
                    for url in urls:
                        url_check = complete_and_check_url(url, config["timeout"])
                        if url_check['best_url']:
                            parsed_url = urlparse(url_check['best_url'])
                            filename = f"{parsed_url.netloc.replace(':', '_')}_{hash(url_check['best_url'])}.html"
                            base_path = os.path.join(BASE_CONTENTS_DIR, filename)
                            if os.path.exists(base_path):
                                has_base_content = True
                                break
                            
                    if not has_base_content:
                        print(f"{Color.RED}未找到基准内容，请先执行选项3初始化基准内容{Color.RESET}")
                        continue
                        
                    run_tamper_detection(urls, config, include_children=True)
            
            elif choice == 5:
                # 配置扫描参数
                print(f"\n{Color.BOLD}===== 扫描参数配置 ====={Color.RESET}")
                try:
                    threads = input(f"{Color.YELLOW}请输入默认线程数 (当前: {config['default_threads']}): {Color.RESET}").strip()
                    if threads:
                        threads = int(threads)
                        if threads > 0 and threads <= 20:
                            config["default_threads"] = threads
                        else:
                            print(f"{Color.RED}线程数必须在1-20之间{Color.RESET}")
                except ValueError:
                    print(f"{Color.RED}线程数输入无效，保持默认值{Color.RESET}")
                
                try:
                    timeout = input(f"{Color.YELLOW}请输入超时时间(秒) (当前: {config['timeout']}): {Color.RESET}").strip()
                    if timeout:
                        timeout = int(timeout)
                        if timeout > 0 and timeout <= 60:
                            config["timeout"] = timeout
                        else:
                            print(f"{Color.RED}超时时间必须在1-60之间{Color.RESET}")
                except ValueError:
                    print(f"{Color.RED}超时时间输入无效，保持默认值{Color.RESET}")
                
                try:
                    depth = input(f"{Color.YELLOW}请输入默认扫描深度 (当前: {config['max_depth']}): {Color.RESET}").strip()
                    if depth:
                        depth = int(depth)
                        if depth > 0 and depth <= 5:
                            config["max_depth"] = depth
                        else:
                            print(f"{Color.RED}扫描深度必须在1-5之间{Color.RESET}")
                except ValueError:
                    print(f"{Color.RED}扫描深度输入无效，保持默认值{Color.RESET}")
                
                # 篡改检测参数配置
                print(f"\n{Color.BOLD}===== 篡改检测参数 ====={Color.RESET}")
                try:
                    sensitivity = input(f"{Color.YELLOW}请输入相似度阈值 (0.0-1.0, 当前: {config['tamper_sensitivity']}): {Color.RESET}").strip()
                    if sensitivity:
                        sensitivity = float(sensitivity)
                        if 0.0 <= sensitivity <= 1.0:
                            config["tamper_sensitivity"] = sensitivity
                        else:
                            print(f"{Color.RED}相似度阈值必须在0.0-1.0之间{Color.RESET}")
                except ValueError:
                    print(f"{Color.RED}相似度阈值输入无效，保持默认值{Color.RESET}")
                
                try:
                    sig_changes = input(f"{Color.YELLOW}请输入显著变化阈值(字符) (当前: {config['significant_changes']}): {Color.RESET}").strip()
                    if sig_changes:
                        sig_changes = int(sig_changes)
                        if sig_changes > 0 and sig_changes <= 1000:
                            config["significant_changes"] = sig_changes
                        else:
                            print(f"{Color.RED}显著变化阈值必须在1-1000之间{Color.RESET}")
                except ValueError:
                    print(f"{Color.RED}显著变化阈值输入无效，保持默认值{Color.RESET}")
                
                save_config(config)
            
            elif choice == 6:
                # 加载自定义规则文件
                print(f"\n{Color.BOLD}===== 加载自定义规则 ====={Color.RESET}")
                file_path = input(f"{Color.YELLOW}请输入规则文件路径 (直接回车查看当前规则): {Color.RESET}").strip()
                
                if file_path and os.path.exists(file_path):
                    if os.path.basename(file_path) not in config["rules_files"]:
                        config["rules_files"].append(os.path.basename(file_path))
                        try:
                            dest_path = os.path.join(RULES_DIR, os.path.basename(file_path))
                            shutil.copy2(file_path, dest_path)
                            save_config(config)
                            print(f"{Color.GREEN}已添加并加载规则文件: {os.path.basename(file_path)}{Color.RESET}")
                        except Exception as e:
                            print(f"{Color.RED}复制规则文件失败: {str(e)}{Color.RESET}")
                    else:
                        print(f"{Color.YELLOW}该规则文件已加载{Color.RESET}")
                else:
                    print(f"{Color.CYAN}当前加载的规则文件:{Color.RESET}")
                    for i, fname in enumerate(config["rules_files"], 1):
                        print(f"{Color.GREEN}{i}. {Color.RESET}{fname}")
                    
                    try:
                        del_choice = input(f"{Color.YELLOW}输入编号删除规则文件 (0跳过): {Color.RESET}").strip()
                        if del_choice and del_choice != '0':
                            idx = int(del_choice) - 1
                            if 0 <= idx < len(config["rules_files"]):
                                removed = config["rules_files"].pop(idx)
                                save_config(config)
                                print(f"{Color.GREEN}已删除规则文件: {removed}{Color.RESET}")
                    except (ValueError, IndexError):
                        print(f"{Color.RED}无效的选择{Color.RESET}")
            
            elif choice == 7:
                # 定时扫描设置
                setup_scheduled_scan(config)
            
            elif choice == 8:
                # 配置API密钥
                print(f"\n{Color.BOLD}===== API密钥配置 ====={Color.RESET}")
                print(f"{Color.YELLOW}提示: 留空表示不修改当前值{Color.RESET}")
                
                vt_key = input(f"{Color.YELLOW}VirusTotal API密钥 (当前: {'***' if config['virustotal_api_key'] else '未设置'}): {Color.RESET}").strip()
                if vt_key:
                    config["virustotal_api_key"] = vt_key
                
                wb_key = input(f"{Color.YELLOW}微步在线API密钥 (当前: {'***' if config['weibu_api_key'] else '未设置'}): {Color.RESET}").strip()
                if wb_key:
                    config["weibu_api_key"] = wb_key
                
                qk_key = input(f"{Color.YELLOW}奇安信API密钥 (当前: {'***' if config['qiankong_api_key'] else '未设置'}): {Color.RESET}").strip()
                if qk_key:
                    config["qiankong_api_key"] = qk_key
                
                save_config(config)
            
            elif choice == 9:
                # 查看扫描历史
                view_scan_history()
        except Exception as e:
            print(f"{Color.RED}菜单操作出错: {str(e)}{Color.RESET}")
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.GREEN}用户中断，程序退出{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}程序出错: {str(e)}{Color.RESET}")
        try:
            # 无论结果如何都保存
            if global_state.get("results") is not None:
                save_path = save_scan_results(global_state["results"], "error_recovery")
                print(f"{Color.YELLOW}错误恢复: 已保存扫描结果至 {save_path}{Color.RESET}")
        except:
            print(f"{Color.RED}错误恢复: 保存扫描结果失败{Color.RESET}")
            
        try:
            # 无论结果如何都保存
            if global_state.get("tamper_results") is not None:
                tamper_save_path = save_tamper_results(global_state["tamper_results"], "error_recovery_tamper")
                print(f"{Color.YELLOW}错误恢复: 已保存篡改检测结果至 {tamper_save_path}{Color.RESET}")
        except:
            print(f"{Color.RED}错误恢复: 保存篡改检测结果失败{Color.RESET}")
    os._exit(0)
