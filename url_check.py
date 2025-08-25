#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import requests
import socket
import csv
import time
import shutil
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List, Dict, Optional

# 工具信息
TOOL_NAME = "url_check"
AUTHOR = "p1r07"
VERSION = "2.0.0"

# 炫酷图标 - 使用Unicode字符确保跨平台兼容
ICONS = {
    "success": "✅",
    "error": "❌",
    "info": "ℹ️",
    "warning": "⚠️",
    "check": "🔍",
    "file": "📄",
    "ip": "🌐",
    "settings": "⚙️",
    "version": "📌",
    "exit": "🚪",
    "install": "📦",
    "history": "📜",
    "clear": "🧹"
}

# 配置和默认值
DEFAULT_WORKERS = 5
DEFAULT_TIMEOUT = 10
CONFIG_FILE = os.path.expanduser("~/.url_check_config")

# 所需依赖
REQUIRED_PACKAGES = ['requests']

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(TOOL_NAME)

def print_title():
    """打印工具标题和标识"""
    title = f"""
{ICONS['check']}  {TOOL_NAME} - URL可用性检查工具 v{VERSION}  {ICONS['check']}
{ICONS['info']}  作者: {AUTHOR}  跨平台支持: macOS, Linux, Windows  {ICONS['info']}
    """
    print("=" * 70)
    print(title)
    print("=" * 70)

def print_menu():
    """打印命令菜单"""
    menu = f"""
{ICONS['check']}  请选择操作:
1. {ICONS['file']}  检查URL列表 (从文件读取)
2. {ICONS['history']}  查看历史检查结果
3. {ICONS['settings']} 设置默认并发数 ({DEFAULT_WORKERS})
4. {ICONS['settings']} 设置默认超时时间 ({DEFAULT_TIMEOUT}秒)
5. {ICONS['info']}  查看帮助信息
6. {ICONS['version']} 查看版本信息
7. {ICONS['install']} 检查并更新依赖
8. {ICONS['clear']}  清除历史结果
9. {ICONS['exit']}  退出工具
    """
    print(menu)
    print("-" * 70)

def load_config():
    """加载配置文件"""
    global DEFAULT_WORKERS, DEFAULT_TIMEOUT
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    key, value = line.strip().split('=')
                    if key == 'workers':
                        DEFAULT_WORKERS = int(value)
                    elif key == 'timeout':
                        DEFAULT_TIMEOUT = int(value)
    except Exception as e:
        logger.warning(f"{ICONS['warning']} 加载配置文件失败: {str(e)}")

def save_config():
    """保存配置到文件"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            f.write(f"workers={DEFAULT_WORKERS}\n")
            f.write(f"timeout={DEFAULT_TIMEOUT}\n")
        logger.info(f"{ICONS['success']} 配置已保存")
    except Exception as e:
        logger.error(f"{ICONS['error']} 保存配置失败: {str(e)}")

def install_package(package: str) -> bool:
    """安装指定的Python包"""
    try:
        logger.info(f"{ICONS['install']} 正在安装依赖: {package}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--upgrade", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logger.info(f"{ICONS['success']} 依赖 {package} 安装/更新成功")
        return True
    except subprocess.CalledProcessError:
        logger.error(f"{ICONS['error']} 安装依赖 {package} 失败，请手动安装: pip install {package}")
        return False
    except Exception as e:
        logger.error(f"{ICONS['error']} 安装依赖时出错: {str(e)}")
        return False

def check_and_install_dependencies(force_update: bool = False) -> bool:
    """检查并安装所有必要的依赖"""
    logger.info(f"{ICONS['info']} 检查必要的依赖...")
    
    # 检查是否安装了pip
    try:
        import pip
    except ImportError:
        logger.error(f"{ICONS['error']} 未找到pip，请先安装pip")
        return False
    
    # 检查并安装每个依赖
    for package in REQUIRED_PACKAGES:
        try:
            if force_update:
                raise ImportError("强制更新")
            __import__(package)
            logger.info(f"{ICONS['success']} 依赖 {package} 已安装")
        except ImportError:
            if not install_package(package):
                return False
    
    return True

def get_ip_address(hostname: str) -> Optional[str]:
    """获取主机名对应的IP地址"""
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except (socket.gaierror, Exception):
        return None

def is_valid_url(url: str) -> bool:
    """检查URL是否有效并包含http/https协议"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def add_protocol_if_missing(url: str) -> Optional[str]:
    """如果URL缺少协议，尝试添加http://和https://并检查哪个有效"""
    if not url:
        return None
        
    parsed = urlparse(url)
    if not parsed.scheme:
        # 尝试添加http和https，优先https
        for scheme in ['https', 'http']:
            test_url = f"{scheme}://{url}"
            if is_valid_url(test_url):
                return test_url
        return None
    return url if is_valid_url(url) else None

def check_url(url: str, timeout: int = 10) -> Dict[str, any]:
    """检查URL是否可访问并返回状态码和IP地址"""
    # 解析主机名并获取IP
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    ip_address = get_ip_address(hostname)
    
    result = {
        'original_url': url,
        'hostname': hostname,
        'ip_address': ip_address,
        'status_code': None,
        'is_accessible': False,
        'error': None,
        'check_time': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    try:
        # 设置请求头，模拟浏览器访问
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # 先尝试HEAD请求，效率更高
        response = requests.head(
            url, 
            timeout=timeout, 
            allow_redirects=True,
            headers=headers,
            verify=True
        )
        
        # 如果HEAD请求失败，尝试GET请求
        if response.status_code not in [200, 301, 302]:
            response = requests.get(
                url, 
                timeout=timeout, 
                allow_redirects=True,
                headers=headers,
                verify=True
            )
            
        result['status_code'] = response.status_code
        result['is_accessible'] = response.status_code == 200
        
    except requests.exceptions.SSLError:
        # SSL错误时尝试不验证证书
        try:
            response = requests.get(
                url, 
                timeout=timeout, 
                allow_redirects=True,
                headers=headers,
                verify=False
            )
            result['status_code'] = response.status_code
            result['is_accessible'] = response.status_code == 200
            result['error'] = "SSL证书验证失败"
        except Exception as e:
            result['error'] = f"SSL错误: {str(e)}"
            
    except requests.exceptions.RequestException as e:
        result['error'] = str(e)
        
    except Exception as e:
        result['error'] = f"错误: {str(e)}"
        
    return result

def read_urls_from_file(file_path: str) -> List[str]:
    """从文件中读取URL列表"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            # 读取所有行，去除空行和前后空格
            urls = [line.strip() for line in file if line.strip()]
        logger.info(f"{ICONS['success']} 成功从 {file_path} 读取 {len(urls)} 个URL")
        return urls
    except FileNotFoundError:
        logger.error(f"{ICONS['error']} 文件 {file_path} 不存在")
    except PermissionError:
        logger.error(f"{ICONS['error']} 没有权限读取文件 {file_path}")
    except UnicodeDecodeError:
        logger.error(f"{ICONS['error']} 文件 {file_path} 不是UTF-8编码")
    except Exception as e:
        logger.error(f"{ICONS['error']} 读取文件出错: {str(e)}")
    return []

def save_results_to_csv(results: List[Dict], timestamp: str) -> None:
    """将检查结果保存到CSV文件"""
    if not results:
        logger.warning(f"{ICONS['warning']} 没有结果可保存到CSV文件")
        return
        
    filename = f"urlcheck_{timestamp}.csv"
    try:
        # CSV列名
        fieldnames = [
            'original_url', 'hostname', 'ip_address', 
            'status_code', 'is_accessible', 'error', 'check_time'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
                
        logger.info(f"{ICONS['file']} 检查结果已保存到: {os.path.abspath(filename)}")
        
    except PermissionError:
        logger.error(f"{ICONS['error']} 没有权限写入文件 {filename}")
    except Exception as e:
        logger.error(f"{ICONS['error']} 保存CSV文件时出错: {str(e)}")

def check_url_list():
    """检查URL列表的主功能"""
    print(f"\n{ICONS['check']} URL列表检查功能")
    print("-" * 50)
    
    # 获取文件路径
    file_path = input("请输入包含URL的文件路径: ").strip()
    
    # 验证文件路径
    if not os.path.exists(file_path):
        logger.error(f"{ICONS['error']} 文件 '{file_path}' 不存在")
        return
    
    if not os.path.isfile(file_path):
        logger.error(f"{ICONS['error']} '{file_path}' 不是一个文件")
        return
    
    # 获取并发数和超时时间（使用默认值或用户输入）
    try:
        workers_input = input(f"请输入并发数 (默认: {DEFAULT_WORKERS}): ").strip()
        workers = int(workers_input) if workers_input else DEFAULT_WORKERS
        
        timeout_input = input(f"请输入超时时间(秒) (默认: {DEFAULT_TIMEOUT}): ").strip()
        timeout = int(timeout_input) if timeout_input else DEFAULT_TIMEOUT
    except ValueError:
        logger.error(f"{ICONS['error']} 无效的数值输入，使用默认值")
        workers = DEFAULT_WORKERS
        timeout = DEFAULT_TIMEOUT
    
    # 生成时间戳
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    
    # 读取并处理URL
    urls = read_urls_from_file(file_path)
    
    if not urls:
        logger.warning(f"{ICONS['warning']} 没有有效的URL可检查")
        return
    
    # 处理URL，确保它们有正确的协议
    processed_urls = []
    invalid_urls = []
    
    for url in urls:
        processed_url = add_protocol_if_missing(url)
        if processed_url:
            processed_urls.append(processed_url)
        else:
            invalid_urls.append(url)
    
    if invalid_urls:
        logger.warning(f"{ICONS['warning']} 发现 {len(invalid_urls)} 个无效URL，已跳过")
        show_invalid = input("是否显示无效URL? (y/n): ").strip().lower() == 'y'
        if show_invalid:
            for url in invalid_urls:
                print(f"  - {url}")
    
    if not processed_urls:
        logger.warning(f"{ICONS['warning']} 没有有效的URL可检查")
        return
    
    logger.info(f"{ICONS['info']} 开始检查 {len(processed_urls)} 个有效URL (并发数: {workers}, 超时: {timeout}秒)")
    print("-" * 80)
    
    # 使用线程池并发检查URL
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # 提交所有任务
        futures = {executor.submit(check_url, url, timeout): url for url in processed_urls}
        
        # 处理完成的任务
        for future in as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
                results.append(result)
                
                # 构建包含IP的状态信息
                ip_info = f"[{ICONS['ip']} {result['ip_address']}]" if result['ip_address'] else "[IP: 未知]"
                
                if result['is_accessible']:
                    logger.info(f"{ICONS['success']} {url} {ip_info} - 状态码: {result['status_code']}")
                else:
                    error_msg = f"状态码: {result['status_code']}" if result['status_code'] else result['error']
                    logger.info(f"{ICONS['error']} {url} {ip_info} - {error_msg}")
                    
            except Exception as e:
                logger.error(f"{ICONS['error']} 检查 {url} 时出错: {str(e)}")
    
    # 保存结果到CSV
    save_results_to_csv(results, timestamp)
    
    # 输出总结
    print("\n" + "-" * 80)
    print(f"{ICONS['info']} 检查结果总结:")
    print(f"总URL数: {len(urls)}")
    print(f"无效URL数: {len(invalid_urls)}")
    print(f"有效URL检查数: {len(processed_urls)}")
    
    successful = [r for r in results if r['is_accessible']]
    print(f"{ICONS['success']} 访问成功(200): {len(successful)}")
    
    failed = [r for r in results if not r['is_accessible']]
    print(f"{ICONS['error']} 访问失败: {len(failed)}")
    print("-" * 80)

def view_history():
    """查看历史检查结果"""
    print(f"\n{ICONS['history']} 历史检查结果")
    print("-" * 50)
    
    # 查找所有结果文件
    result_files = [f for f in os.listdir('.') if f.startswith('urlcheck_') and f.endswith('.csv')]
    
    if not result_files:
        print(f"{ICONS['info']} 没有找到历史检查结果")
        return
    
    # 按创建时间排序
    result_files.sort(key=lambda x: os.path.getctime(x), reverse=True)
    
    # 显示最近的10个结果
    print(f"{ICONS['file']} 最近的检查结果:")
    for i, filename in enumerate(result_files[:10], 1):
        ctime = time.ctime(os.path.getctime(filename))
        size = os.path.getsize(filename) / 1024
        print(f"{i}. {filename} - 创建于: {ctime} - 大小: {size:.2f}KB")
    
    # 询问是否要打开某个文件
    try:
        choice = input("\n请输入要查看的文件编号 (0取消): ").strip()
        if choice and choice != '0':
            index = int(choice) - 1
            if 0 <= index < len(result_files[:10]):
                filename = result_files[index]
                print(f"\n{ICONS['file']} 显示 {filename} 的前10行内容:")
                print("-" * 80)
                with open(filename, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f):
                        if i > 10:
                            print("... (显示前10行)")
                            break
                        print(line.strip())
                print("-" * 80)
                
                # 询问是否用默认程序打开
                open_file = input(f"是否用默认程序打开 {filename}? (y/n): ").strip().lower() == 'y'
                if open_file:
                    if sys.platform.startswith('win32'):
                        os.startfile(filename)
                    elif sys.platform.startswith('darwin'):  # macOS
                        subprocess.run(['open', filename])
                    else:  # Linux
                        subprocess.run(['xdg-open', filename])
    except (ValueError, IndexError):
        logger.error(f"{ICONS['error']} 无效的选择")

def set_workers():
    """设置默认并发数"""
    global DEFAULT_WORKERS
    print(f"\n{ICONS['settings']} 设置默认并发数")
    print("-" * 50)
    
    try:
        new_workers = input(f"当前默认并发数: {DEFAULT_WORKERS}, 请输入新的默认值 (1-20): ").strip()
        new_workers = int(new_workers)
        if 1 <= new_workers <= 20:
            DEFAULT_WORKERS = new_workers
            save_config()
            logger.info(f"{ICONS['success']} 默认并发数已设置为: {DEFAULT_WORKERS}")
        else:
            logger.warning(f"{ICONS['warning']} 并发数必须在1-20之间")
    except ValueError:
        logger.error(f"{ICONS['error']} 无效的数值输入")

def set_timeout():
    """设置默认超时时间"""
    global DEFAULT_TIMEOUT
    print(f"\n{ICONS['settings']} 设置默认超时时间")
    print("-" * 50)
    
    try:
        new_timeout = input(f"当前默认超时时间: {DEFAULT_TIMEOUT}秒, 请输入新的默认值 (5-60秒): ").strip()
        new_timeout = int(new_timeout)
        if 5 <= new_timeout <= 60:
            DEFAULT_TIMEOUT = new_timeout
            save_config()
            logger.info(f"{ICONS['success']} 默认超时时间已设置为: {DEFAULT_TIMEOUT}秒")
        else:
            logger.warning(f"{ICONS['warning']} 超时时间必须在5-60秒之间")
    except ValueError:
        logger.error(f"{ICONS['error']} 无效的数值输入")

def show_help():
    """显示帮助信息"""
    print(f"\n{ICONS['info']} 帮助信息")
    print("-" * 50)
    help_text = f"""
{TOOL_NAME} 是一个用于检查URL可用性的命令行工具，主要功能包括:

1. 检查URL列表 (从文件读取)
   - 从指定文件读取URL列表
   - 自动补全缺失的HTTP/HTTPS协议
   - 检查URL是否可访问(返回200状态码)
   - 解析URL对应的IP地址
   - 将结果保存为CSV文件

2. 查看历史检查结果
   - 显示所有保存的CSV结果文件
   - 查看文件内容并可选择用默认程序打开

3. 设置默认并发数
   - 调整同时检查的URL数量
   - 数值越大速度越快，但可能给服务器带来压力

4. 设置默认超时时间
   - 调整每个URL检查的超时时间(秒)

5. 查看帮助信息
   - 显示本帮助内容

6. 查看版本信息
   - 显示工具版本和作者信息

7. 检查并更新依赖
   - 确保所有必要的库都已安装并更新到最新版本

8. 清除历史结果
   - 删除所有保存的CSV结果文件

9. 退出工具
   - 退出程序

使用提示:
- 确保URL文件中每行包含一个URL
- 对于大型URL列表，建议使用适中的并发数(5-10)
- 结果文件命名格式: urlcheck_年月日_时分秒.csv
    """
    print(help_text)
    print("-" * 50)

def show_version():
    """显示版本信息"""
    print(f"\n{ICONS['version']} 版本信息")
    print("-" * 50)
    version_text = f"""
工具名称: {TOOL_NAME}
版本号: v{VERSION}
作者: {AUTHOR}
兼容平台: macOS, Linux, Windows

功能描述:
URL可用性检查工具，支持批量检查URL是否可访问，
解析IP地址，并将结果导出为CSV文件。

更新日志:
- v2.0.0: 增加交互式命令行界面，支持数字1-9操作
- v1.2.1: 修复参数解析错误，增加文件验证
- v1.2.0: 增加自动依赖检查和安装功能
- v1.1.0: 增加CSV结果导出功能
- v1.0.0: 初始版本，基本URL检查功能
    """
    print(version_text)
    print("-" * 50)

def clear_history():
    """清除历史结果文件"""
    print(f"\n{ICONS['clear']} 清除历史结果")
    print("-" * 50)
    
    # 查找所有结果文件
    result_files = [f for f in os.listdir('.') if f.startswith('urlcheck_') and f.endswith('.csv')]
    
    if not result_files:
        print(f"{ICONS['info']} 没有找到历史检查结果")
        return
    
    print(f"{ICONS['warning']} 警告: 将删除以下 {len(result_files)} 个文件:")
    for i, filename in enumerate(result_files[:5], 1):
        print(f"  - {filename}")
    if len(result_files) > 5:
        print(f"  ... 还有 {len(result_files) - 5} 个文件")
    
    confirm = input(f"\n确定要删除这些文件吗? (y/N): ").strip().lower()
    if confirm == 'y':
        deleted = 0
        for filename in result_files:
            try:
                os.remove(filename)
                deleted += 1
            except Exception as e:
                logger.error(f"{ICONS['error']} 删除 {filename} 失败: {str(e)}")
        logger.info(f"{ICONS['success']} 成功删除 {deleted} 个文件")
    else:
        logger.info(f"{ICONS['info']} 已取消删除操作")

def main():
    """主函数：交互式命令行入口"""
    # 加载配置
    load_config()
    
    # 检查依赖
    if not check_and_install_dependencies():
        logger.error(f"{ICONS['error']} 依赖检查失败，程序可能无法正常运行")
    
    # 显示标题
    print_title()
    
    # 主循环
    while True:
        # 显示菜单
        print_menu()
        
        # 获取用户选择
        try:
            choice = input("请输入操作编号 (1-9): ").strip()
            
            # 根据选择执行相应功能
            if choice == '1':
                check_url_list()
            elif choice == '2':
                view_history()
            elif choice == '3':
                set_workers()
            elif choice == '4':
                set_timeout()
            elif choice == '5':
                show_help()
            elif choice == '6':
                show_version()
            elif choice == '7':
                check_and_install_dependencies(force_update=True)
            elif choice == '8':
                clear_history()
            elif choice == '9':
                print(f"\n{ICONS['exit']} 感谢使用 {TOOL_NAME} 工具，再见!")
                break
            else:
                logger.warning(f"{ICONS['warning']} 无效的选择，请输入1-9之间的数字")
        
        except KeyboardInterrupt:
            print(f"\n{ICONS['warning']} 检测到中断，返回主菜单")
        except Exception as e:
            logger.error(f"{ICONS['error']} 操作出错: {str(e)}")
        
        # 等待用户按回车继续
        input("\n按回车键返回主菜单...")
        # 清屏（跨平台）
        if sys.platform.startswith('win32'):
            os.system('cls')
        else:
            os.system('clear')
        print_title()

if __name__ == "__main__":
    main()
    