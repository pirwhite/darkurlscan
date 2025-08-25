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
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import requests
from bs4 import BeautifulSoup
import schedule

# 确保中文显示正常
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 全局样式配置
class CuteStyle:
    """二次元可爱风格样式配置"""
    BACKGROUND = "#FFF5F7"
    ACCENT_COLOR = "#FF9BB3"
    SECONDARY_COLOR = "#FFD1DC"
    TEXT_COLOR = "#5A3D47"
    BUTTON_COLOR = "#FFB6C1"
    BUTTON_HOVER = "#FF69B4"
    HEADER_COLOR = "#FF85A2"
    FRAME_COLOR = "#FFE4E1"
    FONT_FAMILY = ["微软雅黑", "SimHei", "Arial"]
    TITLE_FONT = (FONT_FAMILY[0], 14, "bold")
    NORMAL_FONT = (FONT_FAMILY[0], 10)
    SMALL_FONT = (FONT_FAMILY[0], 9)
    LARGE_FONT = (FONT_FAMILY[0], 12, "bold")

# 获取脚本所在目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 配置文件路径
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
DEFAULT_RULES_PATH = os.path.join(SCRIPT_DIR, "rules.txt")
RULES_DIR = os.path.join(SCRIPT_DIR, "rules")
SCAN_RESULTS_DIR = os.path.join(SCRIPT_DIR, "scan_results")
BASE_CONTENTS_DIR = os.path.join(SCRIPT_DIR, "base_contents")
IMAGES_DIR = os.path.join(SCRIPT_DIR, "images")

# 确保必要目录存在
for dir_path in [SCAN_RESULTS_DIR, RULES_DIR, BASE_CONTENTS_DIR, IMAGES_DIR]:
    try:
        os.makedirs(dir_path, exist_ok=True)
    except Exception as e:
        print(f"创建目录 {dir_path} 失败: {str(e)}")

# 全局状态跟踪与锁
global_state = {
    "is_terminated": False,
    "current_url": None,
    "processed_urls": 0,
    "total_urls": 0,
    "results": [],
    "start_time": None,
    "active_threads": 0,
    "save_lock": threading.Lock(),
    "log_lock": threading.Lock(),  # 日志锁
    "progress_callback": None      # 进度回调函数
}
state_lock = threading.Lock()

class DarkScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🌸 魔法暗链扫描姬 by p1r07🌸")
        self.root.geometry("900x650")
        self.root.configure(bg=CuteStyle.BACKGROUND)
        self.root.resizable(True, True)
        
        # 设置中文字体支持
        self.setup_fonts()
        
        # 加载配置
        self.config = self.load_config()
        
        # 创建主界面
        self.create_widgets()
        
        # 初始化日志区域
        self.log_buffer = []
        
        # 注册信号处理器
        self.setup_signal_handlers()
        
        # 显示欢迎信息
        self.log("欢迎使用魔法暗链扫描姬 ～(^з^)-♡")
        self.log(f"Python 版本: {sys.version.split()[0]}")
        self.log(f"系统平台: {platform.system()} {platform.release()}")

    def setup_fonts(self):
        """设置界面字体"""
        default_style = ttk.Style()
        default_style.configure("TButton", 
                              font=CuteStyle.NORMAL_FONT,
                              background=CuteStyle.BUTTON_COLOR)
        default_style.configure("TLabel",
                              font=CuteStyle.NORMAL_FONT,
                              background=CuteStyle.BACKGROUND,
                              foreground=CuteStyle.TEXT_COLOR)
        default_style.configure("TFrame",
                              background=CuteStyle.FRAME_COLOR)
        default_style.configure("Header.TLabel",
                              font=CuteStyle.TITLE_FONT,
                              background=CuteStyle.HEADER_COLOR,
                              foreground="white")

    def create_widgets(self):
        """创建界面组件"""
        # 顶部标题栏
        header_frame = ttk.Frame(self.root, height=50)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        header_frame.pack_propagate(False)
        
        header_label = ttk.Label(
            header_frame, 
            text="🌸 魔法暗链扫描姬  write by p1r07 🌸", 
            style="Header.TLabel"
        )
        header_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 主布局：左侧菜单，右侧内容
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 左侧菜单
        menu_frame = ttk.Frame(main_frame, width=180)
        menu_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        menu_frame.pack_propagate(False)
        
        # 菜单标题
        ttk.Label(menu_frame, text="✨ 功能菜单 ✨", font=CuteStyle.LARGE_FONT).pack(pady=10)
        
        # 功能按钮
        menu_buttons = [
            ("快速扫描", self.quick_scan, "只分析一级子链接"),
            ("深度扫描", self.deep_scan, "可自定义分析深度"),
            ("初始化基准", self.init_base_contents, "用于篡改检测"),
            ("配置参数", self.configure_settings, "线程数、超时等"),
            ("规则管理", self.manage_rules, "加载自定义规则文件"),
            ("定时扫描", self.setup_scheduled_scan, "设置自动扫描时间"),
            ("API配置", self.configure_api_keys, "威胁情报API密钥"),
            ("扫描历史", self.view_scan_history, "查看过往扫描结果"),
            ("系统信息", self.show_system_info, "查看系统与解释器信息"),
            ("退出程序", self.exit_program, "关闭扫描姬")
        ]
        
        for text, command, tooltip in menu_buttons:
            btn = ttk.Button(menu_frame, text=text, command=command)
            btn.pack(fill=tk.X, padx=5, pady=5)
            # 添加悬停提示
            self.create_tooltip(btn, tooltip)
        
        # 右侧内容区域
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # URL输入区域
        url_frame = ttk.Frame(content_frame)
        url_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(url_frame, text="🔗 目标URL列表:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.url_file_var = tk.StringVar(value="urls.txt")
        url_entry = ttk.Entry(url_frame, textvariable=self.url_file_var, width=40)
        url_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(url_frame, text="浏览...", command=self.browse_url_file).pack(side=tk.LEFT)
        ttk.Button(url_frame, text="加载URL", command=self.load_urls).pack(side=tk.LEFT)
        
        # 进度条区域
        progress_frame = ttk.Frame(content_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(progress_frame, text="📊 扫描进度:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, length=400)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.pack(side=tk.LEFT, padx=10)
        
        # 日志区域
        log_frame = ttk.Frame(content_frame)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(log_frame, text="📝 扫描日志 📝", font=CuteStyle.LARGE_FONT).pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            font=CuteStyle.SMALL_FONT,
            bg=CuteStyle.BACKGROUND,
            fg=CuteStyle.TEXT_COLOR
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # 状态区域
        status_frame = ttk.Frame(content_frame)
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_var = tk.StringVar(value="就绪状态 ✨ 等待指令～")
        ttk.Label(status_frame, textvariable=self.status_var).pack(anchor=tk.W)
        
        # 设置进度回调
        global_state["progress_callback"] = self.update_progress

    def create_tooltip(self, widget, text):
        """创建控件悬停提示"""
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry("+0+0")
        label = ttk.Label(
            tooltip, 
            text=text, 
            background="#FFFFE0", 
            relief=tk.SOLID, 
            borderwidth=1,
            font=CuteStyle.SMALL_FONT
        )
        label.pack(ipadx=1)
        
        def show_tooltip(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            tooltip.wm_geometry(f"+{x}+{y}")
            tooltip.deiconify()
        
        def hide_tooltip(event):
            tooltip.withdraw()
        
        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)
        tooltip.withdraw()

    def log(self, message, url=None):
        """线程安全的日志输出"""
        def update_log():
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if url:
                log_line = f"[{timestamp}] [{url}] {message}\n"
            else:
                log_line = f"[{timestamp}] {message}\n"
            
            self.log_buffer.append(log_line)
            if len(self.log_buffer) > 1000:
                self.log_buffer.pop(0)
                
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, log_line)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
            
            # 同时写入日志文件
            try:
                log_file = os.path.join(SCRIPT_DIR, "weblog.txt")
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(log_line)
            except Exception as e:
                print(f"日志写入失败: {str(e)}")
        
        # 在主线程中更新UI
        self.root.after(0, update_log)

    def update_progress(self, processed, total):
        """更新进度条"""
        def update():
            if total == 0:
                progress = 0
            else:
                progress = (processed / total) * 100
            self.progress_var.set(progress)
            self.progress_label.config(text=f"{progress:.1f}%")
            
            status_text = f"处理中: {processed}/{total} 个URL "
            if global_state["current_url"]:
                status_text += f"当前: {global_state['current_url'][:30]}..."
            self.status_var.set(status_text)
        
        self.root.after(0, update)

    def browse_url_file(self):
        """浏览选择URL文件"""
        filename = filedialog.askopenfilename(
            title="选择URL列表文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialdir=SCRIPT_DIR
        )
        if filename:
            self.url_file_var.set(filename)

    def load_urls(self):
        """加载URL文件"""
        file_path = self.url_file_var.get()
        if not file_path:
            messagebox.showwarning("警告", "请输入URL文件路径")
            return
            
        if not os.path.exists(file_path):
            # 创建默认文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("# 请在此文件中添加URL，每行一个\n")
                f.write("https://example.com\n")
            self.log(f"已创建默认URL文件: {file_path}，请编辑后重新加载")
            return
            
        urls = self.load_urls_from_file(file_path)
        if urls:
            self.log(f"成功加载 {len(urls)} 个URL ～(^▽^)")
            self.log(f"第一个URL: {urls[0]}")
        else:
            self.log("未找到有效的URL，请检查文件内容")

    def quick_scan(self):
        """快速扫描（一级深度）"""
        self.start_scan(max_depth=1)

    def deep_scan(self):
        """深度扫描（可自定义深度）"""
        depth = simpledialog.askinteger(
            "深度设置", 
            "请输入最大扫描深度 (1-5):",
            minvalue=1, 
            maxvalue=5,
            initialvalue=self.config.get("max_depth", 1)
        )
        if depth:
            self.start_scan(max_depth=depth)

    def start_scan(self, max_depth=1):
        """开始扫描过程"""
        file_path = self.url_file_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("警告", "请指定有效的URL文件")
            return
            
        urls = self.load_urls_from_file(file_path)
        if not urls:
            messagebox.showwarning("警告", "未找到有效的URL")
            return
            
        # 检查并安装缺失的依赖
        if not self.install_missing_dependencies():
            return
            
        # 重置进度
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        
        # 启动扫描线程
        threading.Thread(
            target=self.run_batch_scan, 
            args=(urls, max_depth),
            daemon=True
        ).start()

    def run_batch_scan(self, urls, max_depth):
        """批量扫描URL，带实时进度监控"""
        self.log(f"\n✨ 开始魔法扫描 ～ 共 {len(urls)} 个URL ✨")
        self.log(f"扫描深度: {max_depth} | 线程数: {self.config['default_threads']}")
        
        rules = self.load_rules()
        
        with state_lock:
            global_state["start_time"] = datetime.now()
            global_state["total_urls"] = len(urls)
            global_state["processed_urls"] = 0
            global_state["results"] = []
            global_state["is_terminated"] = False
            global_state["active_threads"] = 0
        
        try:
            with ThreadPoolExecutor(max_workers=self.config["default_threads"]) as executor:
                futures = {
                    executor.submit(self.run_single_scan, url, max_depth, rules): url 
                    for url in urls
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
                        self.log(f"URL扫描失败: {str(e)}", url)
        
        except Exception as e:
            self.log(f"扫描过程出错: {str(e)}")
            with state_lock:
                if not global_state["is_terminated"]:
                    global_state["is_terminated"] = True
        
        with state_lock:
            if not global_state["is_terminated"] and global_state["results"]:
                save_path = self.save_scan_results(global_state["results"])
                if save_path:
                    self.log(f"\n🎉 扫描完成！结果已保存至: {save_path}")
                    
                    malicious_count = sum(1 for link in global_state["results"] if link["is_malicious"])
                    self.log(f"发现 {malicious_count} 个可疑恶意链接 ⚠️")
                else:
                    self.log("\n扫描完成，但保存结果失败")
            elif global_state["is_terminated"]:
                self.log("\n扫描已被用户终止")
        
        self.log(f"\n扫描耗时: {datetime.now() - global_state['start_time']}")
        self.status_var.set("就绪状态 ✨ 等待指令～")

    def run_single_scan(self, url, max_depth, rules):
        """扫描单个URL"""
        with state_lock:
            if global_state["is_terminated"]:
                return []
        
        self.log("开始检测...", url)
        
        with state_lock:
            global_state["current_url"] = url
            global_state["progress_callback"](
                global_state["processed_urls"], 
                global_state["total_urls"]
            )
        
        page_data = self.get_page_content(url, self.config["timeout"])
        if not page_data:
            with state_lock:
                global_state["processed_urls"] += 1
                global_state["current_url"] = None
                global_state["progress_callback"](
                    global_state["processed_urls"], 
                    global_state["total_urls"]
                )
            return []
        
        try:
            soup = BeautifulSoup(page_data["content"], "html.parser")
            links = self.extract_links_from_tags(soup, page_data["final_url"])
            self.log(f"提取到 {len(links)} 个链接", url)
        except Exception as e:
            self.log(f"解析HTML失败: {str(e)}", url)
            with state_lock:
                global_state["processed_urls"] += 1
                global_state["current_url"] = None
                global_state["progress_callback"](
                    global_state["processed_urls"], 
                    global_state["total_urls"]
                )
            return []
        
        results = []
        link_threads = min(5, max(1, len(links) // 3))
        
        with ThreadPoolExecutor(max_workers=link_threads) as executor:
            futures = [
                executor.submit(
                    self.analyze_child_link, 
                    link, 
                    url, 
                    1, 
                    max_depth,
                    rules
                ) for link in links
            ]
            
            for future in as_completed(futures):
                with state_lock:
                    if global_state["is_terminated"]:
                        executor.shutdown(wait=False)
                        break
                try:
                    link_results = future.result()
                    results.extend(link_results)
                except Exception as e:
                    self.log(f"链接分析失败: {str(e)}", url)
        
        with state_lock:
            global_state["processed_urls"] += 1
            global_state["current_url"] = None
            global_state["results"].extend(results)
            global_state["progress_callback"](
                global_state["processed_urls"], 
                global_state["total_urls"]
            )
        
        self.log("检测完成", url)
        return results

    # 其他核心功能方法保持与原版逻辑一致，但修改为类方法
    def install_missing_dependencies(self):
        """检查并安装缺失的依赖"""
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
            self.log(f"检测到缺失的依赖包: {', '.join(missing)}")
            self.log("正在自动安装，请稍候...")
            
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", 
                    "--upgrade pip",
                    *missing
                ])
                self.log("依赖包安装完成 ～(^▽^)")
                return True
            except subprocess.CalledProcessError as e:
                self.log(f"依赖包安装失败: {e}")
                self.log("请手动安装以下包后重试:")
                self.log(f"pip install {' '.join(missing)}")
                messagebox.showerror("安装失败", f"依赖包安装失败，请手动安装：\n{' '.join(missing)}")
                return False
        return True

    def load_urls_from_file(self, file_path):
        """从文件加载URL列表"""
        urls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    url = line.strip()
                    if not url or url.startswith('#'):
                        continue
                    if not url.startswith(('http://', 'https://')):
                        self.log(f"警告: 第{line_num}行URL格式不正确，已跳过: {url}")
                        continue
                    urls.append(url)
            self.log(f"从 {os.path.basename(file_path)} 加载了 {len(urls)} 个URL")
            return urls
        except Exception as e:
            self.log(f"加载URL文件失败: {str(e)}")
            return []

    def get_page_content(self, url, timeout=15):
        """获取网页内容，带重试机制"""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        }
        
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
                self.log(f"SSL证书错误，尝试跳过验证...", url)
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
                    self.log(f"SSL错误: {str(e)}", url)
                    return None
            except Exception as e:
                if attempt < 2:
                    time.sleep(1)
                    continue
                self.log(f"获取页面失败: {str(e)}", url)
                return None

    def extract_links_from_tags(self, soup, base_url):
        """从HTML标签提取链接"""
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

    def load_rules(self):
        """加载检测规则"""
        if not os.path.exists(RULES_DIR):
            os.makedirs(RULES_DIR, exist_ok=True)
        
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
        
        for filename in self.config["rules_files"]:
            if os.path.isabs(filename):
                file_path = filename
            else:
                file_path = os.path.join(RULES_DIR, filename)
                if not os.path.exists(file_path):
                    file_path = os.path.join(SCRIPT_DIR, filename)
            
            if not os.path.exists(file_path):
                self.log(f"规则文件 {filename} 不存在，已跳过")
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
                self.log(f"已加载规则文件: {os.path.basename(file_path)}")
            except Exception as e:
                self.log(f"加载规则文件 {filename} 失败: {str(e)}")
        
        for key in rules:
            rules[key] = list(set(rules[key]))
            
        return rules

    def match_rules(self, link_info, rules):
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
                if re.search(pattern, link, self.config["regex_flags"]):
                    url_matches.append(f"正则: {pattern}")
            except re.error as e:
                self.log(f"无效正则表达式: {pattern} ({str(e)})", link)
        
        for keyword in rules["content_keywords"]:
            if keyword.lower() in link_info["text_content"].lower():
                content_matches.append(f"内容关键词: {keyword}")
        
        return url_matches, content_matches

    def analyze_child_link(self, link_info, parent_url, depth, max_depth, rules):
        """分析子链接"""
        with state_lock:
            if global_state["is_terminated"]:
                return []
            global_state["active_threads"] += 1
        
        try:
            if depth > max_depth:
                return []
            
            self.log(f"分析子链接 (深度: {depth}): {link_info['absolute_link'][:50]}...", parent_url)
            
            page_data = self.get_page_content(link_info["absolute_link"], self.config["timeout"])
            if not page_data:
                return []
            
            url_matches, content_matches = self.match_rules(link_info, rules)
            is_rule_match = len(url_matches) > 0
            is_content_match = len(content_matches) > 0
            
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
            
            results = [result]
            if depth < max_depth:
                try:
                    soup = BeautifulSoup(page_data["content"], "html.parser")
                    child_links = self.extract_links_from_tags(soup, page_data["final_url"])
                    
                    max_child_analyze = 20
                    child_links = child_links[:max_child_analyze]
                    
                    for child_link in child_links:
                        with state_lock:
                            if global_state["is_terminated"]:
                                break
                        child_results = self.analyze_child_link(
                            child_link, 
                            link_info["absolute_link"], 
                            depth + 1, 
                            max_depth,
                            rules
                        )
                        results.extend(child_results)
                except Exception as e:
                    self.log(f"解析子链接内容失败: {str(e)}", link_info["absolute_link"])
            
            return results
        finally:
            with state_lock:
                global_state["active_threads"] -= 1

    def get_unique_filename(self, base_dir, base_name, extension):
        """生成唯一的文件名"""
        try:
            if not os.path.exists(base_dir):
                os.makedirs(base_dir, exist_ok=True)
                
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
            self.log(f"生成唯一文件名失败: {str(e)}")
            emergency_filename = f"emergency_save_{os.getpid()}.{extension}"
            return os.path.join(base_dir, emergency_filename)

    def save_scan_results(self, results, base_filename="scan_results"):
        """保存扫描结果为CSV文件"""
        try:
            file_path = self.get_unique_filename(SCAN_RESULTS_DIR, base_filename, "csv")
            
            if not os.access(os.path.dirname(file_path), os.W_OK):
                raise Exception(f"目录不可写: {os.path.dirname(file_path)}")
            
            fieldnames = [
                "检测时间", "父级URL", "链接类型", "原始链接", "绝对链接",
                "HTTP状态码", "递归深度", "URL规则匹配项", "内容规则匹配项",
                "标签文本内容", "是否匹配URL规则", "是否匹配内容规则",
                "是否恶意", "威胁情报详情"
            ]
            
            temp_file = f"{file_path}.tmp"
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
            
            if os.path.exists(file_path):
                os.remove(file_path)
            os.rename(temp_file, file_path)
            
            return file_path
        except Exception as e:
            self.log(f"保存扫描结果失败: {str(e)}")
            if 'temp_file' in locals() and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
            return None

    def load_config(self):
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
            "rules_files": ["rules.txt"]
        }
        
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    config.update(loaded)
            except Exception as e:
                self.log(f"加载配置文件失败: {str(e)}，使用默认配置")
        
        return config

    def save_config(self):
        """保存配置到文件"""
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            self.log(f"配置已保存到 {CONFIG_PATH}")
            return True
        except Exception as e:
            self.log(f"保存配置文件失败: {str(e)}")
            return False

    # GUI特有功能实现
    def init_base_contents(self):
        """初始化基准内容"""
        file_path = self.url_file_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("警告", "请指定有效的URL文件")
            return
            
        urls = self.load_urls_from_file(file_path)
        if not urls:
            messagebox.showwarning("警告", "未找到有效的URL")
            return
        
        self.log(f"开始初始化 {len(urls)} 个URL的基准内容...")
        
        # 启动线程执行初始化
        threading.Thread(
            target=self._init_base_contents_thread, 
            args=(urls,),
            daemon=True
        ).start()

    def _init_base_contents_thread(self, urls):
        """初始化基准内容的线程函数"""
        success_count = 0
        
        with ThreadPoolExecutor(max_workers=self.config["default_threads"]) as executor:
            futures = {
                executor.submit(self.get_page_content, url, self.config["timeout"]): url 
                for url in urls
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    page_data = future.result()
                    if page_data and "content" in page_data:
                        parsed_url = urlparse(url)
                        filename = f"{parsed_url.netloc.replace(':', '_')}.html"
                        file_path = os.path.join(BASE_CONTENTS_DIR, filename)
                        
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(page_data["content"])
                        
                        success_count += 1
                        self.log(f"已保存基准内容", url)
                except Exception as e:
                    self.log(f"初始化基准内容失败: {str(e)}", url)
        
        self.log(f"基准内容初始化完成，成功 {success_count}/{len(urls)} ～(^▽^)")

    def configure_settings(self):
        """配置扫描参数"""
        # 创建配置窗口
        config_window = tk.Toplevel(self.root)
        config_window.title("⚙️ 扫描参数配置 ⚙️")
        config_window.geometry("400x300")
        config_window.configure(bg=CuteStyle.BACKGROUND)
        config_window.resizable(False, False)
        config_window.transient(self.root)
        config_window.grab_set()
        
        # 配置框架
        frame = ttk.Frame(config_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 线程数设置
        ttk.Label(frame, text="线程数量 (1-20):", font=CuteStyle.NORMAL_FONT).grid(
            row=0, column=0, sticky=tk.W, pady=10)
        
        threads_var = tk.IntVar(value=self.config["default_threads"])
        threads_spinbox = ttk.Spinbox(frame, from_=1, to=20, textvariable=threads_var, width=10)
        threads_spinbox.grid(row=0, column=1, sticky=tk.W, pady=10)
        
        # 超时设置
        ttk.Label(frame, text="超时时间 (秒):", font=CuteStyle.NORMAL_FONT).grid(
            row=1, column=0, sticky=tk.W, pady=10)
        
        timeout_var = tk.IntVar(value=self.config["timeout"])
        timeout_spinbox = ttk.Spinbox(frame, from_=5, to=60, textvariable=timeout_var, width=10)
        timeout_spinbox.grid(row=1, column=1, sticky=tk.W, pady=10)
        
        # 默认深度设置
        ttk.Label(frame, text="默认扫描深度 (1-5):", font=CuteStyle.NORMAL_FONT).grid(
            row=2, column=0, sticky=tk.W, pady=10)
        
        depth_var = tk.IntVar(value=self.config["max_depth"])
        depth_spinbox = ttk.Spinbox(frame, from_=1, to=5, textvariable=depth_var, width=10)
        depth_spinbox.grid(row=2, column=1, sticky=tk.W, pady=10)
        
        # 按钮区域
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="保存设置", command=lambda: self._save_settings(
            config_window, threads_var.get(), timeout_var.get(), depth_var.get()
        )).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(btn_frame, text="取消", command=config_window.destroy).pack(side=tk.LEFT, padx=10)

    def _save_settings(self, window, threads, timeout, depth):
        """保存配置设置"""
        if 1 <= threads <= 20:
            self.config["default_threads"] = threads
        else:
            messagebox.showwarning("警告", "线程数必须在1-20之间")
            return
            
        if 5 <= timeout <= 60:
            self.config["timeout"] = timeout
        else:
            messagebox.showwarning("警告", "超时时间必须在5-60之间")
            return
            
        if 1 <= depth <= 5:
            self.config["max_depth"] = depth
        else:
            messagebox.showwarning("警告", "扫描深度必须在1-5之间")
            return
            
        if self.save_config():
            messagebox.showinfo("成功", "配置已保存 ～(^▽^)")
            window.destroy()

    def manage_rules(self):
        """管理规则文件"""
        # 创建规则管理窗口
        rule_window = tk.Toplevel(self.root)
        rule_window.title("📜 规则管理 📜")
        rule_window.geometry("500x400")
        rule_window.configure(bg=CuteStyle.BACKGROUND)
        rule_window.transient(self.root)
        rule_window.grab_set()
        
        # 当前规则列表
        ttk.Label(rule_window, text="当前加载的规则文件:", font=CuteStyle.LARGE_FONT).pack(pady=10)
        
        rule_frame = ttk.Frame(rule_window)
        rule_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        self.rule_listbox = tk.Listbox(rule_frame, selectmode=tk.SINGLE, height=10)
        self.rule_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(rule_frame, orient=tk.VERTICAL, command=self.rule_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rule_listbox.config(yscrollcommand=scrollbar.set)
        
        # 加载当前规则
        for rule_file in self.config["rules_files"]:
            self.rule_listbox.insert(tk.END, rule_file)
        
        # 按钮区域
        btn_frame = ttk.Frame(rule_window)
        btn_frame.pack(fill=tk.X, pady=20, padx=20)
        
        ttk.Button(btn_frame, text="添加规则文件...", command=self.add_rule_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="删除选中规则", command=self.remove_selected_rule).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="编辑规则文件", command=self.edit_rule_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="关闭", command=rule_window.destroy).pack(side=tk.RIGHT, padx=10)

    def add_rule_file(self):
        """添加新的规则文件"""
        filename = filedialog.askopenfilename(
            title="选择规则文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if filename:
            # 复制到规则目录
            try:
                dest_path = os.path.join(RULES_DIR, os.path.basename(filename))
                shutil.copy2(filename, dest_path)
                
                # 添加到配置
                if os.path.basename(filename) not in self.config["rules_files"]:
                    self.config["rules_files"].append(os.path.basename(filename))
                    self.save_config()
                    self.rule_listbox.insert(tk.END, os.path.basename(filename))
                    self.log(f"已添加规则文件: {os.path.basename(filename)}")
                else:
                    messagebox.showinfo("提示", "该规则文件已加载")
            except Exception as e:
                self.log(f"复制规则文件失败: {str(e)}")
                messagebox.showerror("错误", f"添加规则失败: {str(e)}")

    def remove_selected_rule(self):
        """删除选中的规则文件"""
        selected = self.rule_listbox.curselection()
        if not selected:
            messagebox.showwarning("警告", "请先选择要删除的规则文件")
            return
            
        index = selected[0]
        rule_file = self.rule_listbox.get(index)
        
        if messagebox.askyesno("确认", f"确定要删除规则文件 '{rule_file}' 吗？"):
            try:
                self.config["rules_files"].remove(rule_file)
                self.save_config()
                self.rule_listbox.delete(index)
                self.log(f"已删除规则文件: {rule_file}")
            except Exception as e:
                self.log(f"删除规则文件失败: {str(e)}")
                messagebox.showerror("错误", f"删除规则失败: {str(e)}")

    def edit_rule_file(self):
        """编辑规则文件"""
        selected = self.rule_listbox.curselection()
        if not selected:
            messagebox.showwarning("警告", "请先选择要编辑的规则文件")
            return
            
        rule_file = self.rule_listbox.get(selected[0])
        file_path = os.path.join(RULES_DIR, rule_file)
        
        if not os.path.exists(file_path):
            file_path = os.path.join(SCRIPT_DIR, rule_file)
        
        if os.path.exists(file_path):
            # 使用系统默认程序打开
            try:
                if platform.system() == 'Windows':
                    os.startfile(file_path)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.run(['open', file_path])
                else:  # Linux
                    subprocess.run(['xdg-open', file_path])
            except Exception as e:
                messagebox.showerror("错误", f"无法打开文件: {str(e)}")
        else:
            messagebox.showerror("错误", "规则文件不存在")

    def setup_scheduled_scan(self):
        """设置定时扫描"""
        # 创建定时设置窗口
        schedule_window = tk.Toplevel(self.root)
        schedule_window.title("⏰ 定时扫描设置 ⏰")
        schedule_window.geometry("400x200")
        schedule_window.configure(bg=CuteStyle.BACKGROUND)
        schedule_window.transient(self.root)
        schedule_window.grab_set()
        
        frame = ttk.Frame(schedule_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="当前设置: 每 {} 分钟扫描一次".format(
            self.config["schedule_interval"]), font=CuteStyle.NORMAL_FONT).pack(pady=10)
        
        ttk.Label(frame, text="请输入扫描间隔 (分钟):", font=CuteStyle.NORMAL_FONT).pack(pady=10)
        
        interval_var = tk.IntVar(value=self.config["schedule_interval"])
        interval_entry = ttk.Entry(frame, textvariable=interval_var, width=10)
        interval_entry.pack(pady=10)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="保存设置", command=lambda: self._save_schedule_settings(
            schedule_window, interval_var.get()
        )).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(btn_frame, text="取消", command=schedule_window.destroy).pack(side=tk.LEFT, padx=10)

    def _save_schedule_settings(self, window, interval):
        """保存定时设置"""
        if interval == 0:
            self.config["schedule_interval"] = 0
            self.save_config()
            messagebox.showinfo("成功", "已取消定时扫描")
            window.destroy()
            return
            
        if interval < 5:
            messagebox.showwarning("警告", "扫描间隔不能小于5分钟")
            return
            
        self.config["schedule_interval"] = interval
        self.save_config()
        
        messagebox.showinfo("成功", f"定时扫描已设置为每 {interval} 分钟一次")
        window.destroy()
        
        # 启动定时任务
        self.start_scheduled_scans()

    def start_scheduled_scans(self):
        """启动定时扫描任务"""
        if self.config["schedule_interval"] <= 0:
            return
            
        def scheduled_job():
            self.log(f"\n===== 定时扫描开始 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) =====")
            urls = self.load_urls_from_file(self.url_file_var.get())
            if urls:
                self.run_batch_scan(urls, self.config["max_depth"])
            else:
                self.log("未找到有效的URL，定时扫描取消")
        
        # 立即执行一次
        threading.Thread(target=scheduled_job, daemon=True).start()
        
        # 设置定时任务
        def schedule_runner():
            while True:
                schedule.run_pending()
                time.sleep(60)
        
        schedule.every(self.config["schedule_interval"]).minutes.do(scheduled_job)
        threading.Thread(target=schedule_runner, daemon=True).start()

    def configure_api_keys(self):
        """配置API密钥"""
        # 创建API配置窗口
        api_window = tk.Toplevel(self.root)
        api_window.title("🔑 API密钥配置 🔑")
        api_window.geometry("500x300")
        api_window.configure(bg=CuteStyle.BACKGROUND)
        api_window.transient(self.root)
        api_window.grab_set()
        
        frame = ttk.Frame(api_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # VirusTotal API
        ttk.Label(frame, text="VirusTotal API密钥:", font=CuteStyle.NORMAL_FONT).grid(
            row=0, column=0, sticky=tk.W, pady=10)
        
        vt_var = tk.StringVar(value=self.config["virustotal_api_key"])
        vt_entry = ttk.Entry(frame, textvariable=vt_var, width=40, show="*")
        vt_entry.grid(row=0, column=1, sticky=tk.W, pady=10)
        
        # 微步在线API
        ttk.Label(frame, text="微步在线API密钥:", font=CuteStyle.NORMAL_FONT).grid(
            row=1, column=0, sticky=tk.W, pady=10)
        
        wb_var = tk.StringVar(value=self.config["weibu_api_key"])
        wb_entry = ttk.Entry(frame, textvariable=wb_var, width=40, show="*")
        wb_entry.grid(row=1, column=1, sticky=tk.W, pady=10)
        
        # 奇安信API
        ttk.Label(frame, text="奇安信API密钥:", font=CuteStyle.NORMAL_FONT).grid(
            row=2, column=0, sticky=tk.W, pady=10)
        
        qk_var = tk.StringVar(value=self.config["qiankong_api_key"])
        qk_entry = ttk.Entry(frame, textvariable=qk_var, width=40, show="*")
        qk_entry.grid(row=2, column=1, sticky=tk.W, pady=10)
        
        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="保存密钥", command=lambda: self._save_api_keys(
            api_window, vt_var.get(), wb_var.get(), qk_var.get()
        )).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(btn_frame, text="取消", command=api_window.destroy).pack(side=tk.LEFT, padx=10)

    def _save_api_keys(self, window, vt_key, wb_key, qk_key):
        """保存API密钥"""
        self.config["virustotal_api_key"] = vt_key
        self.config["weibu_api_key"] = wb_key
        self.config["qiankong_api_key"] = qk_key
        
        if self.save_config():
            messagebox.showinfo("成功", "API密钥已保存 ～(^▽^)")
            window.destroy()

    def view_scan_history(self):
        """查看扫描历史"""
        if not os.path.exists(SCAN_RESULTS_DIR) or not os.listdir(SCAN_RESULTS_DIR):
            messagebox.showinfo("提示", "暂无扫描历史记录")
            return
        
        # 创建历史记录窗口
        history_window = tk.Toplevel(self.root)
        history_window.title("📜 扫描历史 📜")
        history_window.geometry("700x500")
        history_window.configure(bg=CuteStyle.BACKGROUND)
        history_window.transient(self.root)
        history_window.grab_set()
        
        # 历史记录列表
        ttk.Label(history_window, text="扫描历史记录:", font=CuteStyle.LARGE_FONT).pack(pady=10)
        
        history_frame = ttk.Frame(history_window)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        self.history_listbox = tk.Listbox(history_frame, selectmode=tk.SINGLE, width=80, height=15)
        self.history_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_listbox.config(yscrollcommand=scrollbar.set)
        
        # 加载历史记录
        files = []
        for fname in os.listdir(SCAN_RESULTS_DIR):
            if fname.endswith(".csv"):
                fpath = os.path.join(SCAN_RESULTS_DIR, fname)
                ftime = os.path.getctime(fpath)
                files.append((-ftime, fname, fpath))
        
        files.sort()
        
        self.history_files = []
        for _, fname, fpath in files[:20]:  # 只显示最近20条
            fsize = os.path.getsize(fpath) / 1024
            fdate = datetime.fromtimestamp(os.path.getctime(fpath)).strftime('%Y-%m-%d %H:%M')
            self.history_listbox.insert(tk.END, f"{fname} ({fsize:.1f}KB) - {fdate}")
            self.history_files.append(fpath)
        
        # 按钮区域
        btn_frame = ttk.Frame(history_window)
        btn_frame.pack(fill=tk.X, pady=20, padx=20)
        
        ttk.Button(btn_frame, text="查看详情", command=lambda: self.view_history_details(history_window)).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="打开文件", command=self.open_history_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="删除记录", command=self.delete_history_record).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="关闭", command=history_window.destroy).pack(side=tk.RIGHT, padx=10)

    def view_history_details(self, parent_window):
        """查看历史记录详情"""
        selected = self.history_listbox.curselection()
        if not selected:
            messagebox.showwarning("警告", "请先选择要查看的记录")
            return
            
        index = selected[0]
        fpath = self.history_files[index]
        fname = os.path.basename(fpath)
        
        # 创建详情窗口
        detail_window = tk.Toplevel(parent_window)
        detail_window.title(f"📝 {fname} 详情 📝")
        detail_window.geometry("700x500")
        detail_window.configure(bg=CuteStyle.BACKGROUND)
        detail_window.transient(parent_window)
        
        # 详情内容
        ttk.Label(detail_window, text=f"记录: {fname}", font=CuteStyle.LARGE_FONT).pack(pady=10)
        
        text_frame = ttk.Frame(detail_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        text_area = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD, 
            font=CuteStyle.SMALL_FONT,
            bg=CuteStyle.BACKGROUND,
            fg=CuteStyle.TEXT_COLOR
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        
        try:
            with open(fpath, 'r', encoding='utf-8-sig') as f:
                reader = csv.reader(f)
                headers = next(reader)
                text_area.insert(tk.END, ", ".join(headers) + "\n\n")
                
                count = 0
                for row in reader:
                    if count >= 20:
                        text_area.insert(tk.END, "... 显示前20条记录 ...\n")
                        break
                    text_area.insert(tk.END, ", ".join(row) + "\n")
                    count += 1
        except Exception as e:
            text_area.insert(tk.END, f"读取文件失败: {str(e)}")
        
        text_area.config(state=tk.DISABLED)
        
        ttk.Label(detail_window, text=f"文件路径: {fpath}", font=CuteStyle.SMALL_FONT).pack(anchor=tk.W, padx=20, pady=10)
        ttk.Button(detail_window, text="关闭", command=detail_window.destroy).pack(pady=10)

    def open_history_file(self):
        """打开历史记录文件"""
        selected = self.history_listbox.curselection()
        if not selected:
            messagebox.showwarning("警告", "请先选择要打开的记录")
            return
            
        index = selected[0]
        fpath = self.history_files[index]
        
        try:
            if platform.system() == 'Windows':
                os.startfile(fpath)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', fpath])
            else:  # Linux
                subprocess.run(['xdg-open', fpath])
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件: {str(e)}")

    def delete_history_record(self):
        """删除历史记录"""
        selected = self.history_listbox.curselection()
        if not selected:
            messagebox.showwarning("警告", "请先选择要删除的记录")
            return
            
        index = selected[0]
        fpath = self.history_files[index]
        fname = os.path.basename(fpath)
        
        if messagebox.askyesno("确认", f"确定要删除记录 '{fname}' 吗？"):
            try:
                os.remove(fpath)
                self.history_listbox.delete(index)
                del self.history_files[index]
                self.log(f"已删除历史记录: {fname}")
            except Exception as e:
                messagebox.showerror("错误", f"删除记录失败: {str(e)}")

    def show_system_info(self):
        """显示系统信息"""
        # 创建系统信息窗口
        info_window = tk.Toplevel(self.root)
        info_window.title("💻 系统信息 💻")
        info_window.geometry("600x400")
        info_window.configure(bg=CuteStyle.BACKGROUND)
        info_window.transient(self.root)
        info_window.grab_set()
        
        # 信息内容
        ttk.Label(info_window, text="系统与解释器信息", font=CuteStyle.LARGE_FONT).pack(pady=10)
        
        text_frame = ttk.Frame(info_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        text_area = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD, 
            font=CuteStyle.NORMAL_FONT,
            bg=CuteStyle.BACKGROUND,
            fg=CuteStyle.TEXT_COLOR
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        
        # 收集系统信息
        info = [
            "="*50,
            "Python 解释器信息:",
            f"• 解释器路径: {sys.executable}",
            f"• Python 版本: {sys.version.split()[0]}",
            f"• 系统平台: {platform.system()} {platform.release()} ({platform.machine()})",
            f"• 运行目录: {os.getcwd()}",
            "="*50,
            "\n扫描姬配置信息:",
            f"• 线程数: {self.config['default_threads']}",
            f"• 超时时间: {self.config['timeout']}秒",
            f"• 默认深度: {self.config['max_depth']}",
            f"• 定时间隔: {self.config['schedule_interval']}分钟",
            f"• 已加载规则: {len(self.config['rules_files'])}个",
            "="*50,
            "\n目录信息:",
            f"• 脚本目录: {SCRIPT_DIR}",
            f"• 结果目录: {SCAN_RESULTS_DIR}",
            f"• 规则目录: {RULES_DIR}",
            f"• 基准目录: {BASE_CONTENTS_DIR}",
            "="*50
        ]
        
        text_area.insert(tk.END, "\n".join(info))
        text_area.config(state=tk.DISABLED)
        
        ttk.Button(info_window, text="关闭", command=info_window.destroy).pack(pady=10)

    def setup_signal_handlers(self):
        """设置信号处理器"""
        def handle_termination(signum, frame):
            """处理强制终止信号"""
            with state_lock:
                if global_state["is_terminated"]:
                    self.log("\n再次收到终止信号，强制退出...")
                    os._exit(1)
                    
                global_state["is_terminated"] = True
            
            # 输出当前分析状态
            with state_lock:
                elapsed_time = datetime.now() - global_state["start_time"] if global_state["start_time"] else 0
                self.log("\n当前分析状态:")
                self.log(f"总URL数: {global_state['total_urls']}")
                self.log(f"已处理: {global_state['processed_urls']}/{global_state['total_urls']}")
                self.log(f"当前处理: {global_state['current_url'] or '无'}")
                self.log(f"活跃线程: {global_state['active_threads']}")
                self.log(f"已分析链接数: {len(global_state['results'])}")
                self.log(f"运行时间: {str(elapsed_time)}")
            
            # 保存当前结果
            save_path = None
            if global_state["results"]:
                try:
                    with global_state["save_lock"]:
                        save_path = self.save_scan_results(global_state["results"], "interrupted_scan")
                    if save_path:
                        self.log(f"\n[!] 中间结果已保存至: {save_path}")
                    else:
                        self.log("\n[!] 尝试保存结果失败")
                except Exception as e:
                    self.log(f"\n[!] 保存结果时发生错误: {str(e)}")
            else:
                self.log("\n[!] 暂无结果可保存")
            
            self.log("\n程序已安全终止")
            os._exit(0)
        
        try:
            if sys.platform.startswith('win32'):
                signal.signal(signal.SIGINT, handle_termination)
            else:
                signal.signal(signal.SIGTSTP, handle_termination)
        except Exception as e:
            self.log(f"信号处理初始化警告: {str(e)}")
            self.log("强制终止功能可能无法正常工作")

    def exit_program(self):
        """退出程序"""
        if messagebox.askyesno("确认", "真的要离开扫描姬吗？(｡•́︿•̀｡)"):
            self.root.destroy()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = DarkScanGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"程序出错: {str(e)}")
        try:
            if global_state["results"]:
                # 创建一个简单的保存函数用于错误恢复
                def emergency_save(results):
                    try:
                        file_path = os.path.join(SCAN_RESULTS_DIR, f"emergency_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
                        with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                            writer = csv.writer(f)
                            writer.writerow(["时间", "URL", "是否恶意"])
                            for r in results:
                                writer.writerow([r["timestamp"], r["absolute_link"], r["is_malicious"]])
                        return file_path
                    except:
                        return None
                
                save_path = emergency_save(global_state["results"])
                if save_path:
                    print(f"错误恢复: 已保存当前结果至 {save_path}")
        except:
            print("错误恢复: 保存当前结果失败")
    os._exit(0)