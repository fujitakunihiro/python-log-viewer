from __future__ import annotations

import json
import os
import sys
import re
import html
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk
from typing import Dict, List, Tuple, Optional, Any

# --- DnD Support ---
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    ROOT_CLASS = TkinterDnD.Tk
    HAS_DND = True
except ImportError:
    ROOT_CLASS = tk.Tk
    HAS_DND = False

# --- Constants ---
VSYNC_TAG = "<VSYNC>"
VSYNC_REGEX = r"V_START|V-Sync|VIRTUAL V-SYNC|\[VIRTUAL V-SYNC\]"
VSYNC_MARKER = "--- [VIRTUAL V-SYNC] ---"
VIRTUAL_SRC_NAME = "(Virtual)"

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "keywords":[
        {"file_pattern": ".*", "pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"file_pattern": ".*", "pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 2},
        {"file_pattern": ".*", "pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0},
        {"file_pattern": ".*", "pattern": r"--- \[VIRTUAL V-SYNC\] ---", "color": "#e1bee7", "comment": "仮想V同期タイミング", "enabled": True, "extra_lines": 0},
        {"file_pattern": ".*", "pattern": r"--- \[VIRTUAL TIMER\].*", "color": "#ffe0b2", "comment": "タイマー満了", "enabled": True, "extra_lines": 0}
    ],
    "sections":[
        {"name": "初期化(Server)", "start": "SRV_INIT_START", "start_wait": False, "end": "SRV_INIT_DONE", "end_wait": False, "duration_ms": "", "color": "#e1f5fe", "file_pattern": "server.*", "enabled": True},
        {"name": "初期化(Client)", "start": "CLI_BOOT",       "start_wait": False, "end": "CLI_READY",     "end_wait": False, "duration_ms": "", "color": "#e0f2f1", "file_pattern": "client.*", "enabled": True},
        {"name": "通信処理",       "start": "CONNECT",        "start_wait": False, "end": "DISCONNECT",    "end_wait": False, "duration_ms": "", "color": "#fff3e0", "file_pattern": ".*",       "enabled": True}
    ],
    "replace_patterns":[],
    "vsync_auto_insert": {
        "enabled": True,
        "time_pattern": r"^\[?\s*(\d+(?:\.\d+)?)\]?",
        "manual_ms": 16.666,
        "start_mode": "line",
        "start_line": "",
        "start_time_val": "2.0"
    }
}

class LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        for ev in['<KeyRelease>', '<MouseWheel>', '<Configure>', '<<Modified>>', '<Button-1>']:
            self.text_widget.bind(ev, self.redraw)

    def redraw(self, *args):
        self.delete("all")
        i = self.text_widget.index("@0,0")
        while True:
            dline = self.text_widget.dlineinfo(i)
            if dline is None: break
            y = dline[1]
            linenum = str(i).split(".")[0]
            self.create_text(40, y, anchor="ne", text=linenum, fill="#666666")
            i = self.text_widget.index(f"{i}+1line")

class LogTab(tk.Frame):
    def __init__(self, master, app, path, content, source_files_list=None, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged
        
        self.source_file_names = source_files_list if source_files_list else ([os.path.basename(path)] if path else[])
        self.line_source_map: List[str] =[]
        self.status_texts: Dict[str, tk.Text] = {}
        self._create_layout()

    def _create_layout(self):
        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=650)
        
        header_text = "[Merged View]" if self.is_merged else (self.source_file_names[0] if self.source_file_names else "Log Content")
        tk.Label(left_frame, text=header_text, bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.text.tag_config("found", background="#0000cd", foreground="white")
        
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        
        self.timediff_text = tk.Text(left_frame, width=12, wrap=tk.NONE, bg="#f8f8f8", fg="#555555", yscrollcommand=self.vsb.set)
        self.timediff_text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.timediff_text.pack(side=tk.LEFT, fill=tk.Y)

        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)
        
        cmt_frame = tk.Frame(self.paned_window)
        self.paned_window.add(cmt_frame, minsize=50, stretch="always", width=250)
        
        self.hsb_cmt = tk.Scrollbar(cmt_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(cmt_frame, text="Comment / Tags", bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        
        self.comment_text = tk.Text(cmt_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa", yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)
        
        for fname in self.source_file_names:
            st_frame = tk.Frame(self.paned_window)
            self.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
            tk.Label(st_frame, text=f"{fname}の区間", bg="#dcedc8", relief=tk.RAISED, font=("MS UI Gothic", 9, "bold")).pack(side=tk.TOP, fill=tk.X)
            
            hsb = tk.Scrollbar(st_frame, orient=tk.HORIZONTAL)
            hsb.pack(side=tk.BOTTOM, fill=tk.X)
            
            st_text = tk.Text(st_frame, wrap=tk.NONE, bg="#f8f8f8", fg="#333333", yscrollcommand=self.vsb.set, xscrollcommand=hsb.set)
            st_text.tag_configure("sel", background="#cce8ff", foreground="black")
            st_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hsb.config(command=st_text.xview)
            self.status_texts[fname] = st_text
            
        self.all_texts =[self.text, self.timediff_text, self.comment_text] + list(self.status_texts.values())
        
        # カーソル行のハイライト設定
        for w in self.all_texts:
            w.tag_configure("cursor_line", background="#ffdddd", underline=True)
            w.bind('<ButtonRelease-1>', self.update_cursor_line)
            w.bind('<KeyRelease>', self.update_cursor_line)
        
        def sync_yview(*args):
            for t in self.all_texts: t.yview(*args)
            self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)
        
        def on_mw(e):
            d = int(-1*(e.delta/120)) if e.delta else 0
            for t in self.all_texts: t.yview_scroll(d, "units")
            self.linenumbers.redraw()
            return "break"
        for t in self.all_texts: t.bind('<MouseWheel>', on_mw)

    def update_cursor_line(self, event=None):
        if not hasattr(self, 'all_texts'): return
        widget = event.widget if event and isinstance(event.widget, tk.Text) else self.text
        try:
            idx = widget.index("insert")
            line_num = idx.split('.')[0]
            
            for w in self.all_texts:
                w.tag_remove("cursor_line", "1.0", tk.END)
                w.tag_add("cursor_line", f"{line_num}.0", f"{line_num}.end")
                w.tag_raise("cursor_line")
        except:
            pass

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1450x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        self.keywords_config =[x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.sections_config =[x.copy() for x in DEFAULT_CONFIG["sections"]]
        self.replace_patterns_config =[]
        self.vsync_config = DEFAULT_CONFIG["vsync_auto_insert"].copy()
        
        self.use_keyword_filter = False
        self.show_vsync_lines = True 
        self.last_merge_ts_len = 19
        
        self.keywords_dlg_ref = None
        self.replace_dlg_ref = None
        self.sections_dlg_ref = None
        self.find_window_ref = None
        self.last_search_keyword = ""
        self.vsync_settings_dlg_ref = None

        self._build_ui()
        
        self.root.bind('<F5>', lambda e: self.reload_file())
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-w>', lambda e: self.close_tab())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())
        self.root.bind('<Shift-F3>', lambda e: self.find_prev())
        
        if os.path.exists(self.config_path):
            self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="再読み込み", command=self.reload_file, accelerator="F5")
        fmenu.add_separator()
        fmenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        fmenu.add_separator()
        fmenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        fmenu.add_separator()
        fmenu.add_command(label="終了", command=self.root.quit)
        menubar.add_cascade(label="ファイル", menu=fmenu)
        
        emenu = tk.Menu(menubar, tearoff=0)
        emenu.add_command(label="検索...", command=self.open_find_dialog, accelerator="Ctrl+F")
        emenu.add_command(label="次を検索", command=self.find_next, accelerator="F3")
        emenu.add_command(label="前を検索", command=self.find_prev, accelerator="Shift+F3")
        menubar.add_cascade(label="編集", menu=emenu)

        cmenu = tk.Menu(menubar, tearoff=0)
        cmenu.add_command(label="設定読み込み...", command=self.load_config_dialog)
        cmenu.add_command(label="設定保存...", command=self.save_config_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="フィルタ設定の編集 (行単位)...", command=self.edit_keywords_dialog)
        cmenu.add_command(label="区間設定の編集 (開始-終了)...", command=self.edit_sections_dialog)
        cmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="V周期(仮想)挿入の設定...", command=self.open_vsync_settings_dialog)
        menubar.add_cascade(label="設定", menu=cmenu)
        
        self.root.config(menu=menubar)
        
        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=12, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e3f2fd").pack(side=tk.LEFT, padx=10)
        
        self.btn_vsync_toggle = tk.Button(toolbar, text="V周期表示: ON", width=12, command=self.toggle_vsync_display)
        self.btn_vsync_toggle.pack(side=tk.LEFT, padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.status_var = tk.StringVar(value="準備完了")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e:[self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    # --- File/Merge ---
    def open_file(self):
        for p in filedialog.askopenfilenames(): self._open_file_path(p)

    def close_tab(self):
        t = self.get_current_tab()
        if t: self.notebook.forget(t)

    def reload_file(self):
        tab = self.get_current_tab()
        if not tab: return
        
        if getattr(tab, "file_path", "") == "Merged":
            self.notebook.forget(tab)
            tabs =[self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
            target_tabs =[t for t in tabs if getattr(t, "file_path", "") and t.file_path != "Merged"]
            
            for t in target_tabs:
                if os.path.exists(t.file_path):
                    content = ""
                    for enc in['utf-8', 'cp932', 'shift_jis', 'latin-1']:
                        try:
                            with open(t.file_path, "r", encoding=enc) as f: content = f.read(); break
                        except: continue
                    
                    if self.vsync_config.get("enabled", True):
                        fname = os.path.basename(t.file_path)
                        new_content, new_src_map = self._process_vsync_insertion(content, [fname]*len(content.splitlines()), [fname])
                        t.original_content = new_content
                        t.line_source_map = new_src_map
                    else: 
                        t.original_content = content
                        t.line_source_map =[] 
                    self.apply_display_update(t)
            
            if len(target_tabs) >= 2:
                self.merge_logs_action(auto_ts_len=self.last_merge_ts_len)
            return

        if not tab.file_path or not os.path.exists(tab.file_path): return
        
        content = ""
        for enc in['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(tab.file_path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        
        if self.vsync_config.get("enabled", True):
            fname = os.path.basename(tab.file_path)
            new_content, new_src_map = self._process_vsync_insertion(content, [fname]*len(content.splitlines()), [fname])
            tab.original_content = new_content
            tab.line_source_map = new_src_map
        else: 
            tab.original_content = content
            tab.line_source_map =[] 
            
        self.apply_display_update(tab)
        self.status_var.set(f"再読み込み完了: {os.path.basename(tab.file_path)}")

    def _open_file_path(self, path: str):
        content = ""
        for enc in['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
            
        fname = os.path.basename(path)
        if self.vsync_config.get("enabled", True):
            new_content, new_src_map = self._process_vsync_insertion(content,[fname]*len(content.splitlines()), [fname])
            tab = LogTab(self.notebook, self, path, new_content, source_files_list=[fname], is_merged=True)
            tab.line_source_map = new_src_map
            self.notebook.add(tab, text=fname)
            self.notebook.select(tab)
            self.apply_display_update(tab)
        else:
            tab = LogTab(self.notebook, self, path, content, source_files_list=[fname])
            self.notebook.add(tab, text=fname)
            self.notebook.select(tab)
            self.apply_display_update(tab)

    def merge_logs_action(self, auto_ts_len=None):
        tabs =[self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
        target_tabs =[t for t in tabs if getattr(t, "file_path", "") and t.file_path != "Merged"]
        if len(target_tabs) < 2:
            messagebox.showinfo("マージ", "マージするには2つ以上のログファイルを開いてください。")
            return
            
        if auto_ts_len is not None:
            ts_len = auto_ts_len
        else:
            ts_len = simpledialog.askinteger("マージ", "時刻ソート用の先頭文字数:", initialvalue=self.last_merge_ts_len, minvalue=0)
            if ts_len is None: return
            self.last_merge_ts_len = ts_len
        
        kw_rules =[]
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: 
                    kw_rules.append((
                        re.compile(itm.get("file_pattern", ".*") or ".*", re.I),
                        re.compile(itm["pattern"], re.I), 
                        int(itm.get("extra_lines", 0))
                    ))
                except: pass
                
        all_blocks =[]
        unique_srcs =[]
        
        for t in target_tabs:
            fn = os.path.basename(t.file_path)
            if fn not in unique_srcs: unique_srcs.append(fn)
            
            raw_lines = t.original_content.splitlines()
            if not raw_lines: continue
            
            effective_ts =[]
            last_valid_ts = ""
            for line in raw_lines:
                ts_part = line[:ts_len]
                if ts_part.strip() and len(line) > 0 and not line[0].isspace(): last_valid_ts = ts_part
                effective_ts.append(last_valid_ts)
            first_ts = next((x for x in effective_ts if x), "0"*ts_len)
            effective_ts =[x if x else first_ts for x in effective_ts]
            
            i = 0
            while i < len(raw_lines):
                line = raw_lines[i]
                current_src = t.line_source_map[i] if (t.line_source_map and i < len(t.line_source_map)) else fn
                extra = 0
                for fpat, pat, ex in kw_rules:
                    if fpat.search(current_src) and pat.search(line): 
                        extra = ex
                        break
                
                actual_extra = 0
                for j in range(1, extra + 1):
                    if i + j < len(raw_lines):
                        next_line = raw_lines[i + j]
                        ts_part_next = next_line[:ts_len]
                        if ts_part_next.strip() and len(next_line) > 0 and not next_line[0].isspace():
                            break
                        actual_extra += 1
                
                bl = raw_lines[i : i + actual_extra + 1]
                skey = effective_ts[i]
                all_blocks.append((skey, bl, current_src))
                i += actual_extra + 1
                
        all_blocks.sort(key=lambda x: x[0])
        final_lines, final_src =[],[]
        for _, bl, src_name in all_blocks:
            final_lines.extend(bl)
            final_src.extend([src_name] * len(bl))
            
        m_tab = LogTab(self.notebook, self, "Merged", "\n".join(final_lines), source_files_list=unique_srcs, is_merged=True)
        m_tab.line_source_map = final_src
        self.notebook.add(m_tab, text="[マージ結果]")
        self.notebook.select(m_tab)
        self.apply_display_update(m_tab)

    # --- Virtual V-Sync (Settings) ---
    def open_vsync_settings_dialog(self):
        if self.vsync_settings_dlg_ref and self.vsync_settings_dlg_ref.winfo_exists():
            self.vsync_settings_dlg_ref.lift()
            return
        
        dlg = tk.Toplevel(self.root)
        dlg.title("V周期(仮想)挿入の設定")
        dlg.geometry("480x250")
        self.vsync_settings_dlg_ref = dlg
        
        conf = self.vsync_config
        
        tk.Label(dlg, text="V周期(仮想)挿入の起点とタイミングを設定します。\n設定を保存すると、次回ファイルを開く時から自動適用されます。", anchor="w", font=("", 9, "bold")).pack(pady=10, padx=10, fill=tk.X)

        # --- 開始位置の指定 ---
        frame_start = tk.LabelFrame(dlg, text="開始位置の指定")
        frame_start.pack(fill=tk.X, padx=10, pady=(5, 5))
        
        start_mode_val = conf.get("start_mode", "line")
        if start_mode_val not in ["line", "time"]:
            start_mode_val = "line"
        start_mode_var = tk.StringVar(value=start_mode_val)
        
        f_start_line = tk.Frame(frame_start)
        f_start_line.pack(anchor="w", padx=5, pady=2)
        rb_start_line = tk.Radiobutton(f_start_line, text="指定した行番号の時刻から開始 (生ログ行番号):", variable=start_mode_var, value="line")
        rb_start_line.pack(side=tk.LEFT)
        e_start_line = tk.Entry(f_start_line, width=10)
        e_start_line.pack(side=tk.LEFT, padx=5)
        e_start_line.insert(0, str(conf.get("start_line", "")))
        
        f_start_time = tk.Frame(frame_start)
        f_start_time.pack(anchor="w", padx=5, pady=2)
        rb_start_time = tk.Radiobutton(f_start_time, text="指定した時刻(秒)から強制開始:", variable=start_mode_var, value="time")
        rb_start_time.pack(side=tk.LEFT)
        e_start_time = tk.Entry(f_start_time, width=10)
        e_start_time.pack(side=tk.LEFT, padx=5)
        e_start_time.insert(0, str(conf.get("start_time_val", "2.0")))

        # --- 間隔設定 ---
        frame_mode = tk.LabelFrame(dlg, text="間隔設定")
        frame_mode.pack(fill=tk.X, padx=10, pady=5)
        
        f_manual = tk.Frame(frame_mode)
        f_manual.pack(anchor="w", padx=5, pady=2)
        tk.Label(f_manual, text="挿入間隔 (ms):").pack(side=tk.LEFT)
        e_ms = tk.Entry(f_manual, width=10)
        e_ms.pack(side=tk.LEFT, padx=5)
        e_ms.insert(0, str(conf.get("manual_ms", 16.666)))

        def save_conf():
            try: ms = float(e_ms.get())
            except: ms = 16.666
            
            self.vsync_config = {
                "enabled": True, 
                "time_pattern": r"^\[?\s*(\d+(?:\.\d+)?)\]?",
                "manual_ms": ms,
                "start_mode": start_mode_var.get(),
                "start_line": e_start_line.get(),
                "start_time_val": e_start_time.get()
            }
            self.save_config_dialog_silent() 
            messagebox.showinfo("保存", "設定を保存しました。次回ファイルオープン時から適用されます。")
            dlg.destroy()

        btn_box = tk.Frame(dlg)
        btn_box.pack(pady=10, fill=tk.X)
        tk.Button(btn_box, text="OK", command=save_conf, bg="#ddddff", width=15).pack(side=tk.RIGHT, padx=10)

    def save_config_dialog_silent(self, filepath=None):
        target_path = filepath if filepath else self.config_path
        data = {
            "keywords": self.keywords_config, 
            "sections": self.sections_config, 
            "replace_patterns": self.replace_patterns_config, 
            "vsync_auto_insert": self.vsync_config
        }
        try:
            with open(target_path, "w", encoding="utf-8") as f: 
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e: 
            print(f"Config Save Error: {e}")

    def _parse_time_seconds(self, ts_str: str) -> Optional[float]:
        try:
            if ":" in ts_str:
                parts = ts_str.split(":")
                h = int(parts[0])
                m = int(parts[1])
                s = float(parts[2])
                return h * 3600 + m * 60 + s
            else:
                return float(ts_str)
        except:
            return None

    def _process_vsync_insertion(self, content: str, src_map: List[str], src_file_names: List[str]) -> Tuple[str, List[str]]:
        lines_temp = content.splitlines()
        src_map_temp = src_map if len(src_map) == len(lines_temp) else src_map + [""] * (len(lines_temp) - len(src_map))
        
        ts_pat = self.vsync_config.get("time_pattern", r"^\[?\s*(\d+(?:\.\d+)?)\]?")
        try: re_ts = re.compile(ts_pat)
        except: re_ts = re.compile(r"^\[?\s*(\d+(?:\.\d+)?)\]?")
            
        timestamps_temp =[]
        is_colon_format = False
        for line in lines_temp:
            m = re_ts.search(line)
            if m:
                ts_str = m.group(1)
                if ":" in ts_str: is_colon_format = True
                timestamps_temp.append(self._parse_time_seconds(ts_str))
            else:
                timestamps_temp.append(None)
                
        def format_sec(s):
            if is_colon_format:
                h = int(s // 3600)
                m = int((s % 3600) // 60)
                sec = s % 60
                return f"{h:02d}:{m:02d}:{sec:06.3f}"
            else: return f"[{s:.6f}]"

        # === PASS 1: Virtual V-Sync Insertion ===
        manual_ms = self.vsync_config.get("manual_ms", 16.666)
        start_mode = self.vsync_config.get("start_mode", "line")
        start_line_str = self.vsync_config.get("start_line", "")
        start_time_val_str = self.vsync_config.get("start_time_val", "0.0")
        
        start_time = None
        start_line_idx = -1
        
        if start_mode == "time":
            try:
                start_time = float(start_time_val_str)
            except Exception:
                pass
        elif start_mode == "line":
            try:
                line_num = int(start_line_str)
                line_idx = line_num - 1
                if 0 <= line_idx < len(timestamps_temp):
                    t = timestamps_temp[line_idx]
                    if t is not None:
                        start_time = t
                        start_line_idx = line_idx
            except Exception:
                pass
                
        try:
            manual_ms_val = float(manual_ms)
        except:
            manual_ms_val = 16.666
            
        interval_sec = manual_ms_val / 1000.0
            
        lines_v =[]
        src_map_v =[]
        timestamps_v =[]

        if start_time is not None:
            next_virtual_ts = start_time + interval_sec
            for i, line in enumerate(lines_temp):
                line_ts = timestamps_temp[i]
                if line_ts is not None and line_ts > start_time:
                    insertion_count = 0
                    while next_virtual_ts < line_ts and insertion_count < 100:
                        lines_v.append(f"{format_sec(next_virtual_ts)} {VSYNC_MARKER}")
                        src_map_v.append(VIRTUAL_SRC_NAME)
                        timestamps_v.append(next_virtual_ts)
                        next_virtual_ts += interval_sec
                        insertion_count += 1
                    if insertion_count >= 100: next_virtual_ts = line_ts + interval_sec
                    
                if i == start_line_idx:
                    lines_v.append(line + "  <<< [V-SYNC 起点]")
                else:
                    lines_v.append(line)
                src_map_v.append(src_map_temp[i])
                timestamps_v.append(line_ts)
        else:
            lines_v = lines_temp
            src_map_v = src_map_temp
            timestamps_v = timestamps_temp

        # === PASS 2: Virtual Timer Insertion ===
        section_rules =[]
        for s in self.sections_config:
            if s.get("enabled", True):
                try: 
                    fp = s.get("file_pattern", ".*") or ".*"
                    end_pat = s["end"]
                    is_vsync_end = False
                    if end_pat == VSYNC_TAG: 
                        end_pat = VSYNC_REGEX
                        is_vsync_end = True
                        
                    end_re = re.compile(end_pat, re.I) if end_pat else None
                    try: dur_ms = float(s.get("duration_ms", 0) or 0)
                    except: dur_ms = 0.0
                    
                    section_rules.append({
                        "start": re.compile(s["start"], re.I),
                        "start_wait": s.get("start_wait", False),
                        "end": end_re,
                        "end_str": end_pat,
                        "end_wait": s.get("end_wait", False),
                        "duration_ms": dur_ms,
                        "name": s["name"],
                        "file_pat_re": re.compile(fp, re.I),
                        "is_vsync_end": is_vsync_end
                    })
                except: pass

        try:
            re_vsync = re.compile(VSYNC_REGEX, re.I)
        except:
            re_vsync = re.compile(r"V_START", re.I)

        lines_final =[]
        src_map_final =[]

        active_states_sim = {fn: None for fn in src_file_names}
        pending_states_sim = {fn: None for fn in src_file_names}

        for i, line in enumerate(lines_v):
            ts = timestamps_v[i]
            line_src = src_map_v[i]
            is_virtual_line = (line_src == VIRTUAL_SRC_NAME)
            is_vsync_line = (re_vsync.search(line) is not None) and ("[VIRTUAL TIMER]" not in line)

            if ts is not None:
                expired =[]
                for fn in src_file_names:
                    s_info = active_states_sim[fn]
                    if s_info and s_info["rule"]["duration_ms"] > 0 and s_info["start_ts"] is not None and not s_info.get("timer_expired"):
                        expire_ts = s_info["start_ts"] + s_info["rule"]["duration_ms"] / 1000.0
                        if ts >= expire_ts - 0.000001:
                            expired.append((expire_ts, fn, s_info))
                
                expired.sort(key=lambda x: x[0])
                for exp_ts, fn_name, s_info in expired:
                    rule = s_info["rule"]
                    dur_ms = rule['duration_ms']
                    v_line = f"{format_sec(exp_ts)} --- [VIRTUAL TIMER] Wait Time {dur_ms}ms End ---"
                    lines_final.append(v_line)
                    src_map_final.append(VIRTUAL_SRC_NAME)
                    s_info["timer_expired"] = True

                    if rule["end_str"] == "":
                        if rule["end_wait"]:
                            s_info["end_pending"] = True
                        else:
                            active_states_sim[fn_name] = None

            lines_final.append(line)
            src_map_final.append(line_src)

            for fn in src_file_names:
                if active_states_sim[fn] and active_states_sim[fn].get("end_pending") and is_vsync_line:
                    active_states_sim[fn] = None

                if pending_states_sim[fn] and is_vsync_line:
                    active_states_sim[fn] = {
                        "rule": pending_states_sim[fn]["rule"],
                        "start_ts": ts,
                        "end_pending": False,
                        "timer_expired": False
                    }
                    pending_states_sim[fn] = None

                if fn == line_src:
                    for rule in section_rules:
                        if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                            if rule["start_wait"]:
                                pending_states_sim[fn] = {"rule": rule}
                            else:
                                active_states_sim[fn] = {
                                    "rule": rule,
                                    "start_ts": ts,
                                    "end_pending": False,
                                    "timer_expired": False
                                }
                                pending_states_sim[fn] = None
                                
                                is_end_match = False
                                if rule["end_str"] != "":
                                    is_end_match = rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"])
                                    
                                if rule["duration_ms"] > 0:
                                    is_end_match = False
                                    
                                if is_end_match:
                                    if rule["end_wait"]:
                                        active_states_sim[fn]["end_pending"] = True
                                    else:
                                        active_states_sim[fn] = None
                            break 

                if active_states_sim[fn] and not active_states_sim[fn].get("end_pending"):
                    rule = active_states_sim[fn]["rule"]
                    state_info = active_states_sim[fn]
                    
                    is_time_expired = state_info.get("timer_expired", False)

                    condition_met = False
                    if rule["end_str"] != "":
                        is_end_match = False
                        if rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"]):
                            is_end_match = True
                        
                        if rule["duration_ms"] > 0 and not is_time_expired:
                            is_end_match = False
                            
                        condition_met = is_end_match
                    else:
                        if rule["duration_ms"] > 0 and is_time_expired and not state_info.get("timer_expired_handled"):
                            condition_met = True
                            state_info["timer_expired_handled"] = True

                    if condition_met:
                        if rule["end_wait"]:
                            active_states_sim[fn]["end_pending"] = True
                        else:
                            active_states_sim[fn] = None

        remaining_expired =[]
        for fn in src_file_names:
            s_info = active_states_sim[fn]
            if s_info and s_info["rule"]["duration_ms"] > 0 and s_info["start_ts"] is not None and not s_info.get("timer_expired"):
                expire_ts = s_info["start_ts"] + s_info["rule"]["duration_ms"] / 1000.0
                remaining_expired.append((expire_ts, fn, s_info["rule"]))
                active_states_sim[fn] = None
        
        remaining_expired.sort(key=lambda x: x[0])
        for exp_ts, fn_name, rule in remaining_expired:
            dur_ms = rule['duration_ms']
            v_line = f"{format_sec(exp_ts)} --- [VIRTUAL TIMER] Wait Time {dur_ms}ms End ---"
            lines_final.append(v_line)
            src_map_final.append(VIRTUAL_SRC_NAME)

        return "\n".join(lines_final), src_map_final

    # --- Filter & Display ---
    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text=f"フィルタ: {'ON' if self.use_keyword_filter else 'OFF'}", bg="#bbdefb" if self.use_keyword_filter else "SystemButtonFace")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def toggle_vsync_display(self):
        self.show_vsync_lines = not self.show_vsync_lines
        self.btn_vsync_toggle.config(text=f"V周期表示: {'ON' if self.show_vsync_lines else 'OFF'}")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def apply_display_update(self, tab: LogTab):
        data = tab.original_content
        if self.replace_patterns_config: data = self._apply_replacements(data)
        lines = data.splitlines()
        
        line_attrs =[{"color": "#ffffff", "comment": "", "priority": 0} for _ in range(len(lines))]
        
        srcs = tab.line_source_map if tab.line_source_map else (tab.source_file_names * len(lines))
        if len(srcs) < len(lines): srcs.extend([""] * (len(lines) - len(srcs))) 

        section_rules =[]
        for s in self.sections_config:
            if s.get("enabled", True):
                try: 
                    fp = s.get("file_pattern", ".*") or ".*"
                    end_pat = s["end"]
                    is_vsync_end = False
                    if end_pat == VSYNC_TAG: 
                        end_pat = VSYNC_REGEX
                        is_vsync_end = True
                        
                    end_re = re.compile(end_pat, re.I) if end_pat else None
                    
                    try: dur_ms = float(s.get("duration_ms", 0) or 0)
                    except: dur_ms = 0.0
                    
                    section_rules.append({
                        "start": re.compile(s["start"], re.I),
                        "start_wait": s.get("start_wait", False),
                        "end": end_re,
                        "end_str": end_pat,
                        "end_wait": s.get("end_wait", False),
                        "duration_ms": dur_ms,
                        "name": s["name"],
                        "color": s["color"],
                        "file_pat_re": re.compile(fp, re.I),
                        "is_vsync_end": is_vsync_end
                    })
                except Exception as e: 
                    print(f"Regex error in section setup: {e}")

        ts_pat = self.vsync_config.get("time_pattern", r"^\[?\s*(\d+(?:\.\d+)?)\]?")
        try:
            re_ts = re.compile(ts_pat)
        except:
            re_ts = re.compile(r"^\[?\s*(\d+(?:\.\d+)?)\]?")
            
        timestamps =[]
        for line in lines:
            m = re_ts.search(line)
            if m:
                timestamps.append(self._parse_time_seconds(m.group(1)))
            else:
                timestamps.append(None)

        active_states = {fn: None for fn in tab.source_file_names}
        pending_states = {fn: None for fn in tab.source_file_names}
        status_buffers = {fn:[] for fn in tab.source_file_names}
        
        try:
            re_vsync = re.compile(VSYNC_REGEX, re.I)
        except:
            re_vsync = re.compile(r"V_START", re.I)

        for i, line in enumerate(lines):
            line_src = srcs[i]
            is_virtual_line = (line_src == VIRTUAL_SRC_NAME)
            is_vsync_line = (re_vsync.search(line) is not None) and ("[VIRTUAL TIMER]" not in line)

            for fn in tab.source_file_names:
                rule_to_display = None
                display_text = ""
                ended_this_line = False
                ended_rule = None
                
                def _end_active_state(fn_name, end_i):
                    ret_str = ""
                    s_info = active_states[fn_name]
                    if s_info and "start_idx" in s_info:
                        idx = s_info["start_idx"]
                        ts_start = s_info.get("start_ts")
                        ts_end = timestamps[end_i]
                        
                        if ts_start is not None and ts_end is not None:
                            diff_ms = (ts_end - ts_start) * 1000.0
                            t_str = f"[{diff_ms:.1f}ms]"
                            
                            if idx < len(status_buffers[fn_name]):
                                old_txt, col = status_buffers[fn_name][idx]
                                status_buffers[fn_name][idx] = (f"{old_txt}{t_str}", col)
                            else:
                                ret_str = t_str
                    
                    active_states[fn_name] = None
                    return ret_str

                if active_states[fn] and active_states[fn].get("end_pending") and is_vsync_line:
                    ended_rule = active_states[fn]["rule"]
                    t_str = _end_active_state(fn, i)
                    ended_this_line = True
                    display_text = f"{ended_rule['name']} (終了){t_str}"

                if pending_states[fn] and is_vsync_line:
                    if active_states[fn]:
                        ended_rule = active_states[fn]["rule"]
                        t_str = _end_active_state(fn, i)
                        ended_this_line = True
                        display_text = f"{ended_rule['name']} (終了){t_str}"
                    
                    active_states[fn] = {
                        "rule": pending_states[fn]["rule"],
                        "start_idx": i,
                        "start_ts": timestamps[i],
                        "end_pending": False,
                        "timer_expired_handled": False
                    }
                    pending_states[fn] = None
                    rule_to_display = active_states[fn]["rule"]
                    display_text = f"{rule_to_display['name']} (開始)"

                if fn == line_src:
                    for rule in section_rules:
                        if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                            if rule["start_wait"]:
                                pending_states[fn] = {"rule": rule}
                            else:
                                if active_states[fn]:
                                    ended_rule = active_states[fn]["rule"]
                                    t_str = _end_active_state(fn, i)
                                    if t_str: display_text += t_str
                                    ended_this_line = True
                                    
                                active_states[fn] = {
                                    "rule": rule,
                                    "start_idx": i,
                                    "start_ts": timestamps[i],
                                    "end_pending": False,
                                    "timer_expired_handled": False
                                }
                                pending_states[fn] = None
                                rule_to_display = rule
                                display_text = f"{rule['name']} (開始)"
                                
                                is_end_match = False
                                if rule["end_str"] != "":
                                    is_end_match = rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"])
                                    
                                if rule["duration_ms"] > 0:
                                    is_end_match = False
                                    
                                if is_end_match:
                                    if rule["end_wait"]:
                                        active_states[fn]["end_pending"] = True
                                    else:
                                        display_text = f"{rule['name']} (開始/終了)[0.0ms]"
                                        active_states[fn] = None
                            break 

                if active_states[fn] and not active_states[fn].get("end_pending"):
                    rule = active_states[fn]["rule"]
                    state_info = active_states[fn]
                    
                    # --- 復活：時間経過計算ロジック ---
                    is_time_expired = False
                    if rule["duration_ms"] > 0 and timestamps[i] is not None and state_info.get("start_ts") is not None:
                        if i > state_info["start_idx"]:
                            elapsed_ms = (timestamps[i] - state_info["start_ts"]) * 1000.0
                            if elapsed_ms >= rule["duration_ms"] - 0.001:
                                is_time_expired = True

                    condition_met = False
                    if rule["end_str"] != "":
                        is_end_match = False
                        if rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"]):
                            is_end_match = True
                        
                        if rule["duration_ms"] > 0 and not is_time_expired:
                            is_end_match = False
                            
                        condition_met = is_end_match
                    else:
                        if rule["duration_ms"] > 0 and is_time_expired and not state_info.get("timer_expired_handled"):
                            condition_met = True
                            state_info["timer_expired_handled"] = True

                    if condition_met:
                        if rule["end_wait"]:
                            active_states[fn]["end_pending"] = True
                        else:
                            ended_rule = rule
                            t_str = _end_active_state(fn, i)
                            ended_this_line = True
                            
                            if rule_to_display == ended_rule:
                                display_text = f"{ended_rule['name']} (終了){t_str}"
                            else:
                                rule_to_display = ended_rule
                                display_text = f"{ended_rule['name']} (終了){t_str}"

                if rule_to_display is None:
                    if active_states[fn]:
                        rule_to_display = active_states[fn]["rule"]
                        display_text = rule_to_display['name']
                    elif ended_this_line:
                        rule_to_display = ended_rule
                        if not display_text:
                            display_text = f"{ended_rule['name']} (終了)"

                if rule_to_display: 
                    status_buffers[fn].append((display_text, rule_to_display["color"]))
                else: 
                    status_buffers[fn].append(("", "#ffffff"))

        kw_rules =[]
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append({
                        "file_pat_re": re.compile(itm.get("file_pattern", ".*") or ".*", re.I),
                        "regex": re.compile(itm["pattern"], re.I),
                        "comment": itm.get("comment", ""),
                        "color": itm.get("color", "#ffffff"),
                        "extra": int(itm.get("extra_lines", 0))
                    })
                except: pass
                
        has_timer_rule = any("VIRTUAL TIMER" in str(r.get("pattern", "")) for r in self.keywords_config)
        if not has_timer_rule:
            kw_rules.append({
                "file_pat_re": re.compile(".*"),
                "regex": re.compile(r"\[VIRTUAL TIMER\]", re.I),
                "comment": "タイマー満了",
                "color": "#ffe0b2",
                "extra": 0
            })

        for idx in range(len(lines)):
            if "<<<[V-SYNC 起点]" in lines[idx]:
                if line_attrs[idx]["priority"] < 30:
                    line_attrs[idx]["color"] = "#ffb6c1" 
                    line_attrs[idx]["comment"] = f"{line_attrs[idx]['comment']}[基準位置]".strip()
                    line_attrs[idx]["priority"] = 30

            line_src = srcs[idx]
            for rule in kw_rules:
                if rule["file_pat_re"].search(line_src):
                    if rule["regex"].search(lines[idx]):
                        for j in range(idx, min(idx + rule["extra"] + 1, len(lines))):
                            if line_attrs[j]["priority"] < 20:
                                line_attrs[j]["color"] = rule["color"]
                                base_cmt = line_attrs[j]["comment"]
                                new_cmt = rule["comment"]
                                line_attrs[j]["comment"] = f"{base_cmt} {new_cmt}".strip()
                                line_attrs[j]["priority"] = 20
                        break

        visible_mapping = {}
        is_visible = [True] * len(lines)
        display_line_count = 1
        
        for i in range(len(lines)):
            if not self.show_vsync_lines and VSYNC_MARKER in lines[i]:
                is_visible[i] = False
            else:
                attr = line_attrs[i]
                if self.use_keyword_filter:
                    if "[VIRTUAL TIMER]" in lines[i] or "<<<[V-SYNC 起点]" in lines[i]:
                        is_visible[i] = True 
                    elif attr["priority"] == 0: 
                        is_visible[i] = False
                    elif re_vsync.search(lines[i]):
                        is_in_section = any(status_buffers[fn][i][0] != "" for fn in tab.source_file_names)
                        if not is_in_section:
                            is_visible[i] = False
                            
            if is_visible[i]:
                visible_mapping[i] = display_line_count
                display_line_count += 1
        
        if self.use_keyword_filter:
            visible_indices =[idx for idx, vis in enumerate(is_visible) if vis]
            v_ptr = 0
            while v_ptr < len(visible_indices):
                idx = visible_indices[v_ptr]
                is_curr_vsync = (VSYNC_MARKER in lines[idx]) or (re_vsync.search(lines[idx]) is not None)
                
                if is_curr_vsync:
                    block_indices =[idx]
                    next_ptr = v_ptr + 1
                    
                    while next_ptr < len(visible_indices):
                        next_idx = visible_indices[next_ptr]
                        is_next_vsync = (VSYNC_MARKER in lines[next_idx]) or (re_vsync.search(lines[next_idx]) is not None)
                        
                        if is_next_vsync:
                            block_indices.append(next_idx)
                            next_ptr += 1
                        else:
                            break
                    
                    if len(block_indices) >= 3:
                        for hide_idx in block_indices[1:-1]:
                            is_visible[hide_idx] = False

                    v_ptr = next_ptr
                else:
                    v_ptr += 1
            
            visible_mapping = {}
            display_line_count = 1
            for i in range(len(lines)):
                if is_visible[i]:
                    visible_mapping[i] = display_line_count
                    display_line_count += 1

        flines, fcmts, ftimediffs = [],[], []
        main_tags =[]
        final_st_lines = {fn:[] for fn in tab.source_file_names}
        final_st_tags = {fn:[] for fn in tab.source_file_names}
        
        line_count = 0
        base_ts = None
        
        for i in range(len(lines)):
            if not is_visible[i]:
                continue
            
            if base_ts is None and timestamps[i] is not None:
                base_ts = timestamps[i]
            
            line_count += 1
            flines.append(lines[i])
            s_name = f"[{srcs[i]}] " if (tab.is_merged and srcs[i]) else ""
            
            if timestamps[i] is not None and base_ts is not None:
                ftimediffs.append(f"{(timestamps[i] - base_ts):.6f}")
            else:
                ftimediffs.append("")
            
            base_cmt = f"{s_name}{line_attrs[i]['comment']}"
            fcmts.append(base_cmt)
            
            if line_attrs[i]["color"] != "#ffffff":
                main_tags.append((line_count, line_attrs[i]["color"]))
            
            for fn in tab.source_file_names:
                txt, col = status_buffers[fn][i]
                final_st_lines[fn].append(txt)
                if col != "#ffffff":
                    final_st_tags[fn].append((line_count, col))
                    
        tab.text.delete("1.0", tk.END)
        tab.text.insert("1.0", "\n".join(flines))
        
        tab.timediff_text.delete("1.0", tk.END)
        tab.timediff_text.insert("1.0", "\n".join(ftimediffs))
        
        tab.comment_text.delete("1.0", tk.END)
        tab.comment_text.insert("1.0", "\n".join(fcmts))
        
        for fn in tab.source_file_names:
            w = tab.status_texts[fn]
            w.delete("1.0", tk.END)
            w.insert("1.0", "\n".join(final_st_lines[fn]))
            
            for tag in w.tag_names():
                 if tag.startswith("st_"): w.tag_delete(tag)
            for ln, col in final_st_tags[fn]:
                tn = f"st_{col.replace('#','')}"
                w.tag_configure(tn, background=col)
                w.tag_add(tn, f"{ln}.0", f"{ln}.end")

        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for ln, col in main_tags:
            tn = f"kw_{col.replace('#','')}"
            tab.text.tag_configure(tn, background=col)
            tab.text.tag_add(tn, f"{ln}.0", f"{ln}.end")
            
        tab.linenumbers.redraw()
        tab.update_cursor_line()

    def _apply_replacements(self, content: str) -> str:
        for itm in self.replace_patterns_config:
            if itm.get("enabled", True):
                try: content = re.sub(itm["search"], lambda m: f"{m.group(0)}({m.expand(itm['replace'])})", content, flags=re.I)
                except: pass
        return content

    # --- Search Logic ---
    def open_find_dialog(self):
        if self.find_window_ref and self.find_window_ref.winfo_exists():
            self.find_window_ref.lift()
            return

        self.find_window_ref = tk.Toplevel(self.root)
        self.find_window_ref.title("検索")
        self.find_window_ref.geometry("350x120")
        self.find_window_ref.transient(self.root) 

        tk.Label(self.find_window_ref, text="検索文字列:").pack(pady=(10, 0))
        
        entry = tk.Entry(self.find_window_ref, width=40)
        entry.pack(pady=5, padx=10)
        entry.insert(0, self.last_search_keyword)
        entry.select_range(0, tk.END)
        entry.focus_set()

        btn_frame = tk.Frame(self.find_window_ref)
        btn_frame.pack(pady=10)

        def do_find_next():
            self.last_search_keyword = entry.get()
            self.find_next()

        def do_find_prev():
            self.last_search_keyword = entry.get()
            self.find_prev()

        tk.Button(btn_frame, text="次を検索 (Enter)", command=do_find_next).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="前を検索 (Shift+Ent)", command=do_find_prev).pack(side=tk.LEFT, padx=5)

        entry.bind('<Return>', lambda e: do_find_next())
        entry.bind('<Shift-Return>', lambda e: do_find_prev())

    def find_next(self): self._execute_search(backwards=False)
    def find_prev(self): self._execute_search(backwards=True)

    def _execute_search(self, backwards=False):
        tab = self.get_current_tab()
        if not tab or not self.last_search_keyword: return

        start_pos = "insert" if backwards else "insert + 1 chars"
        pos = tab.text.search(self.last_search_keyword, start_pos, stopindex=None, nocase=True, backwards=backwards)

        if pos:
            end_pos = f"{pos}+{len(self.last_search_keyword)}c"
            tab.text.tag_remove("found", "1.0", tk.END)
            tab.text.tag_add("found", pos, end_pos)
            tab.text.tag_raise("found") 
            
            tab.text.mark_set("insert", pos)
            tab.text.see(pos)
            tab.update_cursor_line()
            self.status_var.set(f"検索: '{self.last_search_keyword}' が見つかりました。")
        else:
            self.status_var.set(f"検索: '{self.last_search_keyword}' は見つかりませんでした。")

    # --- UI Helpers ---
    def create_preset_menu(self, parent_btn, entry_widget):
        menu = tk.Menu(self.root, tearoff=0)
        presets =[("整数",r"\d+"),("16進",r"0x[0-9A-Fa-f]+"),("IP",r"\d{1,3}(\.\d{1,3}){3}"),("[]内",r"\[.*?\]"),("Key=Val",r"\w+=\S+")]
        for l, r in presets: menu.add_command(label=l, command=lambda t=r: entry_widget.insert(tk.INSERT, t))
        menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())

    def edit_keywords_dialog(self): 
        self._edit_dlg("フィルタ設定の編集 ※正規表現にマッチした行を抽出し、指定の色とコメントを付与します。", "keywords",["file_pattern", "pattern","color","comment","extra_lines"])
        
    def edit_replace_patterns_dialog(self): 
        self._edit_dlg("説明パターンの編集 ※正規表現にマッチした文字列の直後に、 (説明)を付与します。", "replace_patterns",["search","replace"])
        
    def edit_sections_dialog(self): 
        self._edit_dlg("区間設定の編集 ※ファイル毎に開始～終了パターンを定義して色分けします。", "sections",["file_pattern", "name", "start", "start_wait", "end", "end_wait", "duration_ms", "color"])

    def _edit_dlg(self, title, key, fields):
        ref_attr = f"{key}_dlg_ref"
        ref = getattr(self, ref_attr, None)
        if ref and ref.winfo_exists():
            ref.lift()
            return
        
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.geometry("1150x550")
        setattr(self, ref_attr, dlg)
        
        fr = tk.Frame(dlg)
        fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1)
        l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        hdr = tk.Frame(l_fr)
        hdr.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(hdr, width=135).pack(side=tk.LEFT)
        
        if "file_pattern" in fields: tk.Label(hdr, text="対象ファイル(正規表現)", width=20, anchor="w").pack(side=tk.LEFT)
        if "pattern" in fields: tk.Label(hdr, text="正規表現", width=25, anchor="w").pack(side=tk.LEFT)
        if "search" in fields: tk.Label(hdr, text="検索文字列", width=25, anchor="w").pack(side=tk.LEFT)
        if "name" in fields: tk.Label(hdr, text="区間名", width=15, anchor="w").pack(side=tk.LEFT)
        
        if "start" in fields: tk.Label(hdr, text="開始パターン", width=15, anchor="w").pack(side=tk.LEFT)
        if "start_wait" in fields: tk.Label(hdr, text="+V待", width=4).pack(side=tk.LEFT)
        if "end" in fields: tk.Label(hdr, text="終了パターン", width=15, anchor="w").pack(side=tk.LEFT)
        if "end_wait" in fields: tk.Label(hdr, text="+V待", width=4).pack(side=tk.LEFT)
        if "duration_ms" in fields: tk.Label(hdr, text="持続(ms)", width=8).pack(side=tk.LEFT, padx=2)
        
        if "color" in fields: tk.Label(hdr, text="色", width=10).pack(side=tk.LEFT, padx=15)
        if "replace" in fields: tk.Label(hdr, text="置換/説明", width=30).pack(side=tk.LEFT, padx=5)
        if "comment" in fields: tk.Label(hdr, text="コメント", width=20).pack(side=tk.LEFT, padx=5)
        if "extra_lines" in fields: tk.Label(hdr, text="+行", width=5).pack(side=tk.LEFT)

        cv = tk.Canvas(l_fr)
        sc = tk.Scrollbar(l_fr, command=cv.yview)
        sf = tk.Frame(cv)
        cv.configure(yscrollcommand=sc.set)
        sc.pack(side=tk.RIGHT, fill=tk.Y)
        cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))

        entries =[]
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, item in enumerate(entries):
                r = tk.Frame(sf)
                r.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(r, variable=item["enabled"]).pack(side=tk.LEFT)
                tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)).pack(side=tk.LEFT)
                tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)).pack(side=tk.LEFT)
                tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                
                if "file_pattern" in fields:
                    tk.Entry(r, textvariable=item["file_pattern"], width=20).pack(side=tk.LEFT, padx=2)
                if "pattern" in fields:
                    tk.Entry(r, textvariable=item["pattern"], width=25).pack(side=tk.LEFT, padx=2)
                if "search" in fields:
                    tk.Entry(r, textvariable=item["search"], width=25).pack(side=tk.LEFT, padx=2)
                if "name" in fields:
                    tk.Entry(r, textvariable=item["name"], width=15).pack(side=tk.LEFT, padx=2)
                    
                if "start" in fields:
                    tk.Entry(r, textvariable=item["start"], width=15).pack(side=tk.LEFT, padx=2)
                if "start_wait" in fields:
                    tk.Checkbutton(r, variable=item["start_wait"]).pack(side=tk.LEFT, padx=2)
                    
                if "end" in fields:
                    tk.Entry(r, textvariable=item["end"], width=15).pack(side=tk.LEFT, padx=2)
                    if key == "sections":
                         tk.Button(r, text="V周期", width=5, command=lambda v=item["end"]: v.set(VSYNC_TAG), bg="#e1bee7").pack(side=tk.LEFT, padx=1)
                if "end_wait" in fields:
                    tk.Checkbutton(r, variable=item["end_wait"]).pack(side=tk.LEFT, padx=2)
                if "duration_ms" in fields:
                    tk.Entry(r, textvariable=item["duration_ms"], width=8).pack(side=tk.LEFT, padx=2)
                
                if "color" in fields:
                    tk.Entry(r, textvariable=item["color"], width=8).pack(side=tk.LEFT, padx=15)
                    tk.Button(r, text="色", command=lambda v=item["color"]: v.set(colorchooser.askcolor(v.get())[1] or v.get())).pack(side=tk.LEFT)
                
                if "replace" in fields:
                    tk.Entry(r, textvariable=item["replace"], width=30).pack(side=tk.LEFT, padx=5)
                if "comment" in fields:
                    tk.Entry(r, textvariable=item["comment"], width=20).pack(side=tk.LEFT, padx=5)
                if "extra_lines" in fields:
                    tk.Entry(r, textvariable=item["extra_lines"], width=4).pack(side=tk.LEFT, padx=5)

        def add(data=None):
            item = {"enabled": tk.BooleanVar(value=data.get("enabled", True) if data else True)}
            for f in fields:
                if f in["start_wait", "end_wait"]:
                    item[f] = tk.BooleanVar(value=data.get(f, False) if data else False)
                else:
                    def_val = "0" if f == "extra_lines" else (".*" if f == "file_pattern" else "")
                    val = data.get(f, def_val) if data and f in data else def_val
                    item[f] = tk.StringVar(value=str(val))
            entries.append(item)
            refresh()
            
        def delete(i): 
            del entries[i]
            refresh()
            
        def move(i, d): 
            if 0 <= i+d < len(entries): 
                entries[i], entries[i+d] = entries[i+d], entries[i]
                refresh()

        cfg = getattr(self, f"{key}_config")
        for c in cfg: add(c)
        if not entries: add()

        btn_fr = tk.Frame(fr, width=250)
        btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        tk.Button(btn_fr, text="行を追加", command=add, width=20, height=2).pack(pady=5)
        
        info_text = ""
        if key == "sections":
            info_text = (
                "【区間設定の使い方】\n\n"
                "■開始パターン\n"
                " 区間の開始条件(正規表現)です。\n"
                " [+V待]で、合致後の次のV周期から\n"
                " 区間を開始します。\n\n"
                "■終了パターン\n"
                " 区間の終了条件(正規表現)です。\n"
                " [V周期]ボタンで<VSYNC>を入力可能です。\n"
                " 空欄の場合は持続(ms)の経過のみで\n"
                " 終了します。\n\n"
                "■終了の+V待\n"
                " 条件(パターンや時間)を満たした直後の\n"
                " V周期で区間を終了させます。\n\n"
                "■持続(ms)\n"
                " 指定時間が経過すると区間が\n"
                " 終了します。この時[VIRTUAL TIMER]\n"
                " のログが自動挿入されます。\n\n"
                " ※終了パターンと持続(ms)の両方を\n"
                " 指定した場合、持続(ms)が経過するまでは\n"
                " 終了パターンに合致しても無視されます。"
            )
        elif key == "keywords":
            info_text = (
                "【フィルタ設定の使い方】\n\n"
                "正規表現で検索し、マッチした行を\n"
                "抽出・色付け・コメント付与します。\n\n"
                "■対象ファイル\n"
                " 適用するファイル名(正規表現)です。\n"
                " (例: client.* , server.*)\n\n"
                "■+行\n"
                " マッチした行のさらに下何行分まで\n"
                " 同じ色を適用するかを指定します。\n"
                " スタックトレース等をまとめて\n"
                " 色付けしたい場合に便利です。"
            )
        elif key == "replace_patterns":
            info_text = (
                "【説明パターンの使い方】\n\n"
                "ログ内の難解な文字列を、読みやすい\n"
                "説明に置換(付記)します。\n\n"
                "■検索文字列\n"
                " 検索対象の正規表現を指定します。\n\n"
                "■置換/説明\n"
                " 置換後の文字列を指定します。\n"
                " マッチした文字列の直後に\n"
                " 検索文字列(置換/説明)\n"
                " の形式で表示されます。"
            )

        if info_text:
            info_lbl = tk.Label(btn_fr, text=info_text, justify=tk.LEFT, anchor="nw", bg="#ffffe0", relief=tk.SOLID, bd=1, padx=8, pady=8, font=("MS UI Gothic", 9))
            info_lbl.pack(fill=tk.BOTH, expand=True, pady=10)
        
        def save():
            new_cfg =[]
            for item in entries:
                valid = False
                for k in["pattern", "search", "start"]:
                    if k in fields and item[k].get(): valid = True
                if valid:
                    d = {f: item[f].get() for f in fields}
                    d["enabled"] = item["enabled"].get()
                    new_cfg.append(d)
            
            setattr(self, f"{key}_config", new_cfg)
            self.save_config_dialog_silent()
            dlg.destroy()
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.apply_display_update(w)
                except: pass

        tk.Button(btn_fr, text="OK", command=save, width=20, bg="#ddddff", height=2).pack(side=tk.BOTTOM, pady=5)

    # --- IO ---
    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if p: self.load_config(p)
        
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json")
        if p: 
            self.save_config_dialog_silent(p)
            messagebox.showinfo("完了", "設定を保存しました。")
        
    def load_config(self, p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
                self.keywords_config = d.get("keywords",[])
                self.sections_config = d.get("sections",[])
                self.replace_patterns_config = d.get("replace_patterns",[])
                self.vsync_config = d.get("vsync_auto_insert", self.vsync_config)
            t = self.get_current_tab()
            if t: self.apply_display_update(t)
        except: pass

    def export_to_excel(self):
        tab = self.get_current_tab()
        if not tab: return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p: return
        try:
            l = tab.text.get("1.0", "end-1c").splitlines()
            c = tab.comment_text.get("1.0", "end-1c").splitlines()
            td = tab.timediff_text.get("1.0", "end-1c").splitlines()
            srcs = tab.line_source_map if tab.is_merged else tab.source_file_names * len(l)
            if len(srcs) < len(l): srcs.extend([""] * (len(l) - len(srcs))) 
            
            h =['<html><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:monospace;} th{background:#ddd;border:1px solid #999;} td{border:1px solid #ccc;padding:2px 4px;white-space:pre-wrap;}</style></head><body><table>']
            header_row = '<thead><tr><th>Line</th><th>Time Diff</th><th>Log Content</th><th>Comment</th>'
            for fn in tab.source_file_names: header_row += f'<th>{html.escape(fn)}の区間</th>'
            h.append(header_row + '</tr></thead><tbody>')
            
            for i, line in enumerate(l):
                bg_color = "transparent"
                tags = tab.text.tag_names(f"{i+1}.0")
                for tag in tags:
                    if tag.startswith("kw_"):
                        bg_color = f"#{tag[3:]}"
                        break
                        
                cm = c[i] if i < len(c) else ""
                diff_str = td[i] if i < len(td) else ""
                row_html = f'<tr style="background:{bg_color}"><td>{i+1}</td><td>{html.escape(diff_str)}</td><td>{html.escape(line)}</td><td>{html.escape(cm)}</td>'
                
                for fn in tab.source_file_names:
                    txt = tab.status_texts[fn].get(f"{i+1}.0", f"{i+1}.end")
                    st_bg = "transparent"
                    st_tags = tab.status_texts[fn].tag_names(f"{i+1}.0")
                    for tag in st_tags:
                        if tag.startswith("st_"):
                            st_bg = f"#{tag[3:]}"
                            break
                    row_html += f'<td style="background:{st_bg}">{html.escape(txt)}</td>'
                h.append(row_html + '</tr>')
                
            with open(p, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</tbody></table></body></html>")
            messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()