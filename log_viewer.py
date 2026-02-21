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
    "keywords": [
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 2},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0},
        {"pattern": r"--- \[VIRTUAL V-SYNC\] ---", "color": "#e1bee7", "comment": "仮想V同期タイミング", "enabled": True, "extra_lines": 0}
    ],
    "sections": [
        {"name": "初期化(Server)", "start": "SRV_INIT_START", "end": "SRV_INIT_DONE", "color": "#e1f5fe", "file_pattern": "server.*", "enabled": True},
        {"name": "初期化(Client)", "start": "CLI_BOOT",       "end": "CLI_READY",     "color": "#e0f2f1", "file_pattern": "client.*", "enabled": True},
        {"name": "通信処理",       "start": "CONNECT",        "end": "DISCONNECT",    "color": "#fff3e0", "file_pattern": ".*",       "enabled": True}
    ],
    "replace_patterns": [],
    "analysis_rules": [
        {"name": "Input->V", "cmd_pattern": "Command|Input", "vsync_pattern": "V_START|V-Sync|VIRTUAL V-SYNC", "enabled": True}
    ],
    "analysis_time_pattern": r"^\[?(\d+(?:\.\d+)?)\]?",
    "vsync_auto_insert": {
        "enabled": True,
        "event_pattern": r"V_START|V-Sync",
        "time_pattern": r"^\[?(\d+(?:\.\d+)?)\]?",
        "mode": "auto", 
        "manual_ms": 16.666
    }
}

class LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        for ev in ['<KeyRelease>', '<MouseWheel>', '<Configure>', '<<Modified>>', '<Button-1>']:
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
        
        self.source_file_names = source_files_list if source_files_list else ([os.path.basename(path)] if path else [])
        self.line_source_map: List[str] = []
        self.status_texts: Dict[str, tk.Text] = {}
        self.analysis_comments: Dict[int, str] = {}
        self._create_layout()

    def _create_layout(self):
        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=600)
        header_text = "[Merged View]" if self.is_merged else (self.source_file_names[0] if self.source_file_names else "Log Content")
        tk.Label(left_frame, text=header_text, bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL); self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.text.tag_config("found", background="#0000cd", foreground="white")
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0'); self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); self.hsb_log.config(command=self.text.xview)
        cmt_frame = tk.Frame(self.paned_window); self.paned_window.add(cmt_frame, minsize=50, stretch="always", width=250)
        self.hsb_cmt = tk.Scrollbar(cmt_frame, orient=tk.HORIZONTAL); self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(cmt_frame, text="Comment / Tags / Analysis", bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        self.comment_text = tk.Text(cmt_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa", yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); self.hsb_cmt.config(command=self.comment_text.xview)
        for fname in self.source_file_names:
            st_frame = tk.Frame(self.paned_window); self.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
            tk.Label(st_frame, text=f"{fname}の区間", bg="#dcedc8", relief=tk.RAISED, font=("MS UI Gothic", 9, "bold")).pack(side=tk.TOP, fill=tk.X)
            hsb = tk.Scrollbar(st_frame, orient=tk.HORIZONTAL); hsb.pack(side=tk.BOTTOM, fill=tk.X)
            st_text = tk.Text(st_frame, wrap=tk.NONE, bg="#f8f8f8", fg="#333333", yscrollcommand=self.vsb.set, xscrollcommand=hsb.set)
            st_text.tag_configure("sel", background="#cce8ff", foreground="black")
            st_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); hsb.config(command=st_text.xview); self.status_texts[fname] = st_text
        all_texts = [self.text, self.comment_text] + list(self.status_texts.values())
        def sync_yview(*args):
            for t in all_texts: t.yview(*args)
            self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)
        def on_mw(e):
            d = int(-1*(e.delta/120)) if e.delta else 0
            for t in all_texts: t.yview_scroll(d, "units")
            self.linenumbers.redraw()
            return "break"
        for t in all_texts: t.bind('<MouseWheel>', on_mw)

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root; self.root.title("Log Viewer"); self.root.geometry("1450x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.sections_config = [x.copy() for x in DEFAULT_CONFIG["sections"]]
        self.replace_patterns_config = []; self.analysis_rules_config = [x.copy() for x in DEFAULT_CONFIG["analysis_rules"]]
        self.analysis_time_pattern = DEFAULT_CONFIG["analysis_time_pattern"]; self.vsync_config = DEFAULT_CONFIG["vsync_auto_insert"].copy()
        self.use_keyword_filter = False; self.show_vsync_lines = True 
        self.keywords_dlg_ref = None; self.replace_dlg_ref = None; self.sections_dlg_ref = None; self.find_window_ref = None; self.last_search_keyword = ""; self.analysis_dlg_ref = None; self.vsync_settings_dlg_ref = None
        self._build_ui()
        self.root.bind('<F5>', lambda e: self.reload_file()); self.root.bind('<Control-o>', lambda e: self.open_file()); self.root.bind('<Control-w>', lambda e: self.close_tab()); self.root.bind('<Control-f>', lambda e: self.open_find_dialog()); self.root.bind('<F3>', lambda e: self.find_next()); self.root.bind('<Shift-F3>', lambda e: self.find_prev())
        if os.path.exists(self.config_path): self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="再読み込み", command=self.reload_file, accelerator="F5")
        fmenu.add_separator(); fmenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        fmenu.add_separator(); fmenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        fmenu.add_separator(); fmenu.add_command(label="終了", command=self.root.quit); menubar.add_cascade(label="ファイル", menu=fmenu)
        emenu = tk.Menu(menubar, tearoff=0); emenu.add_command(label="検索...", command=self.open_find_dialog, accelerator="Ctrl+F"); emenu.add_command(label="次を検索", command=self.find_next, accelerator="F3"); emenu.add_command(label="前を検索", command=self.find_prev, accelerator="Shift+F3"); menubar.add_cascade(label="編集", menu=emenu)
        cmenu = tk.Menu(menubar, tearoff=0); cmenu.add_command(label="設定読み込み...", command=self.load_config_dialog); cmenu.add_command(label="設定保存...", command=self.save_config_dialog); cmenu.add_separator(); cmenu.add_command(label="フィルタ設定の編集 (行単位)...", command=self.edit_keywords_dialog); cmenu.add_command(label="区間設定の編集 (開始-終了)...", command=self.edit_sections_dialog); cmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog); cmenu.add_separator(); cmenu.add_command(label="イベント適用解析設定の編集...", command=self.edit_analysis_rules_dialog); cmenu.add_command(label="V周期(仮想)挿入の設定...", command=self.open_vsync_settings_dialog); menubar.add_cascade(label="設定", menu=cmenu)
        self.root.config(menu=menubar)
        toolbar = tk.Frame(self.root); toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=12, command=self.toggle_filter); self.btn_kw_filter.pack(side=tk.LEFT)
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e3f2fd").pack(side=tk.LEFT, padx=10)
        self.btn_vsync_toggle = tk.Button(toolbar, text="V周期表示: ON", width=12, command=self.toggle_vsync_display); self.btn_vsync_toggle.pack(side=tk.LEFT, padx=5)
        self.notebook = ttk.Notebook(self.root); self.notebook.pack(fill=tk.BOTH, expand=True)
        self.status_var = tk.StringVar(value="準備完了"); tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)
        if HAS_DND:
            self.root.drop_target_register(DND_FILES); self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    # --- File/Merge ---
    def open_file(self):
        for p in filedialog.askopenfilenames(): self._open_file_path(p)

    def close_tab(self):
        t = self.get_current_tab(); 
        if t: self.notebook.forget(t)

    def reload_file(self):
        tab = self.get_current_tab(); 
        if not tab: return
        if tab.is_merged:
            messagebox.showinfo("再読み込み", "マージ結果タブは再読み込みできません。")
            return
        if not tab.file_path or not os.path.exists(tab.file_path): return
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(tab.file_path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        if self.vsync_config.get("enabled", True):
            fname = os.path.basename(tab.file_path); new_content, new_src_map = self._process_vsync_insertion(content, [fname]*len(content.splitlines()), [fname]); tab.original_content = new_content; tab.line_source_map = new_src_map
        else: tab.original_content = content; tab.line_source_map = [] 
        self.run_analysis_for_tab(tab)

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        fname = os.path.basename(path)
        if self.vsync_config.get("enabled", True):
            new_content, new_src_map = self._process_vsync_insertion(content, [fname]*len(content.splitlines()), [fname]); tab = LogTab(self.notebook, self, path, new_content, source_files_list=[fname], is_merged=True); tab.line_source_map = new_src_map
            self.notebook.add(tab, text=fname); self.notebook.select(tab); self.run_analysis_for_tab(tab)
        else:
            tab = LogTab(self.notebook, self, path, content, source_files_list=[fname]); self.notebook.add(tab, text=fname); self.notebook.select(tab); self.run_analysis_for_tab(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
        # ファイルパスが存在し、[Merged]でないタブを選択（自動V周期挿入済みタブも対象にする）
        target_tabs = [t for t in tabs if t.file_path and t.file_path != "Merged"]
        if len(target_tabs) < 2:
            messagebox.showinfo("マージ", "マージするには2つ以上のログファイルを開いてください。")
            return
        ts_len = simpledialog.askinteger("マージ", "時刻ソート用の先頭文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append((re.compile(itm["pattern"], re.I), int(itm.get("extra_lines", 0))))
                except: pass
        all_blocks = []
        unique_srcs = []
        for t in target_tabs:
            fn = os.path.basename(t.file_path)
            if fn not in unique_srcs: unique_srcs.append(fn)
            # 自動挿入されたV周期を含まない「生」のコンテンツを使ってマージを行う（混乱防止）
            # もし挿入後の状態でマージしたい場合は t.original_content.splitlines() にする
            raw_lines = t.original_content.splitlines()
            if not raw_lines: continue
            effective_ts = []; last_valid_ts = ""
            for line in raw_lines:
                ts_part = line[:ts_len]
                if ts_part.strip() and len(line) > 0 and not line[0].isspace(): last_valid_ts = ts_part
                effective_ts.append(last_valid_ts)
            first_ts = next((x for x in effective_ts if x), "0"*ts_len); effective_ts = [x if x else first_ts for x in effective_ts]
            i = 0
            while i < len(raw_lines):
                line = raw_lines[i]; extra = 0
                for pat, ex in kw_rules:
                    if pat.search(line): extra = ex; break
                bl = raw_lines[i : i + extra + 1]; skey = effective_ts[i]
                all_blocks.append((skey, bl, fn)); i += extra + 1
        all_blocks.sort(key=lambda x: x[0])
        final_lines, final_src = [], []
        for _, bl, fn in all_blocks: final_lines.extend(bl); final_src.extend([fn] * len(bl))
        m_tab = LogTab(self.notebook, self, "Merged", "\n".join(final_lines), source_files_list=unique_srcs, is_merged=True)
        m_tab.line_source_map = final_src
        self.notebook.add(m_tab, text="[マージ結果]"); self.notebook.select(m_tab); self.run_analysis_for_tab(m_tab)

    # --- Analysis Features (Auto) ---
    def edit_analysis_rules_dialog(self):
        if self.analysis_dlg_ref and self.analysis_dlg_ref.winfo_exists(): self.analysis_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); dlg.title("イベント適用解析設定の編集"); dlg.geometry("900x500"); self.analysis_dlg_ref = dlg
        fr = tk.Frame(dlg); fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(fr, text="「(先) 指示イベント」と「(後) 適用イベント」のペアを登録します。", anchor="w").pack(fill=tk.X)
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1); l_fr.pack(fill=tk.BOTH, expand=True, pady=5)
        hdr = tk.Frame(l_fr); hdr.pack(fill=tk.X, padx=5, pady=2); tk.Frame(hdr, width=120).pack(side=tk.LEFT) 
        tk.Label(hdr, text="解析名", width=20, anchor="w").pack(side=tk.LEFT, padx=5); tk.Label(hdr, text="(先) 指示イベント(Trigger)", width=30, anchor="w", fg="#0000aa").pack(side=tk.LEFT, padx=5); tk.Label(hdr, text="(後) 適用イベント(Apply)", width=30, anchor="w", fg="#aa0000").pack(side=tk.LEFT, padx=5)
        cv = tk.Canvas(l_fr); sc = tk.Scrollbar(l_fr, command=cv.yview); sf = tk.Frame(cv); cv.configure(yscrollcommand=sc.set); sc.pack(side=tk.RIGHT, fill=tk.Y); cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); win = cv.create_window((0,0), window=sf, anchor="nw"); sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all"))); cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, item in enumerate(entries):
                r = tk.Frame(sf); r.pack(fill=tk.X, pady=2, padx=5); tk.Checkbutton(r, variable=item["enabled"]).pack(side=tk.LEFT); tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)).pack(side=tk.LEFT); tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)).pack(side=tk.LEFT); tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                tk.Entry(r, textvariable=item["name"], width=20).pack(side=tk.LEFT, padx=5); tk.Entry(r, textvariable=item["cmd_pattern"], width=30).pack(side=tk.LEFT, padx=5); tk.Entry(r, textvariable=item["vsync_pattern"], width=30).pack(side=tk.LEFT, padx=5)
        def add(data=None):
            item = {"enabled": tk.BooleanVar(value=data.get("enabled", True) if data else True),"name": tk.StringVar(value=data.get("name", "") if data else ""),"cmd_pattern": tk.StringVar(value=data.get("cmd_pattern", "") if data else ""),"vsync_pattern": tk.StringVar(value=data.get("vsync_pattern", "") if data else "")}; entries.append(item); refresh()
        def delete(i): del entries[i]; refresh()
        def move(i, d): 
            if 0 <= i+d < len(entries): entries[i], entries[i+d] = entries[i+d], entries[i]; refresh()
        if not self.analysis_rules_config: add()
        else:
            for r in self.analysis_rules_config: add(r)
        btn_bar = tk.Frame(fr); btn_bar.pack(fill=tk.X, pady=5); tk.Button(btn_bar, text="行を追加", command=add).pack(side=tk.LEFT)
        btm_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1); btm_fr.pack(fill=tk.X, pady=10, ipady=5); tk.Label(btm_fr, text="【共通設定】 時刻抽出パターン (行頭):").pack(side=tk.LEFT, padx=5); e_ts = tk.Entry(btm_fr, width=40); e_ts.pack(side=tk.LEFT, padx=5); e_ts.insert(0, self.analysis_time_pattern or r"^\[?(\d+(?:\.\d+)?)\]?") 
        def save_and_run():
            self.analysis_rules_config = [{"enabled": i["enabled"].get(),"name": i["name"].get(),"cmd_pattern": i["cmd_pattern"].get(),"vsync_pattern": i["vsync_pattern"].get()} for i in entries]; self.analysis_time_pattern = e_ts.get()
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.run_analysis_for_tab(w)
                except: pass
            dlg.destroy()
        tk.Button(dlg, text="OK", command=save_and_run, bg="#ddddff", width=15, height=2).pack(side=tk.BOTTOM, pady=10)

    def run_analysis_for_tab(self, tab: LogTab):
        tab.analysis_comments.clear()
        rules = [r for r in self.analysis_rules_config if r["enabled"] and r["cmd_pattern"] and r["vsync_pattern"]]
        if not rules: self.apply_display_update(tab); return
        try:
            re_ts = re.compile(self.analysis_time_pattern); compiled = [{"name": r["name"],"cmd_re": re.compile(r["cmd_pattern"], re.I),"vsync_re": re.compile(r["vsync_pattern"], re.I)} for r in rules]
        except: self.apply_display_update(tab); return
        lines = tab.original_content.splitlines(); events = []
        for i, line in enumerate(lines):
            ts = 0.0; m = re_ts.search(line)
            if m: ts = self._parse_time_seconds(m.group(1)) or 0.0
            for rule_idx, rule in enumerate(compiled):
                if rule["cmd_re"].search(line): events.append({'line': i, 'ts': ts, 'type': 0, 'rule': rule_idx})
                if rule["vsync_re"].search(line): events.append({'line': i, 'ts': ts, 'type': 1, 'rule': rule_idx})
        count = 0
        for rule_idx, rule in enumerate(compiled):
            rule_events = [e for e in events if e['rule'] == rule_idx]; pending = []
            for ev in rule_events:
                if ev['type'] == 0: pending.append(ev)
                elif ev['type'] == 1 and pending:
                    for trig in pending:
                        diff = (ev['ts'] - trig['ts']) * 1000.0 if (ev['ts'] > 0 and trig['ts'] > 0) else 0.0; prefix = f"[{rule['name']}]" if rule['name'] else ""; ts_str = f" (+{diff:.1f}ms)" if diff >= 0 else ""
                        tab.analysis_comments[trig['line']] = (tab.analysis_comments.get(trig['line'], "") + f" {prefix}--> 指示: L{ev['line']+1}{ts_str}").strip()
                        tab.analysis_comments[ev['line']] = (tab.analysis_comments.get(ev['line'], "") + f" {prefix}<-- 適用: L{trig['line']+1}").strip(); count += 1
                    pending = []
        self.apply_display_update(tab); self.status_var.set(f"解析完了(自動): {count} 件")

    # --- Virtual V-Sync (Settings) ---
    def open_vsync_settings_dialog(self):
        if self.vsync_settings_dlg_ref and self.vsync_settings_dlg_ref.winfo_exists(): self.vsync_settings_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); dlg.title("V周期(仮想)挿入の設定"); dlg.geometry("450x350"); self.vsync_settings_dlg_ref = dlg
        tk.Label(dlg, text="V周期(仮想)挿入の条件を設定します。", anchor="w", font=("", 9, "bold")).pack(pady=10, padx=10)
        tk.Label(dlg, text="基準イベント(正規表現):").pack(anchor="w", padx=10); e_pattern = tk.Entry(dlg, width=50); e_pattern.pack(padx=10, pady=2); e_pattern.insert(0, self.vsync_config.get("event_pattern", r"V_START|V-Sync"))
        tk.Label(dlg, text="時刻抽出(正規表現):").pack(anchor="w", padx=10); e_ts_pat = tk.Entry(dlg, width=50); e_ts_pat.pack(padx=10, pady=2); e_ts_pat.insert(0, self.vsync_config.get("time_pattern", r"^\[?(\d+(?:\.\d+)?)\]?"))
        frame_mode = tk.LabelFrame(dlg, text="間隔設定"); frame_mode.pack(fill=tk.X, padx=10, pady=10); mode_var = tk.StringVar(value=self.vsync_config.get("mode", "auto"))
        tk.Radiobutton(frame_mode, text="自動計算", variable=mode_var, value="auto").pack(anchor="w", padx=5); f_man = tk.Frame(frame_mode); f_man.pack(anchor="w", padx=5); tk.Radiobutton(f_man, text="手動指定 (ms):", variable=mode_var, value="manual").pack(side=tk.LEFT); e_ms = tk.Entry(f_man, width=10); e_ms.pack(side=tk.LEFT, padx=5); e_ms.insert(0, str(self.vsync_config.get("manual_ms", 16.666)))
        def save_conf():
            self.vsync_config = {"enabled": True,"event_pattern": e_pattern.get(),"time_pattern": e_ts_pat.get(),"mode": mode_var.get(),"manual_ms": float(e_ms.get() or 16.666)}; self.save_config_dialog_silent(); dlg.destroy()
        def apply_now():
            t = self.get_current_tab(); 
            if t:
                new_c, new_m = self._process_vsync_insertion(t.original_content, t.line_source_map if t.is_merged else [t.source_file_names[0]]*len(t.original_content.splitlines()), t.source_file_names)
                nt = LogTab(self.notebook, self, "V-Sync View", new_content=new_c, source_files_list=t.source_file_names, is_merged=True); nt.line_source_map = new_m; self.notebook.add(nt, text="[V-Sync Inserted]"); self.notebook.select(nt); self.run_analysis_for_tab(nt); dlg.destroy()
        tk.Button(dlg, text="保存", command=save_conf, bg="#ddddff", width=12).pack(side=tk.RIGHT, padx=10); tk.Button(dlg, text="現在適用", command=apply_now, width=12).pack(side=tk.RIGHT)

    def save_config_dialog_silent(self):
        data = {"keywords": self.keywords_config, "sections": self.sections_config, "replace_patterns": self.replace_patterns_config, "analysis_rules": self.analysis_rules_config,"analysis_time_pattern": self.analysis_time_pattern,"vsync_auto_insert": self.vsync_config}
        try:
            with open(self.config_path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, ensure_ascii=False)
        except: pass

    def _parse_time_seconds(self, ts_str: str) -> Optional[float]:
        try:
            if ":" in ts_str: parts = ts_str.split(":"); return int(parts[0])*3600 + int(parts[1])*60 + float(parts[2])
            return float(ts_str)
        except: return None

    def _process_vsync_insertion(self, content: str, src_map: List[str], src_file_names: List[str]) -> Tuple[str, List[str]]:
        lines = content.splitlines(); pat = self.vsync_config.get("event_pattern", r"V_START|V-Sync"); ts_pat = self.vsync_config.get("time_pattern", r"^\[?(\d+(?:\.\d+)?)\]?"); mode = self.vsync_config.get("mode", "auto"); re_event = re.compile(pat, re.I); re_ts = re.compile(ts_pat)
        events = []; is_colon = False
        for line in lines:
            if re_event.search(line):
                m = re_ts.search(line)
                if m:
                    ts_s = m.group(1); is_colon = ":" in ts_s; t = self._parse_time_seconds(ts_s)
                    if t is not None:
                        events.append(t)
                        if mode == "auto" and len(events) >= 2: break 
        if not events: return content, src_map
        start_time = events[0]; interval = (self.vsync_config.get("manual_ms", 16.666)/1000.0) if mode == "manual" else (events[1]-events[0] if len(events)>=2 else 0.016666)
        if interval <= 0: interval = 0.016666
        new_lines, new_src, next_v = [], [], start_time + interval; cur_src_map = src_map if len(src_map) == len(lines) else src_map + [""]*(len(lines)-len(src_map))
        def fmt(s):
            if is_colon: h=int(s//3600); m=int((s%3600)//60); sec=s%60; return f"{h:02d}:{m:02d}:{sec:06.3f}"
            return f"[{s:.6f}]"
        for i, line in enumerate(lines):
            m = re_ts.search(line); l_ts = self._parse_time_seconds(m.group(1)) if m else None
            if l_ts is not None and l_ts > start_time:
                cnt = 0
                while next_v < l_ts and cnt < 100: new_lines.append(f"{fmt(next_v)} {VSYNC_MARKER}"); new_src.append(VIRTUAL_SRC_NAME); next_v += interval; cnt += 1
                if cnt >= 100: next_v = l_ts + interval
            new_lines.append(line); new_src.append(cur_src_map[i])
        return "\n".join(new_lines), new_src

    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter; self.btn_kw_filter.config(text=f"フィルタ: {'ON' if self.use_keyword_filter else 'OFF'}", bg="#bbdefb" if self.use_keyword_filter else "SystemButtonFace"); t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def toggle_vsync_display(self):
        self.show_vsync_lines = not self.show_vsync_lines; self.btn_vsync_toggle.config(text=f"V周期表示: {'ON' if self.show_vsync_lines else 'OFF'}"); t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def apply_display_update(self, tab: LogTab):
        data = tab.original_content; 
        if self.replace_patterns_config: data = self._apply_replacements(data)
        lines = data.splitlines(); attrs = [{"color": "#ffffff", "comment": "", "priority": 0} for _ in range(len(lines))]
        srcs = tab.line_source_map if tab.line_source_map else (tab.source_file_names * len(lines))
        if len(srcs) < len(lines): srcs.extend([""] * (len(lines) - len(srcs))) 
        sec_rules = []
        for s in self.sections_config:
            if s.get("enabled", True):
                try: 
                    fp = s.get("file_pattern", ".*") or ".*"; end_p = s["end"]
                    if end_p == VSYNC_TAG: end_p = VSYNC_REGEX
                    sec_rules.append({"start": re.compile(s["start"], re.I),"end": re.compile(end_p, re.I),"name": s["name"],"color": s["color"],"file_pat_re": re.compile(fp, re.I)})
                except: pass
        active = {fn: None for fn in tab.source_file_names}; st_bufs = {fn: [] for fn in tab.source_file_names}
        for i, line in enumerate(lines):
            l_src = srcs[i]; is_v = (l_src == VIRTUAL_SRC_NAME)
            for fn in tab.source_file_names:
                r_disp, d_txt = None, ""
                if fn == l_src or (is_v and active[fn]):
                    if active[fn]:
                        if active[fn]["end"].search(line): r_disp = active[fn]; d_txt = f"{r_disp['name']} (終了)"; active[fn] = None 
                        else: r_disp = active[fn]; d_txt = r_disp['name']
                    if not r_disp and not active[fn] and fn == l_src:
                        for rule in sec_rules:
                            if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                                r_disp = rule; d_txt = f"{rule['name']} (開始)"; active[fn] = rule
                                if rule["end"].search(line): d_txt = f"{rule['name']} (開始/終了)"; active[fn] = None
                                break
                elif active[fn]: r_disp = active[fn]; d_txt = r_disp['name']
                st_bufs[fn].append((d_txt, r_disp["color"] if r_disp else "#ffffff"))
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append({"regex": re.compile(itm["pattern"], re.I),"comment": itm.get("comment", ""),"color": itm.get("color", "#ffffff"),"extra": int(itm.get("extra_lines", 0))})
                except: pass
        for idx in range(len(lines)):
            for rule in kw_rules:
                if rule["regex"].search(lines[idx]):
                    for j in range(idx, min(idx + rule["extra"] + 1, len(lines))):
                        if attrs[j]["priority"] < 20: attrs[j]["color"] = rule["color"]; attrs[j]["comment"] = f"{attrs[j]['comment']} {rule['comment']}".strip(); attrs[j]["priority"] = 20
                    break
        flines, fcmts, main_tags, f_st_lines, f_st_tags, l_cnt = [], [], [], {fn: [] for fn in tab.source_file_names}, {fn: [] for fn in tab.source_file_names}, 0
        for i in range(len(lines)):
            if not self.show_vsync_lines and VSYNC_MARKER in lines[i]: continue
            if self.use_keyword_filter and attrs[i]["priority"] == 0: continue
            l_cnt += 1; flines.append(lines[i]); s_n = f"[{srcs[i]}] " if (tab.is_merged and srcs[i]) else ""
            b_c = f"{s_n}{attrs[i]['comment']}"; a_c = tab.analysis_comments.get(i, ""); fcmts.append((b_c + " " + a_c).strip())
            if attrs[i]["color"] != "#ffffff": main_tags.append((l_cnt, attrs[i]["color"]))
            for fn in tab.source_file_names:
                txt, col = st_bufs[fn][i]; f_st_lines[fn].append(txt)
                if col != "#ffffff": f_st_tags[fn].append((l_cnt, col))
        tab.text.delete("1.0", tk.END); tab.text.insert("1.0", "\n".join(flines))
        tab.comment_text.delete("1.0", tk.END); tab.comment_text.insert("1.0", "\n".join(fcmts))
        for fn in tab.source_file_names:
            w = tab.status_texts[fn]; w.delete("1.0", tk.END); w.insert("1.0", "\n".join(f_st_lines[fn]))
            for tag in w.tag_names():
                 if tag.startswith("st_"): w.tag_delete(tag)
            for ln, col in f_st_tags[fn]:
                tn = f"st_{col.replace('#','')}"; w.tag_configure(tn, background=col); w.tag_add(tn, f"{ln}.0", f"{ln}.end")
        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for ln, col in main_tags:
            tn = f"kw_{col.replace('#','')}"; tab.text.tag_configure(tn, background=col); tab.text.tag_add(tn, f"{ln}.0", f"{ln}.end")
        tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        for itm in self.replace_patterns_config:
            if itm.get("enabled", True):
                try: content = re.sub(itm["search"], lambda m: f"{m.group(0)}({m.expand(itm['replace'])})", content, flags=re.I)
                except: pass
        return content

    def open_find_dialog(self):
        if self.find_window_ref and self.find_window_ref.winfo_exists(): self.find_window_ref.lift(); return
        self.find_window_ref = tk.Toplevel(self.root); self.find_window_ref.title("検索"); self.find_window_ref.geometry("350x120"); self.find_window_ref.transient(self.root) 
        tk.Label(self.find_window_ref, text="検索文字列:").pack(pady=(10, 0))
        entry = tk.Entry(self.find_window_ref, width=40); entry.pack(pady=5, padx=10); entry.insert(0, self.last_search_keyword); entry.select_range(0, tk.END); entry.focus_set()
        btn_frame = tk.Frame(self.find_window_ref); btn_frame.pack(pady=10)
        def do_find_next(): self.last_search_keyword = entry.get(); self.find_next()
        def do_find_prev(): self.last_search_keyword = entry.get(); self.find_prev()
        tk.Button(btn_frame, text="次を検索", command=do_find_next).pack(side=tk.LEFT, padx=5); tk.Button(btn_frame, text="前を検索", command=do_find_prev).pack(side=tk.LEFT, padx=5)
        entry.bind('<Return>', lambda e: do_find_next()); entry.bind('<Shift-Return>', lambda e: do_find_prev())

    def find_next(self): self._execute_search(backwards=False)
    def find_prev(self): self._execute_search(backwards=True)
    def _execute_search(self, backwards=False):
        tab = self.get_current_tab()
        if not tab or not self.last_search_keyword: return
        start_pos = "insert" if backwards else "insert + 1 chars"
        pos = tab.text.search(self.last_search_keyword, start_pos, stopindex=None, nocase=True, backwards=backwards)
        if pos:
            tab.text.tag_remove("found", "1.0", tk.END); tab.text.tag_add("found", pos, f"{pos}+{len(self.last_search_keyword)}c"); tab.text.mark_set("insert", pos); tab.text.see(pos)
        else: self.status_var.set(f"検索: '{self.last_search_keyword}' は見つかりませんでした。")

    def edit_keywords_dialog(self): self._edit_dlg("フィルタ設定", "keywords", ["pattern","color","comment","extra_lines"])
    def edit_replace_patterns_dialog(self): self._edit_dlg("説明パターン", "replace_patterns", ["search","replace"])
    def edit_sections_dialog(self): self._edit_dlg("区間設定", "sections", ["file_pattern", "name", "start", "end", "color"])
    def _edit_dlg(self, title, key, fields):
        ref_attr = f"{key}_dlg_ref"; ref = getattr(self, ref_attr, None)
        if ref and ref.winfo_exists(): ref.lift(); return
        dlg = tk.Toplevel(self.root); dlg.title(title); dlg.geometry("1150x500"); setattr(self, ref_attr, dlg)
        fr = tk.Frame(dlg); fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10); l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1); l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hdr = tk.Frame(l_fr); hdr.pack(fill=tk.X, padx=5, pady=2); tk.Frame(hdr, width=135).pack(side=tk.LEFT)
        cv = tk.Canvas(l_fr); sc = tk.Scrollbar(l_fr, command=cv.yview); sf = tk.Frame(cv); cv.configure(yscrollcommand=sc.set); sc.pack(side=tk.RIGHT, fill=tk.Y); cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all"))); cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, itm in enumerate(entries):
                r = tk.Frame(sf); r.pack(fill=tk.X, pady=2, padx=5); tk.Checkbutton(r, variable=itm["enabled"]).pack(side=tk.LEFT); tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)).pack(side=tk.LEFT); tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)).pack(side=tk.LEFT); tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                for f in fields:
                    if f == "color":
                        tk.Entry(r, textvariable=itm[f], width=8).pack(side=tk.LEFT, padx=15); tk.Button(r, text="色", command=lambda v=itm[f]: v.set(colorchooser.askcolor(v.get())[1] or v.get())).pack(side=tk.LEFT)
                    elif f == "end" and key == "sections":
                        tk.Entry(r, textvariable=itm[f], width=20).pack(side=tk.LEFT, padx=2); tk.Button(r, text="V周期", width=5, command=lambda v=itm[f]: v.set(VSYNC_TAG), bg="#e1bee7").pack(side=tk.LEFT, padx=1)
                    else: tk.Entry(r, textvariable=itm[f], width=25 if f in ["pattern","search","start","end"] else 15 if f=="name" else 4).pack(side=tk.LEFT, padx=2)
        def add(data=None):
            item = {"enabled": tk.BooleanVar(value=data.get("enabled", True) if data else True)}
            for f in fields: item[f] = tk.StringVar(value=str(data.get(f, "0" if f=="extra_lines" else "")) if data else ("0" if f=="extra_lines" else ""))
            entries.append(item); refresh()
        def delete(i): del entries[i]; refresh()
        def move(i, d): 
            if 0 <= i+d < len(entries): entries[i], entries[i+d] = entries[i+d], entries[i]; refresh()
        cfg = getattr(self, f"{key}_config")
        for c in cfg: add(c)
        if not entries: add()
        btn_fr = tk.Frame(fr); btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10); tk.Button(btn_fr, text="行を追加", command=add, width=10).pack(pady=5)
        def save():
            new_cfg = []
            for item in entries: d = {f: item[f].get() for f in fields}; d["enabled"] = item["enabled"].get(); new_cfg.append(d)
            setattr(self, f"{key}_config", new_cfg); dlg.destroy()
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.apply_display_update(w)
                except: pass
        tk.Button(btn_fr, text="OK", command=save, width=10, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")]); 
        if p: self.load_config(p)
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json"); 
        if p: self.save_config_dialog_silent()
    def load_config(self, p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f); self.keywords_config = d.get("keywords", []); self.sections_config = d.get("sections", []); self.replace_patterns_config = d.get("replace_patterns", []); self.analysis_rules_config = d.get("analysis_rules", []); self.analysis_time_pattern = d.get("analysis_time_pattern", self.analysis_time_pattern); self.vsync_config = d.get("vsync_auto_insert", self.vsync_config)
            t = self.get_current_tab(); 
            if t: self.run_analysis_for_tab(t)
        except: pass

    def export_to_excel(self):
        tab = self.get_current_tab(); 
        if not tab: return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p: return
        try:
            l = tab.text.get("1.0", "end-1c").splitlines(); c = tab.comment_text.get("1.0", "end-1c").splitlines(); srcs = tab.line_source_map if tab.is_merged else tab.source_file_names * len(l)
            if len(srcs) < len(l): srcs.extend([""] * (len(l) - len(srcs))) 
            sec_rules = []
            for s in self.sections_config:
                if s.get("enabled", True):
                    fp = s.get("file_pattern", ".*") or ".*"; end_p = s["end"]
                    if end_p == VSYNC_TAG: end_p = VSYNC_REGEX
                    sec_rules.append({"start": re.compile(s["start"], re.I),"end": re.compile(end_p, re.I),"name": s["name"],"color": s["color"],"file_pat_re": re.compile(fp, re.I)})
            active = {fn: None for fn in tab.source_file_names}; status_buffers = {fn: [] for fn in tab.source_file_names}
            for i, line in enumerate(l):
                l_src = srcs[i]; is_v = (l_src == VIRTUAL_SRC_NAME)
                for fn in tab.source_file_names:
                    r_disp, d_txt = None, ""
                    if fn == l_src or (is_v and active[fn]):
                        if active[fn]:
                            if active[fn]["end"].search(line): r_disp = active[fn]; d_txt = f"{r_disp['name']} (終了)"; active[fn] = None 
                            else: r_disp = active[fn]; d_txt = r_disp['name']
                        if not r_disp and not active[fn] and fn == l_src:
                            for rule in sec_rules:
                                if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                                    r_disp = rule; d_txt = f"{rule['name']} (開始)"; active[fn] = rule
                                    if rule["end"].search(line): d_txt = f"{rule['name']} (開始/終了)"; active[fn] = None
                                    break
                    elif active[fn]: r_disp = active[fn]; d_txt = r_disp['name']
                    status_buffers[fn].append((d_txt, r_disp["color"] if r_disp else "#ffffff"))
            colors = ["#ffffff"] * len(l); k_rules = []
            for it in self.keywords_config:
                if it["enabled"]: k_rules.append((re.compile(it["pattern"], re.I), it["color"], int(it["extra_lines"])))
            for i in range(len(l)):
                for pat, col, ext in k_rules:
                    if pat.search(l[i]):
                        for j in range(i, min(i+ext+1, len(l))): colors[j] = col
                        break
            h = ['<html><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:monospace;} th{background:#ddd;border:1px solid #999;} td{border:1px solid #ccc;padding:2px 4px;white-space:pre-wrap;}</style></head><body><table>']
            header_row = '<thead><tr><th>Line</th><th>Log Content</th><th>Comment</th>'
            for fn in tab.source_file_names: header_row += f'<th>{html.escape(fn)}の区間</th>'
            h.append(header_row + '</tr></thead><tbody>')
            for i, line in enumerate(l):
                if not self.show_vsync_lines and VSYNC_MARKER in line: continue
                cm = c[i] if i < len(c) else ""
                row_html = f'<tr style="background:{colors[i]}"><td>{i+1}</td><td>{html.escape(line)}</td><td>{html.escape(cm)}</td>'
                for fn in tab.source_file_names:
                    txt, col = status_buffers[fn][i]; row_html += f'<td style="background:{col if col != "#ffffff" else "transparent"}">{html.escape(txt)}</td>'
                h.append(row_html + '</tr>')
            with open(p, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</tbody></table></body></html>"); messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS(); app = LogViewerApp(root); root.mainloop()