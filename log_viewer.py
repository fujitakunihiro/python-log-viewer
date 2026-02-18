from __future__ import annotations

import json
import os
import sys
import re
import html
import tkinter as tk
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

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "keywords": [
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 2},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0}
    ],
    "sections": [
        {"name": "初期化(Server)", "start": "SRV_INIT_START", "end": "SRV_INIT_DONE", "color": "#e1f5fe", "file_pattern": "server.*", "enabled": True},
        {"name": "初期化(Client)", "start": "CLI_BOOT",       "end": "CLI_READY",     "color": "#e0f2f1", "file_pattern": "client.*", "enabled": True},
        {"name": "通信処理",       "start": "CONNECT",        "end": "DISCONNECT",    "color": "#fff3e0", "file_pattern": ".*",       "enabled": True}
    ],
    "replace_patterns": []
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

        self._create_layout()

    def _create_layout(self):
        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # 1. Log Content (Main)
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=600)
        
        header_text = "Log Content"
        if not self.is_merged and self.source_file_names:
             header_text = self.source_file_names[0]
        elif self.is_merged:
             header_text = "[Merged View]"

        tk.Label(left_frame, text=header_text, bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        
        # 修正: 選択時の色設定 (文字を黒、背景を薄い水色に)
        self.text.tag_configure("sel", background="#cce8ff", foreground="black")
        
        self.text.tag_config("found", background="#0000cd", foreground="white")

        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)

        # 2. Comment Column
        cmt_frame = tk.Frame(self.paned_window)
        self.paned_window.add(cmt_frame, minsize=50, stretch="always", width=250)
        self.hsb_cmt = tk.Scrollbar(cmt_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(cmt_frame, text="Comment / Tags", bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        
        self.comment_text = tk.Text(cmt_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa",
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        # 修正: 選択時の色設定
        self.comment_text.tag_configure("sel", background="#cce8ff", foreground="black")
        
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)

        # 3+. Status Columns
        for fname in self.source_file_names:
            st_frame = tk.Frame(self.paned_window)
            self.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
            
            # 修正: ヘッダー名を「○○の区間」に変更
            header_label = f"{fname}の区間"
            tk.Label(st_frame, text=header_label, bg="#dcedc8", relief=tk.RAISED, font=("MS UI Gothic", 9, "bold")).pack(side=tk.TOP, fill=tk.X)

            hsb = tk.Scrollbar(st_frame, orient=tk.HORIZONTAL)
            hsb.pack(side=tk.BOTTOM, fill=tk.X)
            st_text = tk.Text(st_frame, wrap=tk.NONE, bg="#f8f8f8", fg="#333333",
                              yscrollcommand=self.vsb.set, xscrollcommand=hsb.set)
            
            # 修正: 選択時の色設定
            st_text.tag_configure("sel", background="#cce8ff", foreground="black")
            
            st_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hsb.config(command=st_text.xview)
            self.status_texts[fname] = st_text

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
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1450x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.sections_config = [x.copy() for x in DEFAULT_CONFIG["sections"]]
        self.replace_patterns_config = []
        
        self.use_keyword_filter = False
        self.keywords_dlg_ref = None
        self.replace_dlg_ref = None
        self.sections_dlg_ref = None
        self.find_window_ref = None
        self.last_search_keyword = ""

        self._build_ui()
        
        self.root.bind('<F5>', lambda e: self.reload_file())
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-w>', lambda e: self.close_tab())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())
        self.root.bind('<Shift-F3>', lambda e: self.find_prev())
        
        if os.path.exists(self.config_path): self.load_config(self.config_path)

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
        menubar.add_cascade(label="設定", menu=cmenu)
        self.root.config(menu=menubar)

        toolbar = tk.Frame(self.root); toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=15, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e3f2fd").pack(side=tk.LEFT, padx=10)

        self.notebook = ttk.Notebook(self.root); self.notebook.pack(fill=tk.BOTH, expand=True)
        self.status_var = tk.StringVar(value="準備完了"); tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

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
        if tab.is_merged:
            messagebox.showinfo("再読み込み", "マージ結果タブは再読み込みできません。\n元ファイルを再読み込みしてから再度マージしてください。")
            return
        if not tab.file_path or not os.path.exists(tab.file_path): return
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(tab.file_path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        tab.original_content = content
        self.apply_display_update(tab)
        self.status_var.set(f"再読み込み完了: {os.path.basename(tab.file_path)}")

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        
        fname = os.path.basename(path)
        tab = LogTab(self.notebook, self, path, content, source_files_list=[fname])
        self.notebook.add(tab, text=fname)
        self.notebook.select(tab); self.apply_display_update(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
        target_tabs = [t for t in tabs if not t.is_merged]
        if len(target_tabs) < 2: return
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
            
            lines = t.original_content.splitlines()
            if not lines: continue
            effective_ts = []
            last_valid_ts = ""
            for line in lines:
                ts_part = line[:ts_len]
                if ts_part.strip() and len(line) > 0 and not line[0].isspace(): last_valid_ts = ts_part
                effective_ts.append(last_valid_ts)
            first_valid_ts = next((t for t in effective_ts if t), "0"*ts_len)
            effective_ts = [t if t else first_valid_ts for t in effective_ts]

            i = 0
            while i < len(lines):
                line = lines[i]
                if not line.strip(): i += 1; continue
                extra = 0
                for pat, ex in kw_rules:
                    if pat.search(line): extra = ex; break
                block_lines = lines[i : i + extra + 1]
                sort_key = effective_ts[i]
                
                all_blocks.append((sort_key, block_lines, fn))
                i += extra + 1

        all_blocks.sort(key=lambda x: x[0])
        final_lines, final_src = [], []
        for _, bl, fn in all_blocks:
            final_lines.extend(bl); final_src.extend([fn] * len(bl))
            
        m_tab = LogTab(self.notebook, self, "Merged", "\n".join(final_lines), source_files_list=unique_srcs, is_merged=True)
        m_tab.line_source_map = final_src
        self.notebook.add(m_tab, text="[マージ結果]"); self.notebook.select(m_tab); self.apply_display_update(m_tab)

    # --- Filter & Display ---
    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text=f"フィルタ: {'ON' if self.use_keyword_filter else 'OFF'}", bg="#bbdefb" if self.use_keyword_filter else "SystemButtonFace")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def apply_display_update(self, tab: LogTab):
        data = tab.original_content
        if self.replace_patterns_config: data = self._apply_replacements(data)
        lines = data.splitlines()
        
        line_attrs = [{"color": "#ffffff", "comment": "", "priority": 0} for _ in range(len(lines))]
        
        srcs = tab.line_source_map if tab.is_merged else tab.source_file_names * len(lines)
        if len(srcs) < len(lines): srcs.extend([""] * (len(lines) - len(srcs))) 

        section_rules = []
        for s in self.sections_config:
            if s.get("enabled", True):
                try: 
                    fp = s.get("file_pattern", ".*") or ".*"
                    section_rules.append({
                        "start": re.compile(s["start"], re.I),
                        "end": re.compile(s["end"], re.I),
                        "name": s["name"],
                        "color": s["color"],
                        "file_pat_re": re.compile(fp, re.I)
                    })
                except: pass

        # 状態追跡用
        active_states = {fn: None for fn in tab.source_file_names}
        status_buffers = {fn: [] for fn in tab.source_file_names}
        
        for i, line in enumerate(lines):
            line_src = srcs[i]

            for fn in tab.source_file_names:
                rule_to_display = None
                display_text = ""
                
                # --- ロジックA: 状態遷移判定 ---
                if fn == line_src:
                    if active_states[fn]:
                        if active_states[fn]["end"].search(line):
                            rule_to_display = active_states[fn]
                            display_text = f"{rule_to_display['name']} (終了)"
                            active_states[fn] = None 
                        else:
                            rule_to_display = active_states[fn]
                            display_text = rule_to_display['name']

                    if not rule_to_display and not active_states[fn]:
                        for rule in section_rules:
                            if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                                rule_to_display = rule
                                display_text = f"{rule['name']} (開始)"
                                active_states[fn] = rule
                                
                                if rule["end"].search(line):
                                    display_text = f"{rule['name']} (開始/終了)"
                                    active_states[fn] = None
                                break
                
                # --- ロジックB: 表示維持 ---
                elif active_states[fn]:
                    rule_to_display = active_states[fn]
                    display_text = rule_to_display['name']

                if rule_to_display:
                    status_buffers[fn].append((display_text, rule_to_display["color"]))
                else:
                    status_buffers[fn].append(("", "#ffffff"))

        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append({
                        "regex": re.compile(itm["pattern"], re.I),
                        "comment": itm.get("comment", ""),
                        "color": itm.get("color", "#ffffff"),
                        "extra": int(itm.get("extra_lines", 0))
                    })
                except: pass

        for idx in range(len(lines)):
            for rule in kw_rules:
                if rule["regex"].search(lines[idx]):
                    limit = min(idx + rule["extra"] + 1, len(lines))
                    for j in range(idx, limit):
                        if line_attrs[j]["priority"] < 20:
                            line_attrs[j]["color"] = rule["color"]
                            base_cmt = line_attrs[j]["comment"]
                            new_cmt = rule["comment"]
                            line_attrs[j]["comment"] = f"{base_cmt} {new_cmt}".strip()
                            line_attrs[j]["priority"] = 20
                    break

        flines, fcmts = [], []
        main_tags = []
        final_st_lines = {fn: [] for fn in tab.source_file_names}
        final_st_tags = {fn: [] for fn in tab.source_file_names}
        
        line_count = 0
        for i in range(len(lines)):
            attr = line_attrs[i]
            if self.use_keyword_filter and attr["priority"] == 0: continue
            
            line_count += 1
            flines.append(lines[i])
            s_name = f"[{srcs[i]}] " if (tab.is_merged and srcs[i]) else ""
            fcmts.append(f"{s_name}{attr['comment']}")
            
            if attr["color"] != "#ffffff":
                main_tags.append((line_count, attr["color"]))
            
            for fn in tab.source_file_names:
                txt, col = status_buffers[fn][i]
                final_st_lines[fn].append(txt)
                if col != "#ffffff":
                    final_st_tags[fn].append((line_count, col))
        
        tab.text.delete("1.0", tk.END); tab.text.insert("1.0", "\n".join(flines))
        tab.comment_text.delete("1.0", tk.END); tab.comment_text.insert("1.0", "\n".join(fcmts))
        
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
            self.status_var.set(f"検索: '{self.last_search_keyword}' が見つかりました。")
        else:
            self.status_var.set(f"検索: '{self.last_search_keyword}' は見つかりませんでした。")

    # --- UI Helpers ---
    def create_preset_menu(self, parent_btn, entry_widget):
        menu = tk.Menu(self.root, tearoff=0)
        presets = [("整数",r"\d+"),("16進",r"0x[0-9A-Fa-f]+"),("IP",r"\d{1,3}(\.\d{1,3}){3}"),("[]内",r"\[.*?\]"),("Key=Val",r"\w+=\S+")]
        for l, r in presets: menu.add_command(label=l, command=lambda t=r: entry_widget.insert(tk.INSERT, t))
        menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())

    def edit_keywords_dialog(self): self._edit_dlg("フィルタ設定の編集 ※正規表現にマッチした行を抽出し、指定の色とコメントを付与します。", "keywords", ["pattern","color","comment","extra_lines"])
    def edit_replace_patterns_dialog(self): self._edit_dlg("説明パターンの編集 ※正規表現にマッチした文字列の直後に、 (説明)を付与します。", "replace_patterns", ["search","replace"])
    def edit_sections_dialog(self): self._edit_dlg("区間設定の編集 ※ファイル毎に開始～終了パターンを定義して色分けします。", "sections", ["file_pattern", "name", "start", "end", "color"])

    def _edit_dlg(self, title, key, fields):
        ref_attr = f"{key}_dlg_ref"
        ref = getattr(self, ref_attr, None)
        if ref and ref.winfo_exists(): ref.lift(); return
        
        dlg = tk.Toplevel(self.root); dlg.title(title)
        dlg.geometry("1150x500")
        setattr(self, ref_attr, dlg)
        
        fr = tk.Frame(dlg); fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1); l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        hdr = tk.Frame(l_fr); hdr.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(hdr, width=135).pack(side=tk.LEFT)
        
        if "file_pattern" in fields: tk.Label(hdr, text="対象ファイル(正規表現)", width=20, anchor="w").pack(side=tk.LEFT)
        if "pattern" in fields: tk.Label(hdr, text="正規表現", width=25, anchor="w").pack(side=tk.LEFT)
        if "search" in fields: tk.Label(hdr, text="検索文字列", width=25, anchor="w").pack(side=tk.LEFT)
        if "name" in fields: tk.Label(hdr, text="区間名", width=15, anchor="w").pack(side=tk.LEFT)
        if "start" in fields: tk.Label(hdr, text="開始パターン", width=15, anchor="w").pack(side=tk.LEFT)
        if "end" in fields: tk.Label(hdr, text="終了パターン", width=15, anchor="w").pack(side=tk.LEFT)
        
        if "color" in fields: tk.Label(hdr, text="色", width=10).pack(side=tk.LEFT, padx=15)
        if "replace" in fields: tk.Label(hdr, text="置換/説明", width=30).pack(side=tk.LEFT, padx=5)
        if "comment" in fields: tk.Label(hdr, text="コメント", width=20).pack(side=tk.LEFT, padx=5)
        if "extra_lines" in fields: tk.Label(hdr, text="+行", width=5).pack(side=tk.LEFT)

        cv = tk.Canvas(l_fr); sc = tk.Scrollbar(l_fr, command=cv.yview)
        sf = tk.Frame(cv); cv.configure(yscrollcommand=sc.set)
        sc.pack(side=tk.RIGHT, fill=tk.Y); cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))

        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, item in enumerate(entries):
                r = tk.Frame(sf); r.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(r, variable=item["enabled"]).pack(side=tk.LEFT)
                tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)).pack(side=tk.LEFT)
                tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)).pack(side=tk.LEFT)
                tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                
                if "file_pattern" in fields:
                    tk.Entry(r, textvariable=item["file_pattern"], width=20).pack(side=tk.LEFT, padx=2)

                if "pattern" in fields:
                    ep = tk.Entry(r, textvariable=item["pattern"], width=25); ep.pack(side=tk.LEFT, padx=2)
                    tk.Button(r, text="▼", width=2, command=lambda b=None, e=ep: self.create_preset_menu(b, e)).pack(side=tk.LEFT)
                if "search" in fields:
                    ep = tk.Entry(r, textvariable=item["search"], width=25); ep.pack(side=tk.LEFT, padx=2)
                    tk.Button(r, text="▼", width=2, command=lambda b=None, e=ep: self.create_preset_menu(b, e)).pack(side=tk.LEFT)
                
                if "name" in fields: tk.Entry(r, textvariable=item["name"], width=15).pack(side=tk.LEFT, padx=2)
                if "start" in fields:
                    es = tk.Entry(r, textvariable=item["start"], width=15); es.pack(side=tk.LEFT, padx=2)
                    tk.Button(r, text="▼", width=2, command=lambda b=None, e=es: self.create_preset_menu(b, e)).pack(side=tk.LEFT)
                if "end" in fields:
                    ee = tk.Entry(r, textvariable=item["end"], width=15); ee.pack(side=tk.LEFT, padx=2)
                    tk.Button(r, text="▼", width=2, command=lambda b=None, e=ee: self.create_preset_menu(b, e)).pack(side=tk.LEFT)
                
                if "color" in fields:
                    tk.Entry(r, textvariable=item["color"], width=8).pack(side=tk.LEFT, padx=15)
                    tk.Button(r, text="色", command=lambda v=item["color"]: v.set(colorchooser.askcolor(v.get())[1] or v.get())).pack(side=tk.LEFT)
                
                if "replace" in fields: tk.Entry(r, textvariable=item["replace"], width=30).pack(side=tk.LEFT, padx=5)
                if "comment" in fields: tk.Entry(r, textvariable=item["comment"], width=20).pack(side=tk.LEFT, padx=5)
                if "extra_lines" in fields: tk.Entry(r, textvariable=item["extra_lines"], width=4).pack(side=tk.LEFT, padx=5)

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

        btn_fr = tk.Frame(fr); btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        tk.Button(btn_fr, text="行を追加", command=add, width=10).pack(pady=5)
        def save():
            new_cfg = []
            for item in entries:
                valid = False
                for k in ["pattern", "search", "start"]:
                    if k in fields and item[k].get(): valid = True
                
                if valid:
                    d = {f: item[f].get() for f in fields}
                    d["enabled"] = item["enabled"].get()
                    new_cfg.append(d)
            setattr(self, f"{key}_config", new_cfg)
            dlg.destroy()
            t = self.get_current_tab()
            if t: self.apply_display_update(t)
        tk.Button(btn_fr, text="OK", command=save, width=10, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    # --- IO ---
    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")]); 
        if p: self.load_config(p)
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json"); 
        if p:
            data = {"keywords": self.keywords_config, "sections": self.sections_config, "replace_patterns": self.replace_patterns_config}
            with open(p, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, ensure_ascii=False)
    def load_config(self, p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
                self.keywords_config = d.get("keywords", [])
                self.sections_config = d.get("sections", [])
                self.replace_patterns_config = d.get("replace_patterns", [])
            t = self.get_current_tab(); 
            if t: self.apply_display_update(t)
        except: pass

    def export_to_excel(self):
        tab = self.get_current_tab(); 
        if not tab: return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p: return
        try:
            l, c = tab.text.get("1.0", "end-1c").splitlines(), tab.comment_text.get("1.0", "end-1c").splitlines()
            colors = ["#ffffff"] * len(l)
            
            if tab.is_merged: srcs = tab.line_source_map
            else: srcs = [os.path.basename(tab.file_path)] * len(l)

            s_rules = []
            for s in self.sections_config:
                if s["enabled"]:
                    fp = s.get("file_pattern", ".*") or ".*"
                    try: s_rules.append({"s": re.compile(s["start"], re.I), "e": re.compile(s["end"], re.I), "c": s["color"], "fp": re.compile(fp, re.I)})
                    except: pass
            
            k_rules = []
            for it in self.keywords_config:
                if it["enabled"]:
                    try: k_rules.append((re.compile(it["pattern"], re.I), it["color"], int(it["extra_lines"])))
                    except: pass
            
            for i in range(len(l)):
                for pat, col, ext in k_rules:
                    if pat.search(l[i]):
                        for j in range(i, min(i+ext+1, len(l))): colors[j] = col
                        break

            h = ['<html><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:monospace;} th{background:#ddd;border:1px solid #999;} td{border:1px solid #ccc;padding:2px 4px;white-space:pre-wrap;}</style></head><body><table>']
            h.append('<thead><tr><th>Line</th><th>Log Content</th><th>Comment</th></tr></thead><tbody>')
            for i, line in enumerate(l):
                cm = c[i] if i < len(c) else ""
                h.append(f'<tr style="background:{colors[i]}"><td>{i+1}</td><td>{html.escape(line)}</td><td>{html.escape(cm)}</td></tr>')
            with open(p, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</tbody></table></body></html>")
            messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS(); app = LogViewerApp(root); root.mainloop()