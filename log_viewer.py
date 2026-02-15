from __future__ import annotations

import json
import os
import sys
import re
import html
import ctypes
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk
from typing import Dict, List, Tuple, Optional, Any

# --- DnD Support (Optional) ---
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
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True},
        {"pattern": r"\[\d+\]",   "color": "#e0e0e0", "comment": "タイムスタンプ",   "enabled": True}
    ],
    "replace_patterns": []
}

class LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        self.text_widget.bind('<KeyRelease>', self.redraw)
        self.text_widget.bind('<MouseWheel>', self.redraw)
        self.text_widget.bind('<Configure>', self.redraw)
        self.text_widget.bind('<<Modified>>', self.redraw)
        self.text_widget.bind('<Button-1>', self.redraw)

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
    """各ログファイルまたはマージ結果を表示するタブ"""
    def __init__(self, master, app: LogViewerApp, path: str, content: str, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged

        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=720) 
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)

        right_frame = tk.Frame(self.paned_window)
        self.paned_window.add(right_frame, minsize=100, stretch="always", width=480) 
        self.hsb_cmt = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        self.comment_text = tk.Text(right_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa",
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)

        def sync_yview(*args):
            self.text.yview(*args)
            self.comment_text.yview(*args)
            self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)

        def on_mousewheel(event):
            delta = int(-1*(event.delta/120)) if event.delta else 0
            self.text.yview_scroll(delta, "units")
            self.comment_text.yview_scroll(delta, "units")
            self.linenumbers.redraw()
            return "break"
        
        for w in [self.text, self.comment_text]:
            w.bind('<MouseWheel>', on_mousewheel)
            w.bind('<Button-4>', lambda e: on_mousewheel(type('obj', (object,), {'delta': 120})()))
            w.bind('<Button-5>', lambda e: on_mousewheel(type('obj', (object,), {'delta': -120})()))

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1200x800")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns_config = []
        self.use_keyword_filter = False
        self.last_search_keyword = ""

        self._build_ui()
        self._bind_shortcuts()
        if os.path.exists(self.config_path):
            self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        filemenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        filemenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        filemenu.add_separator()
        filemenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        filemenu.add_separator()
        filemenu.add_command(label="終了", command=self.root.quit)
        menubar.add_cascade(label="ファイル", menu=filemenu)
        
        editmenu = tk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="検索...", command=self.open_find_dialog, accelerator="Ctrl+F")
        editmenu.add_command(label="次を検索", command=self.find_next, accelerator="F3")
        menubar.add_cascade(label="編集", menu=editmenu)

        configmenu = tk.Menu(menubar, tearoff=0)
        configmenu.add_command(label="フィルタ設定の編集...", command=self.edit_keywords_dialog)
        configmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        menubar.add_cascade(label="設定", menu=configmenu)
        self.root.config(menu=menubar)

        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=12, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e1f5fe").pack(side=tk.LEFT, padx=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.status_var = tk.StringVar(value="準備完了")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def _bind_shortcuts(self):
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-w>', lambda e: self.close_tab())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    def open_file(self):
        paths = filedialog.askopenfilenames()
        for p in paths: self._open_file_path(p)

    def close_tab(self):
        tab = self.get_current_tab()
        if tab: self.notebook.forget(tab)

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis']:
            try:
                with open(path, "r", encoding=enc) as f:
                    content = f.read()
                    break
            except: continue
        
        tab = LogTab(self.notebook, self, path, content)
        self.notebook.add(tab, text=os.path.basename(path))
        self.notebook.select(tab)
        self.apply_display_update(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs()]
        tabs = [t for t in tabs if isinstance(t, LogTab) and not t.is_merged]
        if len(tabs) < 2:
            messagebox.showwarning("マージ", "マージするには複数のファイルを開いてください。")
            return

        ts_len = simpledialog.askinteger("マージ設定", "時刻として扱う先頭の文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return

        all_lines = []
        for t in tabs:
            fname = os.path.basename(t.file_path)
            for line in t.original_content.splitlines():
                if not line.strip(): continue
                # (ソートキー, 元の行, 出典ファイル名)
                all_lines.append((line[:ts_len], line, fname))

        # 時刻でソート
        all_lines.sort(key=lambda x: x[0])

        merged_content = "\n".join([x[1] for x in all_lines])
        merged_tab = LogTab(self.notebook, self, "Merged_Results", merged_content, is_merged=True)
        
        # マージ版ではコメント欄に出典ファイル名を流し込む
        merged_tab.comment_text.delete("1.0", tk.END)
        merged_tab.comment_text.insert("1.0", "\n".join([x[2] for x in all_lines]))
        
        self.notebook.add(merged_tab, text="[マージ結果]")
        self.notebook.select(merged_tab)
        self.apply_display_update(merged_tab, skip_comment_gen=True)

    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text="フィルタ: ON" if self.use_keyword_filter else "フィルタ: OFF",
                                  bg="#aaccff" if self.use_keyword_filter else "SystemButtonFace")
        tab = self.get_current_tab()
        if tab: self.apply_display_update(tab)

    def apply_display_update(self, tab: LogTab, skip_comment_gen=False):
        content = tab.original_content
        if self.replace_patterns_config:
            content = self._apply_replacements(content)

        lines = content.splitlines()
        check_list = []
        for item in self.keywords_config:
            if item.get("enabled"):
                try: check_list.append((re.compile(item["pattern"], re.I), item.get("comment", "")))
                except: pass

        filtered_lines = []
        auto_comments = []
        
        # マージ済みの場合は既存のコメント（ファイル名）を保持してフィルタ
        existing_comments = tab.comment_text.get("1.0", "end-1c").splitlines() if skip_comment_gen else []

        for i, line in enumerate(lines):
            matched_cmt = ""
            is_match = False
            for pat, cmt in check_list:
                if pat.search(line):
                    is_match = True
                    matched_cmt = cmt
                    break
            
            if self.use_keyword_filter and not is_match: continue
            
            filtered_lines.append(line)
            if skip_comment_gen:
                # マージタブの場合、元の出典ファイル名を維持
                auto_comments.append(existing_comments[i] if i < len(existing_comments) else "")
            else:
                auto_comments.append(matched_cmt)

        tab.text.delete("1.0", tk.END)
        tab.text.insert("1.0", "\n".join(filtered_lines))
        tab.comment_text.delete("1.0", tk.END)
        tab.comment_text.insert("1.0", "\n".join(auto_comments))
        
        self.highlight_keywords(tab)
        tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        # (前回のロジックと同様)
        for item in self.replace_patterns_config:
            if not item.get("enabled"): continue
            try: content = re.sub(item["search"], lambda m: f"{m.group(0)}({m.expand(item['replace'])})", content, flags=re.I)
            except: pass
        return content

    def highlight_keywords(self, tab: LogTab):
        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for item in self.keywords_config:
            if not item.get("enabled") or not item.get("pattern"): continue
            tag = f"kw_{abs(hash(item['pattern']))}"
            tab.text.tag_configure(tag, background=item["color"])
            start = "1.0"
            while True:
                pos = tab.text.search(item["pattern"], start, stopindex=tk.END, nocase=True, regexp=True)
                if not pos: break
                match_len = len(re.search(item["pattern"], tab.text.get(pos, f"{pos} lineend"), re.I).group(0))
                end = f"{pos}+{match_len}c"
                tab.text.tag_add(tag, pos, end)
                start = end

    def export_to_excel(self):
        tab = self.get_current_tab()
        if not tab: return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not path: return
        
        log_lines = tab.text.get("1.0", "end-1c").splitlines()
        cmt_lines = tab.comment_text.get("1.0", "end-1c").splitlines()
        
        html_data = ["<html><head><meta charset='utf-8'><style>td{border:1px solid #ccc; font-family:monospace;}</style></head><body><table>"]
        for i, line in enumerate(log_lines):
            c = cmt_lines[i] if i < len(cmt_lines) else ""
            html_data.append(f"<tr><td>{i+1}</td><td><pre>{html.escape(line)}</pre></td><td>{html.escape(c)}</td></tr>")
        html_data.append("</table></body></html>")
        
        with open(path, "w", encoding="utf-8-sig") as f: f.write("\n".join(html_data))
        messagebox.showinfo("完了", "エクスポートしました。")

    def open_find_dialog(self):
        k = simpledialog.askstring("検索", "検索文字列:")
        if k: self.last_search_keyword = k; self.find_next(True)

    def find_next(self, first=False):
        tab = self.get_current_tab()
        if not tab or not self.last_search_keyword: return
        start = "1.0" if first else f"{tab.text.index(tk.INSERT)}+1c"
        pos = tab.text.search(self.last_search_keyword, start, nocase=True)
        if pos:
            tab.text.mark_set(tk.INSERT, pos)
            tab.text.see(pos)
            tab.text.tag_remove("found", "1.0", tk.END)
            tab.text.tag_add("found", pos, f"{pos}+{len(self.last_search_keyword)}c")
            tab.text.tag_config("found", background="yellow")
            tab.text.focus_set()

    # --- ダイアログ等は省略（前回のロジックとほぼ同等） ---
    def edit_keywords_dialog(self):
        # 簡易的な実装（実際は前回の詳細なダイアログコードを使用）
        messagebox.showinfo("情報", "設定ダイアログを表示します（前回コード参照）")

    def edit_replace_patterns_dialog(self):
        messagebox.showinfo("情報", "パターン編集を表示します（前回コード参照）")

    def load_config(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.keywords_config = data.get("keywords", self.keywords_config)
                self.replace_patterns_config = data.get("replace_patterns", [])
        except: pass

if __name__ == "__main__":
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()