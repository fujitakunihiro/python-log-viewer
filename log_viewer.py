"""
Embedded Log Viewer v27 (6:4 Split & Trash Icon Edition)

【変更点】
- 画面分割の初期比率を「左6 : 右4」に調整しました。
  (ウィンドウ幅 1200px に対して、左720px : 右480px)
- 設定画面の「Del」ボタンを「🗑」(ゴミ箱アイコン) に変更しました。

【機能一覧】
1. ファイル読み込み (Shift-JIS/UTF-8自動判別, DnD対応)
2. 行番号表示
3. 画面分割表示 (左: ログ本文 / 右: コメント)
4. フィルタ機能 (FilterボタンでON/OFF切替)
5. フィルタ設定 (正規表現, 色, コメント)
   - [▼]ボタンによる正規表現入力支援
6. 文字列置換 (正規表現対応, グループ参照, 即時反映)
7. Excel形式での保存 (HTML形式を利用し、色・コメントを保持して保存)
8. 検索機能 (Ctrl+F)
9. 設定保存 (JSON, 単一ファイル運用)
"""

from __future__ import annotations

import json
import os
import sys
import re
import html
import ctypes
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, simpledialog
from typing import Dict, List, Tuple, Optional

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
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生"},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ"},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ"},
        {"pattern": r"\[\d+\]",   "color": "#e0e0e0", "comment": "タイムスタンプ"}
    ],
    "replace_patterns": []
}

class LineNumberCanvas(tk.Canvas):
    """行番号を描画するキャンバス"""
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
            if dline is None: 
                break
            y = dline[1]
            linenum = str(i).split(".")[0]
            self.create_text(40, y, anchor="ne", text=linenum, fill="#666666")
            i = self.text_widget.index(f"{i}+1line")

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Embedded Log Viewer")
        root.geometry("1200x700")

        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        # 設定データ
        self.keywords_config: List[Dict[str, str]] = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns: List[Tuple[str, str, bool, bool]] = []

        # 状態変数
        self.use_keyword_filter = False
        self.keywords_dlg_ref: Optional[tk.Toplevel] = None
        self.replace_dlg_ref: Optional[tk.Toplevel] = None

        self.current_file_path = None
        self.original_content = "" 
        self.last_search_keyword = ""

        self._build_ui()
        self._bind_shortcuts()
        
        if os.path.exists(self.config_path):
            try:
                self.load_config(self.config_path)
            except Exception as e:
                print(f"Failed to load config: {e}", file=sys.stderr)

    def _build_ui(self) -> None:
        # --- Menu ---
        menubar = tk.Menu(self.root)
        
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open...", accelerator="Ctrl+O", command=self.open_file)
        filemenu.add_command(label="Reload", accelerator="F5", command=self.reload_file)
        filemenu.add_separator()
        filemenu.add_command(label="Export to Excel (HTML)...", command=self.export_to_excel)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        editmenu = tk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="Find...", accelerator="Ctrl+F", command=self.open_find_dialog)
        editmenu.add_command(label="Find Next", accelerator="F3", command=self.find_next)
        menubar.add_cascade(label="Edit", menu=editmenu)

        configmenu = tk.Menu(menubar, tearoff=0)
        configmenu.add_command(label="Load Config...", command=self.load_config_dialog)
        configmenu.add_command(label="Save Config...", command=self.save_config_dialog)
        configmenu.add_separator()
        configmenu.add_command(label="Edit Filter...", command=self.edit_keywords_dialog)
        configmenu.add_command(label="Edit Replace Patterns...", command=self.edit_replace_patterns_dialog)
        menubar.add_cascade(label="Config", menu=configmenu)

        self.root.config(menu=menubar)

        # --- Toolbar ---
        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # フィルタ切り替えボタン
        self.btn_kw_filter = tk.Button(toolbar, text="Filter: OFF", width=15,
                                       command=self.toggle_keyword_filter, relief=tk.RAISED)
        self.btn_kw_filter.pack(side=tk.LEFT)

        # --- Main Layout (PanedWindow) ---
        self.vsb = tk.Scrollbar(self.root, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.paned_window = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # --- 左側: ログ表示エリア (初期幅 720px = 60%) ---
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=720) 

        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)

        self.text = tk.Text(left_frame, wrap=tk.NONE, undo=False, maxundo=0,
                            yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.hsb_log.config(command=self.text.xview)

        # --- 右側: コメント表示エリア (初期幅 480px = 40%) ---
        right_frame = tk.Frame(self.paned_window)
        self.paned_window.add(right_frame, minsize=100, stretch="always", width=480) 

        self.hsb_cmt = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)

        self.comment_text = tk.Text(right_frame, wrap=tk.NONE, undo=False, maxundo=0,
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set,
                                    bg="#fcfcfc", fg="#0000aa")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.hsb_cmt.config(command=self.comment_text.xview)

        # --- スクロール同期設定 ---
        def sync_yview(*args):
            self.text.yview(*args)
            self.comment_text.yview(*args)
            self.linenumbers.redraw()

        self.vsb.config(command=sync_yview)

        def on_mousewheel(event):
            delta = int(-1*(event.delta/120)) if event.delta else 0
            if event.num == 4: delta = -1
            if event.num == 5: delta = 1
            
            self.text.yview_scroll(delta, "units")
            self.comment_text.yview_scroll(delta, "units")
            self.linenumbers.redraw()
            return "break"

        for widget in [self.text, self.comment_text]:
            widget.bind('<MouseWheel>', on_mousewheel)
            widget.bind('<Button-4>', on_mousewheel)
            widget.bind('<Button-5>', on_mousewheel)

        self.text.bind('<KeyRelease>', lambda e: self.linenumbers.redraw())

        # ステータスバー
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)

        # DnD
        if HAS_DND and hasattr(self.text, 'drop_target_register'):
            self.text.drop_target_register(DND_FILES)
            self.text.dnd_bind('<<Drop>>', self._on_drop_file)

    def _bind_shortcuts(self):
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())
        self.root.bind('<F5>', lambda e: self.reload_file())

    def _on_drop_file(self, event):
        path = event.data
        if path.startswith('{') and path.endswith('}'): path = path[1:-1]
        self._open_file_path(path)

    # --- File Operations ---
    def open_file(self):
        path = filedialog.askopenfilename()
        if path: self._open_file_path(path)

    def reload_file(self):
        if self.current_file_path:
            self._open_file_path(self.current_file_path)

    def _open_file_path(self, path: str):
        self.current_file_path = path
        encodings = ['utf-8', 'cp932', 'shift_jis', 'latin-1']
        data = None
        used_enc = ""

        for enc in encodings:
            try:
                with open(path, "r", encoding=enc) as f:
                    data = f.read()
                    used_enc = enc
                    break
            except UnicodeDecodeError:
                continue
        
        if data is None:
            with open(path, "r", encoding='utf-8', errors='replace') as f:
                data = f.read()
                used_enc = "utf-8(replace)"

        if self.replace_patterns:
            data = self._apply_replacements(data)

        self.original_content = data
        self.status_var.set(f"Opened: {path} [{used_enc}]")
        self.apply_display_update()

    def _apply_replacements(self, content: str) -> str:
        matches = []
        for entry in self.replace_patterns:
            if len(entry) == 4:
                search, replace, match_case, use_regex = entry
            else:
                search, replace, match_case = entry
                use_regex = False

            flags = 0 if match_case else re.IGNORECASE
            try:
                if use_regex:
                    pattern = re.compile(search, flags)
                else:
                    pattern = re.compile(re.escape(search), flags)

                for m in pattern.finditer(content):
                    if use_regex:
                        try:
                            repl_text = m.expand(replace)
                        except re.error:
                            repl_text = replace
                    else:
                        repl_text = replace
                    
                    matches.append((m.start(), m.end(), m.group(0), repl_text))
            except re.error:
                continue

        if not matches: return content

        matches.sort(key=lambda x: x[0])
        out = []
        pos = 0
        for s, e, orig, repl in matches:
            if s < pos: continue
            out.append(content[pos:s])
            out.append(f"{orig}({repl})")
            pos = e
        out.append(content[pos:])
        return "".join(out)

    # --- Excel Export Logic (HTML) ---
    def export_to_excel(self):
        """現在表示中のログを色とコメント付きでHTMLファイルとして保存（Excelで開ける形式）"""
        if not self.text.get("1.0", "end-1c").strip():
            messagebox.showwarning("Export", "保存するデータがありません。")
            return

        # ファイル保存ダイアログ
        path = filedialog.asksaveasfilename(
            title="Export to Excel (HTML)",
            defaultextension=".html",
            filetypes=[("HTML File (Excel readable)", "*.html"), ("All Files", "*.*")]
        )
        if not path:
            return

        try:
            log_lines = self.text.get("1.0", "end-1c").splitlines()
            comment_lines = self.comment_text.get("1.0", "end-1c").splitlines()

            html_content = [
                '<html><head><meta charset="utf-8">',
                '<style>table { border-collapse: collapse; width: 100%; font-family: Consolas, monospace; }',
                'th, td { border: 1px solid #999; padding: 4px; text-align: left; vertical-align: top; }',
                'th { background-color: #ddd; }</style></head>',
                '<body><table>',
                '<thead><tr><th>Line</th><th>Log Content</th><th>Comment</th></tr></thead><tbody>'
            ]

            check_list = []
            for item in self.keywords_config:
                pat_str = item.get("pattern", "")
                color = item.get("color", "#ffffff")
                if pat_str:
                    try:
                        check_list.append((re.compile(pat_str, re.IGNORECASE), color))
                    except re.error: pass

            for i, line in enumerate(log_lines):
                cmt = comment_lines[i] if i < len(comment_lines) else ""
                bg_color = "#ffffff"
                for pat, color in check_list:
                    if pat.search(line):
                        bg_color = color
                        break 
                
                safe_line = html.escape(line)
                safe_cmt = html.escape(cmt)
                html_content.append(
                    f'<tr style="background-color: {bg_color}"><td>{i+1}</td>'
                    f'<td style="white-space: pre-wrap;">{safe_line}</td><td>{safe_cmt}</td></tr>'
                )

            html_content.append('</tbody></table></body></html>')

            with open(path, "w", encoding="utf-8-sig") as f:
                f.write("\n".join(html_content))

            msg = f"保存しました。\n今すぐExcel（ブラウザ）で開いて確認しますか？\n\n場所: {path}"
            if sys.platform == 'win32':
                if ctypes.windll.user32.MessageBoxW(0, msg, "Export Complete", 4 | 32) == 6:
                    os.startfile(path)
            else:
                messagebox.showinfo("Export Complete", f"保存しました。\n{path}")

        except Exception as e:
            messagebox.showerror("Error", f"エクスポート中にエラーが発生しました:\n{e}")

    # --- Filter & View Update Logic ---
    def toggle_keyword_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        if self.use_keyword_filter:
            self.btn_kw_filter.config(text="Filter: ON", relief=tk.SUNKEN, bg="#aaccff")
        else:
            self.btn_kw_filter.config(text="Filter: OFF", relief=tk.RAISED, bg="SystemButtonFace")
        self.apply_display_update()

    def apply_display_update(self):
        """表示更新：フィルタ適用とコメント生成を行う"""
        if not self.original_content: 
            return

        use_kw = self.use_keyword_filter
        lines = self.original_content.splitlines()
        
        check_list = []
        for item in self.keywords_config:
            pat_str = item.get("pattern", "")
            cmt = item.get("comment", "")
            if pat_str:
                try:
                    p = re.compile(pat_str, re.IGNORECASE)
                    check_list.append((p, cmt))
                except re.error:
                    pass

        filtered_lines = []
        comment_lines = []

        for line in lines:
            matched_comment = ""
            is_match = False
            
            for pat, cmt in check_list:
                if pat.search(line):
                    is_match = True
                    if cmt:
                        matched_comment = cmt
                        break 
            
            if use_kw and not is_match:
                continue

            filtered_lines.append(line)
            comment_lines.append(matched_comment)

        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", "\n".join(filtered_lines))
        
        self.comment_text.delete("1.0", tk.END)
        self.comment_text.insert("1.0", "\n".join(comment_lines))

        self.linenumbers.redraw()
        self.highlight_keywords()
        
        count = len(filtered_lines)
        status_txt = f"Display: {count} lines"
        if use_kw: status_txt += " | Filter: ON"
        self.status_var.set(status_txt)

    def highlight_keywords(self):
        for tag in self.text.tag_names():
            if tag.startswith("kw_"): self.text.tag_delete(tag)

        count_var = tk.IntVar()
        
        for item in self.keywords_config:
            pattern = item.get("pattern", "")
            color = item.get("color", "#ffffff")
            if not pattern: continue
            
            tag_name = f"kw_{abs(hash(pattern))}"
            self.text.tag_configure(tag_name, background=color)
            
            start_pos = "1.0"
            while True:
                try:
                    pos = self.text.search(pattern, start_pos, stopindex=tk.END, 
                                           nocase=True, regexp=True, count=count_var)
                except tk.TclError:
                    break

                if not pos: break
                
                match_len = count_var.get()
                if match_len == 0:
                    start_pos = f"{pos}+1c"
                    continue

                end_pos = f"{pos}+{match_len}c"
                self.text.tag_add(tag_name, pos, end_pos)
                start_pos = end_pos

    # --- Find Function ---
    def open_find_dialog(self):
        k = simpledialog.askstring("Find", "Text to find:")
        if k:
            self.last_search_keyword = k
            self.find_next(True)

    def find_next(self, start_first=False):
        if not self.last_search_keyword: return
        start = "1.0" if start_first else f"{self.text.index(tk.INSERT)}+1c"
        pos = self.text.search(self.last_search_keyword, start, stopindex=tk.END, nocase=True)
        if pos:
            self.text.mark_set(tk.INSERT, pos)
            self.text.see(pos)
            end = f"{pos}+{len(self.last_search_keyword)}c"
            self.text.tag_remove("found", "1.0", tk.END)
            self.text.tag_add("found", pos, end)
            self.text.tag_config("found", background="yellow", foreground="black")
            self.text.focus_set()
        else:
            messagebox.showinfo("Find", "No more matches found.")

    # --- Helper ---
    def create_preset_menu(self, parent_btn, entry_widget):
        menu = tk.Menu(self.root, tearoff=0)
        presets_groups = [
            ("--- 数値・値 ---", None),
            ("整数 (例: 123)", r"\d+"),
            ("16進数 (例: 0xA1)", r"0x[0-9A-Fa-f]+"),
            ("小数/符号付 (例: -12.5)", r"[-+]?\d+(\.\d+)?"),
            ("--- ネットワーク・ID ---", None),
            ("IPアドレス", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
            ("MACアドレス", r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"),
            ("--- 文字列・構造 ---", None),
            ("[]の中身 (例: [INFO])", r"\[.*?\]"),
            ("Key=Value (例: Err=1)", r"\w+\s*=\s*\S+"),
            ("--- グループ・論理 ---", None),
            ("グループ化 (...)", r"()"),
            ("いずれか (A|B)", r"|"),
            ("--- ワイルドカード ---", None),
            ("任意の文字列 (*)", r".*"),
        ]
        def insert_text(text):
            if text: entry_widget.insert(tk.INSERT, text)
        for label, regex in presets_groups:
            if regex is None:
                menu.add_separator()
                menu.add_command(label=label, state="disabled")
            else:
                menu.add_command(label=label, command=lambda t=regex: insert_text(t))
        try:
            menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())
        finally:
            menu.grab_release()

    # --- Config Dialogs (Modal) ---
    def edit_keywords_dialog(self):
        if self.keywords_dlg_ref is not None and self.keywords_dlg_ref.winfo_exists():
            self.keywords_dlg_ref.lift()
            return

        dlg = tk.Toplevel(self.root)
        self.keywords_dlg_ref = dlg
        dlg.title("Edit Filter")
        dlg.geometry("950x450")
        dlg.transient(self.root)
        dlg.grab_set()

        container = tk.Frame(dlg)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(left_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="Regex Pattern", width=45, anchor="w").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Color", width=10, anchor="w").pack(side=tk.LEFT, padx=(38,0))
        tk.Label(header_frame, text="Comment", width=40, anchor="w").pack(side=tk.LEFT, padx=10)

        canvas = tk.Canvas(left_frame, highlightthickness=0)
        scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        scrollable_frame.bind("<Configure>", on_frame_configure)
        def on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind("<Configure>", on_canvas_configure)

        entries = []
        preset_colors = ["#ffff99", "#ccffcc", "#ccffff", "#ffcc99", "#ff99cc", "#e0e0e0"]

        def add_row(k="", c=None, cmt=""):
            row = tk.Frame(scrollable_frame)
            row.pack(fill=tk.X, pady=2, padx=5)
            if c is None: c = preset_colors[len(entries) % len(preset_colors)]
            
            kv = tk.StringVar(value=k)
            cv = tk.StringVar(value=c)
            cmtv = tk.StringVar(value=cmt)

            entry_k = tk.Entry(row, textvariable=kv, width=42)
            entry_k.pack(side=tk.LEFT, padx=(0, 2))
            
            btn_help = tk.Button(row, text="▼", width=2, command=lambda: self.create_preset_menu(btn_help, entry_k))
            btn_help.pack(side=tk.LEFT, padx=(0, 5))
            
            tk.Entry(row, textvariable=cv, width=8).pack(side=tk.LEFT, padx=(0, 2))
            tk.Button(row, text="Color", command=lambda: cv.set(colorchooser.askcolor(cv.get(), parent=dlg)[1] or cv.get())).pack(side=tk.LEFT, padx=2)
            
            tk.Entry(row, textvariable=cmtv, width=40).pack(side=tk.LEFT, padx=(10, 5))

            # ゴミ箱ボタン
            tk.Button(row, text="🗑", width=3, command=lambda: (row.destroy(), entries.remove((kv,cv,cmtv)))).pack(side=tk.LEFT, padx=2)
            entries.append((kv, cv, cmtv))

        for item in self.keywords_config:
            add_row(item.get("pattern", ""), item.get("color", None), item.get("comment", ""))
        
        if not entries: add_row()

        right_frame = tk.Frame(container)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        tk.Button(right_frame, text="Add Row", command=add_row, width=10, height=2).pack(side=tk.TOP, pady=5)
        
        def save():
            new_config = []
            for kv, cv, cmtv in entries:
                if kv.get():
                    new_config.append({"pattern": kv.get(), "color": cv.get(), "comment": cmtv.get()})
            self.keywords_config = new_config
            dlg.destroy()
            self.keywords_dlg_ref = None
            self.apply_display_update()
        
        tk.Frame(right_frame).pack(fill=tk.Y, expand=True)
        tk.Button(right_frame, text="OK", command=save, width=10, height=2, bg="#dddddd").pack(side=tk.BOTTOM, pady=5)
    
    def edit_replace_patterns_dialog(self):
        if self.replace_dlg_ref is not None and self.replace_dlg_ref.winfo_exists():
            self.replace_dlg_ref.lift()
            return

        dlg = tk.Toplevel(self.root)
        self.replace_dlg_ref = dlg
        dlg.title("Edit Replace Patterns")
        dlg.geometry("850x450")
        dlg.transient(self.root)
        dlg.grab_set()

        container = tk.Frame(dlg)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(left_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="Find (Regex)", width=25, anchor="w").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Replace", width=20, anchor="w").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Case", width=5).pack(side=tk.LEFT)
        tk.Label(header_frame, text="Regex", width=5).pack(side=tk.LEFT)
        
        canvas = tk.Canvas(left_frame, highlightthickness=0)
        scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        scrollable_frame.bind("<Configure>", on_frame_configure)
        def on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind("<Configure>", on_canvas_configure)

        entries = []

        def add_row(s="", r="", m=False, rg=True):
            row = tk.Frame(scrollable_frame)
            row.pack(fill=tk.X, pady=2, padx=5)
            sv, rv = tk.StringVar(value=s), tk.StringVar(value=r)
            mv, rgv = tk.BooleanVar(value=m), tk.BooleanVar(value=rg)
            entry_s = tk.Entry(row, textvariable=sv, width=25)
            entry_s.pack(side=tk.LEFT, padx=(0, 2))
            btn_help = tk.Button(row, text="▼", width=2, command=lambda: self.create_preset_menu(btn_help, entry_s))
            btn_help.pack(side=tk.LEFT, padx=(0, 5))
            tk.Entry(row, textvariable=rv, width=20).pack(side=tk.LEFT, padx=(0, 5))
            tk.Checkbutton(row, variable=mv).pack(side=tk.LEFT, padx=5)
            tk.Checkbutton(row, variable=rgv).pack(side=tk.LEFT, padx=5)
            # ゴミ箱ボタン
            tk.Button(row, text="🗑", width=3, command=lambda: (row.destroy(), entries.remove((sv, rv, mv, rgv)))).pack(side=tk.RIGHT)
            entries.append((sv, rv, mv, rgv))

        for entry in self.replace_patterns:
            if len(entry) == 4: add_row(*entry)
            else: add_row(entry[0], entry[1], entry[2], False)
        if not entries: add_row()

        right_frame = tk.Frame(container)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        tk.Button(right_frame, text="Add Row", command=add_row, width=10, height=2).pack(side=tk.TOP, pady=5)
        
        def save():
            new_patterns = []
            for s, r, m, rg in entries:
                if s.get():
                    new_patterns.append((s.get(), r.get(), m.get(), rg.get()))
            self.replace_patterns = new_patterns
            dlg.destroy()
            self.replace_dlg_ref = None
            if self.current_file_path:
                self.reload_file()
        
        tk.Frame(right_frame).pack(fill=tk.Y, expand=True)
        tk.Button(right_frame, text="OK", command=save, width=10, height=2, bg="#dddddd").pack(side=tk.BOTTOM, pady=5)

    # --- Config I/O ---
    def load_config_dialog(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if path: self.load_config(path)

    def save_config_dialog(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if path: self.save_config(path)

    def load_config(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "keywords" in data and isinstance(data["keywords"], list):
            self.keywords_config = data["keywords"]
        elif "colors" in data and isinstance(data["colors"], dict):
            self.keywords_config = []
            for k, v in data["colors"].items():
                self.keywords_config.append({"pattern": k, "color": v, "comment": ""})
        
        loaded_patterns = data.get("replace_patterns", [])
        self.replace_patterns = []
        for p in loaded_patterns:
            if isinstance(p, dict):
                self.replace_patterns.append((p.get("search", ""), p.get("replace", ""), p.get("match_case", False), p.get("use_regex", False)))
        self.apply_display_update()

    def save_config(self, path):
        data = {
            "keywords": self.keywords_config,
            "replace_patterns": [{"search":s, "replace":r, "match_case":m, "use_regex":rg} for s,r,m,rg in self.replace_patterns],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()