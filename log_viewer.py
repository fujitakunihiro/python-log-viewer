from __future__ import annotations

import json
import os
import sys
import re
import html
import ctypes
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, simpledialog
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
        self.root.title("Log Viewer") # タイトルはそのまま (Log Viewer)

        # ... (中略: 初期設定、コンフィグパスなど) ...
        self.root.geometry("1200x700")

        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        self.keywords_config: List[Dict[str, Any]] = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns_config: List[Dict[str, Any]] = []

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
        
        # Fileメニュー
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="開く...", accelerator="Ctrl+O", command=self.open_file) # Open... -> 開く...
        filemenu.add_command(label="再読み込み", accelerator="F5", command=self.reload_file) # Reload -> 再読み込み
        filemenu.add_separator()
        filemenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel) # Export to Excel (HTML)... -> Excel形式でエクスポート (HTML)...
        filemenu.add_separator()
        filemenu.add_command(label="終了", command=self.root.quit) # Exit -> 終了
        menubar.add_cascade(label="ファイル", menu=filemenu) # File -> ファイル

        # Editメニュー
        editmenu = tk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="検索...", accelerator="Ctrl+F", command=self.open_find_dialog) # Find... -> 検索...
        editmenu.add_command(label="次を検索", accelerator="F3", command=self.find_next) # Find Next -> 次を検索
        menubar.add_cascade(label="編集", menu=editmenu) # Edit -> 編集

        # Configメニュー
        configmenu = tk.Menu(menubar, tearoff=0)
        configmenu.add_command(label="設定読み込み...", command=self.load_config_dialog) # Load Config... -> 設定読み込み...
        configmenu.add_command(label="設定保存...", command=self.save_config_dialog) # Save Config... -> 設定保存...
        configmenu.add_separator()
        configmenu.add_command(label="フィルタ設定の編集...", command=self.edit_keywords_dialog) # Edit Filter... -> フィルタ設定の編集...
        configmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog) # Edit Replace Patterns... -> 説明パターンの編集...
        menubar.add_cascade(label="設定", menu=configmenu) # Config -> 設定

        self.root.config(menu=menubar)

        # --- Toolbar ---
        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # フィルタ切り替えボタン
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=15, # Filter: OFF -> フィルタ: OFF
                                       command=self.toggle_keyword_filter, relief=tk.RAISED)
        self.btn_kw_filter.pack(side=tk.LEFT)

        # --- Main Layout (PanedWindow) ---
        self.vsb = tk.Scrollbar(self.root, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.paned_window = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # 左側: ログ (60%)
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

        # 右側: コメント (40%)
        right_frame = tk.Frame(self.paned_window)
        self.paned_window.add(right_frame, minsize=100, stretch="always", width=480) 

        self.hsb_cmt = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)

        self.comment_text = tk.Text(right_frame, wrap=tk.NONE, undo=False, maxundo=0,
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set,
                                    bg="#fcfcfc", fg="#0000aa")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)

        # スクロール同期
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
        self.status_var = tk.StringVar(value="準備完了") # Ready -> 準備完了
        tk.Label(self.root, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)

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

        if self.replace_patterns_config:
            data = self._apply_replacements(data)

        self.original_content = data
        self.status_var.set(f"ファイルを開きました: {path} [{used_enc}]") # Opened: {path} [{used_enc}] -> ファイルを開きました: {path} [{used_enc}]
        self.apply_display_update()

    def _apply_replacements(self, content: str) -> str:
        matches = []
        for item in self.replace_patterns_config:
            if not item.get("enabled", True): continue
            
            search = item.get("search", "")
            replace = item.get("replace", "")
            
            flags = re.IGNORECASE
            try:
                pattern = re.compile(search, flags)
                for m in pattern.finditer(content):
                    try:
                        repl_text = m.expand(replace)
                    except re.error:
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

    # --- Excel Export Logic ---
    def export_to_excel(self):
        if not self.text.get("1.0", "end-1c").strip():
            messagebox.showwarning("エクスポート", "保存するデータがありません。") # Export -> エクスポート
            return

        path = filedialog.asksaveasfilename(
            title="Excel形式でエクスポート (HTML)", # Export to Excel (HTML) -> Excel形式でエクスポート (HTML)
            defaultextension=".html",
            filetypes=[("HTMLファイル (Excelで開けます)", "*.html"), ("すべてのファイル", "*.*")] # HTML File (Excel readable) -> HTMLファイル (Excelで開けます), All Files -> すべてのファイル
        )
        if not path: return

        try:
            # ... (HTML生成ロジックは変更なし) ...

            with open(path, "w", encoding="utf-8-sig") as f:
                f.write("\n".join(html_content))

            msg = f"保存しました。\n今すぐExcel（ブラウザ）で開いて確認しますか？\n\n場所: {path}"
            if sys.platform == 'win32':
                if ctypes.windll.user32.MessageBoxW(0, msg, "エクスポート完了", 4 | 32) == 6: # Export Complete -> エクスポート完了
                    os.startfile(path)
            else:
                messagebox.showinfo("エクスポート完了", f"保存しました。\n{path}") # Export Complete -> エクスポート完了

        except Exception as e:
            messagebox.showerror("エラー", f"エクスポート中にエラーが発生しました:\n{e}") # Error -> エラー, エラーメッセージを日本語化

    # --- Filter & View Update Logic ---
    def toggle_keyword_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        if self.use_keyword_filter:
            self.btn_kw_filter.config(text="フィルタ: ON", relief=tk.SUNKEN, bg="#aaccff") # Filter: ON -> フィルタ: ON
        else:
            self.btn_kw_filter.config(text="フィルタ: OFF", relief=tk.RAISED, bg="SystemButtonFace") # Filter: OFF -> フィルタ: OFF
        self.apply_display_update()

    def apply_display_update(self):
        if not self.original_content: 
            return

        use_kw = self.use_keyword_filter
        lines = self.original_content.splitlines()
        
        check_list = []
        for item in self.keywords_config:
            if not item.get("enabled", True): continue
            
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
        status_txt = f"表示: {count} 行" # Display: {count} lines -> 表示: {count} 行
        if use_kw: status_txt += " | フィルタ: ON" # Filter: ON -> フィルタ: ON
        self.status_var.set(status_txt)

    def highlight_keywords(self):
        for tag in self.text.tag_names():
            if tag.startswith("kw_"): self.text.tag_delete(tag)

        count_var = tk.IntVar()
        
        for item in self.keywords_config:
            if not item.get("enabled", True): continue
            
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
        k = simpledialog.askstring("検索", "検索する文字列:") # Find -> 検索, Text to find: -> 検索する文字列:
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
            messagebox.showinfo("検索", "一致する項目はありません。") # Find -> 検索, No more matches found. -> 一致する項目はありません。

    # --- Helper ---
    def create_preset_menu(self, parent_btn, entry_widget):
        # ... (プリセット内容は日本語化) ...
        menu = tk.Menu(self.root, tearoff=0)
        presets_groups = [
            ("--- 数値・値 ---", None),
            ("整数 (例: 123)", r"\d+"),
            ("16進数 (例: 0xA1)", r"0x[0-9A-Fa-f]+"),
            ("小数/符号付 (例: -12.5)", r"[-+]?\d+(\.\d+)?"),
            ("--- ネットワーク・ID ---", None),
            ("IPアドレス", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
            ("MACアドレス (例: AA:BB:CC...)", r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"),
            ("--- 文字列・構造 ---", None),
            ("[]の中身 (例: [INFO])", r"\[.*?\]"),
            ("Key=Value (例: Err=1)", r"\w+\s*=\s*\S+"),
            ("--- グループ・論理 ---", None),
            ("グループ化 (グループ番号取得)", r"()"),
            ("いずれか (A|B)", r"|"),
            ("--- ワイルドカード ---", None),
            ("任意の文字列 (.*)", r".*"),
        ]
        # ... (メニュー構築ロジックは変更なし) ...
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

    # --- Config Dialogs (Modal with Aligned Labels) ---
    def edit_keywords_dialog(self):
        if self.keywords_dlg_ref is not None and self.keywords_dlg_ref.winfo_exists():
            self.keywords_dlg_ref.lift()
            return

        dlg = tk.Toplevel(self.root)
        self.keywords_dlg_ref = dlg
        dlg.title("フィルタ設定の編集") # Edit Filter -> フィルタ設定の編集
        dlg.geometry("1100x450") 
        dlg.transient(self.root)
        dlg.grab_set()

        container = tk.Frame(dlg)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- ヘッダー位置合わせ ---
        header_frame = tk.Frame(left_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # 1. 左側ボタン群(Check,Up,Down,Del)の幅分のスペーサー: 約130-135px
        tk.Frame(header_frame, width=135).pack(side=tk.LEFT)
        
        # 2. "Regex Pattern" ラベル
        tk.Label(header_frame, text="正規表現パターン", width=30, anchor="w").pack(side=tk.LEFT, padx=(5, 0)) # Regex Pattern -> 正規表現パターン
        
        # 3. [▼]ボタン分のスペーサー: 約30px
        tk.Frame(header_frame, width=35).pack(side=tk.LEFT)
        
        # 4. "Color" ラベル
        tk.Label(header_frame, text="色", width=10, anchor="w").pack(side=tk.LEFT, padx=(0,0)) # Color -> 色
        
        # 5. [Color]ボタン分のスペーサー: 約55px
        tk.Frame(header_frame, width=55).pack(side=tk.LEFT)
        
        # 6. "Comment" ラベル
        tk.Label(header_frame, text="コメント", width=20, anchor="w").pack(side=tk.LEFT, padx=(5,0)) # Comment -> コメント

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

        def refresh_rows():
            for widget in scrollable_frame.winfo_children():
                widget.destroy()
            for i, (en, kv, cv, cmtv) in enumerate(entries):
                row = tk.Frame(scrollable_frame)
                row.pack(fill=tk.X, pady=2, padx=5)

                # 左側コントロール群
                tk.Checkbutton(row, variable=en).pack(side=tk.LEFT, padx=2)
                btn_up = tk.Button(row, text="↑", width=2, command=lambda idx=i: move_up(idx))
                btn_up.pack(side=tk.LEFT, padx=(2,0))
                if i == 0: btn_up.config(state="disabled")
                btn_down = tk.Button(row, text="↓", width=2, command=lambda idx=i: move_down(idx))
                btn_down.pack(side=tk.LEFT, padx=(0,2))
                if i == len(entries) - 1: btn_down.config(state="disabled")
                tk.Button(row, text="削除", width=3, command=lambda idx=i: delete_row(idx)).pack(side=tk.LEFT, padx=2) # Del -> 削除

                # 入力フィールド
                entry_k = tk.Entry(row, textvariable=kv, width=32)
                entry_k.pack(side=tk.LEFT, padx=(5, 2))
                
                btn_help = tk.Button(row, text="▼", width=2, command=lambda e=entry_k: self.create_preset_menu(btn_help, e))
                btn_help.pack(side=tk.LEFT, padx=(0, 5))
                
                tk.Entry(row, textvariable=cv, width=8).pack(side=tk.LEFT, padx=(0, 2))
                tk.Button(row, text="色選択", command=lambda v=cv: v.set(colorchooser.askcolor(v.get(), parent=dlg)[1] or v.get())).pack(side=tk.LEFT, padx=2) # Color -> 色選択
                
                tk.Entry(row, textvariable=cmtv, width=40).pack(side=tk.LEFT, padx=(10, 5))

        def add_row(k="", c=None, cmt="", enabled=True):
            if c is None: c = preset_colors[len(entries) % len(preset_colors)]
            entries.append((tk.BooleanVar(value=enabled), tk.StringVar(value=k), tk.StringVar(value=c), tk.StringVar(value=cmt)))
            refresh_rows()

        def delete_row(index):
            del entries[index]
            refresh_rows()

        def move_up(index):
            if index > 0:
                entries[index-1], entries[index] = entries[index], entries[index-1]
                refresh_rows()

        def move_down(index):
            if index < len(entries) - 1:
                entries[index+1], entries[index] = entries[index], entries[index+1]
                refresh_rows()

        for item in self.keywords_config:
            add_row(item.get("pattern", ""), item.get("color", None), item.get("comment", ""), item.get("enabled", True))
        
        if not entries: add_row()

        right_frame = tk.Frame(container)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        tk.Button(right_frame, text="行を追加", command=lambda: add_row(), width=10, height=2).pack(side=tk.TOP, pady=5) # Add Row -> 行を追加
        
        def save():
            new_config = []
            for en, kv, cv, cmtv in entries:
                if kv.get():
                    new_config.append({
                        "pattern": kv.get(), 
                        "color": cv.get(), 
                        "comment": cmtv.get(),
                        "enabled": en.get()
                    })
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
        dlg.title("説明パターンの編集") # Edit Replace Patterns -> 説明パターンの編集
        dlg.geometry("950x450")
        dlg.transient(self.root)
        dlg.grab_set()

        container = tk.Frame(dlg)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(left_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Spacer for left controls (Check+Up+Down+Del)
        tk.Frame(header_frame, width=135).pack(side=tk.LEFT)
        
        tk.Label(header_frame, text="正規表現パターン", width=35, anchor="w").pack(side=tk.LEFT, padx=(5, 0))
        
        # Spacer for ▼ button area
        tk.Frame(header_frame, width=30).pack(side=tk.LEFT)
        
        tk.Label(header_frame, text="説明", width=40, anchor="w").pack(side=tk.LEFT)
        
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

        def refresh_rows():
            for widget in scrollable_frame.winfo_children():
                widget.destroy()
            
            for i, (en, pv, dv) in enumerate(entries):
                row = tk.Frame(scrollable_frame)
                row.pack(fill=tk.X, pady=2, padx=5)
                
                # 左側コントロール
                tk.Checkbutton(row, variable=en).pack(side=tk.LEFT, padx=2)
                btn_up = tk.Button(row, text="↑", width=2, command=lambda idx=i: move_up(idx))
                btn_up.pack(side=tk.LEFT, padx=(2,0))
                if i == 0: btn_up.config(state="disabled")
                btn_down = tk.Button(row, text="↓", width=2, command=lambda idx=i: move_down(idx))
                btn_down.pack(side=tk.LEFT, padx=(0,2))
                if i == len(entries) - 1: btn_down.config(state="disabled")
                tk.Button(row, text="削除", width=3, command=lambda idx=i: delete_row(idx)).pack(side=tk.LEFT, padx=2)

                # 入力フィールド（パターン）
                entry_p = tk.Entry(row, textvariable=pv, width=35)
                entry_p.pack(side=tk.LEFT, padx=(5, 2))
                
                btn_help = tk.Button(row, text="▼", width=2, command=lambda e=entry_p: self.create_preset_menu(btn_help, e))
                btn_help.pack(side=tk.LEFT, padx=(0, 5))
                
                # 説明フィールド
                tk.Entry(row, textvariable=dv, width=40).pack(side=tk.LEFT, padx=(0, 5))

        def add_row(p="", d="", enabled=True):
            entries.append((tk.BooleanVar(value=enabled), tk.StringVar(value=p), tk.StringVar(value=d)))
            refresh_rows()

        def delete_row(index):
            del entries[index]
            refresh_rows()

        def move_up(index):
            if index > 0:
                entries[index-1], entries[index] = entries[index], entries[index-1]
                refresh_rows()

        def move_down(index):
            if index < len(entries) - 1:
                entries[index+1], entries[index] = entries[index], entries[index+1]
                refresh_rows()

        for item in self.replace_patterns_config:
            add_row(item.get("search", ""), item.get("replace", ""), item.get("enabled", True))
        
        if not entries: add_row()

        right_frame = tk.Frame(container)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        tk.Button(right_frame, text="行を追加", command=lambda: add_row(), width=10, height=2).pack(side=tk.TOP, pady=5)
        
        def save():
            new_patterns = []
            for en, pv, dv in entries:
                if pv.get():
                    new_patterns.append({
                        "search": pv.get(),
                        "replace": dv.get(),
                        "enabled": en.get()
                    })
            self.replace_patterns_config = new_patterns
            dlg.destroy()
            self.replace_dlg_ref = None
            if self.current_file_path:
                self.reload_file()
        
        tk.Frame(right_frame).pack(fill=tk.Y, expand=True)
        tk.Button(right_frame, text="OK", command=save, width=10, height=2, bg="#dddddd").pack(side=tk.BOTTOM, pady=5)

    # --- Config I/O ---
    def load_config_dialog(self):
        path = filedialog.askopenfilename(filetypes=[("JSONファイル","*.json")]) # JSON -> JSONファイル
        if path: self.load_config(path)

    def save_config_dialog(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSONファイル","*.json")]) # JSON -> JSONファイル
        if path: self.save_config(path)
        
    def load_config(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if "keywords" in data and isinstance(data["keywords"], list):
            self.keywords_config = data["keywords"]
        elif "colors" in data and isinstance(data["colors"], dict):
            self.keywords_config = []
            for k, v in data["colors"].items():
                self.keywords_config.append({"pattern": k, "color": v, "comment": "", "enabled": True})
        
        raw_patterns = data.get("replace_patterns", [])
        self.replace_patterns_config = []
        for p in raw_patterns:
            if isinstance(p, dict):
                self.replace_patterns_config.append({
                    "search": p.get("search", ""),
                    "replace": p.get("replace", ""),
                    "match_case": False,
                    "use_regex": True,
                    "enabled": p.get("enabled", True)
                })
        
        self.apply_display_update()

    def save_config(self, path):
        data = {
            "keywords": self.keywords_config,
            "replace_patterns": self.replace_patterns_config,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()