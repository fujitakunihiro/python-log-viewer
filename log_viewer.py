"""
Embedded Log Viewer v9 (Unified Design Edition)

【機能一覧】
1. ファイル読み込み (Shift-JIS/UTF-8自動判別, DnD対応)
2. 行番号表示
3. フィルタ (簡易grep)
4. キーワードハイライト (正規表現対応, 色設定GUI改善)
5. 文字列置換 (正規表現対応, グループ参照対応, 設定GUI改善)
6. 検索機能 (Ctrl+F)
7. 設定保存 (JSON)

※ Edit Keywords と Edit Replace Patterns のデザインを統一しました。
"""

from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, simpledialog
from typing import Dict, List, Tuple

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
    "colors": {
        "ERROR": "#ffcccc",
        "FAIL": "#ffcccc",
        "WARN": "#ffebcc",
        "INFO": "#ccffcc",
        r"\[\d+\]": "#e0e0e0" 
    },
    "replace_patterns": []
}

class LineNumberCanvas(tk.Canvas):
    """テキストウィジェットに同期して行番号を描画するキャンバス"""
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
        root.geometry("1100x700")

        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keyword_colors: Dict[str, str] = DEFAULT_CONFIG["colors"].copy()
        self.replace_patterns: List[Tuple[str, str, bool, bool]] = []

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
        configmenu.add_command(label="Edit Keywords (Highlight)...", command=self.edit_keywords_dialog)
        configmenu.add_command(label="Edit Replace Patterns...", command=self.edit_replace_patterns_dialog)
        menubar.add_cascade(label="Config", menu=configmenu)

        self.root.config(menu=menubar)

        # --- Toolbar ---
        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(toolbar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(toolbar, textvariable=self.filter_var)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.filter_entry.bind('<Return>', lambda e: self.apply_filter())
        
        tk.Button(toolbar, text="Apply", command=self.apply_filter).pack(side=tk.LEFT)
        tk.Button(toolbar, text="Reset", command=self.reset_filter).pack(side=tk.LEFT, padx=2)

        # --- Main Text Area ---
        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.vsb = tk.Scrollbar(frame, orient=tk.VERTICAL)
        self.hsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
        
        self.text = tk.Text(frame, wrap=tk.NONE, undo=False, maxundo=0,
                            yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        
        self.linenumbers = LineNumberCanvas(frame, self.text, width=45, bg='#f0f0f0')

        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.vsb.config(command=self._on_vsb_scroll)
        self.hsb.config(command=self.text.xview)
        
        self.text.bind('<KeyRelease>', lambda e: self.linenumbers.redraw())
        self.text.bind('<MouseWheel>', self._on_mousewheel)
        self.text.bind('<Button-4>', self._on_mousewheel)
        self.text.bind('<Button-5>', self._on_mousewheel)
        
        if HAS_DND and hasattr(self.text, 'drop_target_register'):
            self.text.drop_target_register(DND_FILES)
            self.text.dnd_bind('<<Drop>>', self._on_drop_file)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)

        self.current_file_path = None
        self.original_content = ""
        self.last_search_keyword = ""

    def _bind_shortcuts(self):
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())
        self.root.bind('<F5>', lambda e: self.reload_file())

    def _on_vsb_scroll(self, *args):
        self.text.yview(*args)
        self.linenumbers.redraw()

    def _on_mousewheel(self, event):
        self.text.yview_scroll(int(-1*(event.delta/120)), "units")
        self.linenumbers.redraw()
        return "break"

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
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", data)
        self.status_var.set(f"Opened: {path} [{used_enc}]")
        
        self.linenumbers.redraw()
        self.highlight_keywords()

    def _apply_replacements(self, content: str) -> str:
        import re
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

    # --- Filter & Highlight ---
    def apply_filter(self):
        query = self.filter_var.get()
        if not query or not self.original_content: return
        
        lines = self.original_content.splitlines()
        filtered = [line for line in lines if query.lower() in line.lower()]
        
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", "\n".join(filtered))
        self.linenumbers.redraw()
        self.highlight_keywords()
        self.status_var.set(f"Filter: '{query}' ({len(filtered)} lines)")

    def reset_filter(self):
        if not self.original_content: return
        self.filter_var.set("")
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", self.original_content)
        self.linenumbers.redraw()
        self.highlight_keywords()
        self.status_var.set("Filter reset")

    def highlight_keywords(self):
        for tag in self.text.tag_names():
            if tag.startswith("kw_"): self.text.tag_delete(tag)

        count_var = tk.IntVar()
        for key, color in self.keyword_colors.items():
            if not key: continue
            
            tag_name = f"kw_{abs(hash(key))}"
            self.text.tag_configure(tag_name, background=color)
            
            start_pos = "1.0"
            while True:
                try:
                    pos = self.text.search(key, start_pos, stopindex=tk.END, 
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

    # --- Configuration Dialogs (Unified Design) ---
    
    # 1. Edit Keywords (Design updated to match Replace Patterns)
    def edit_keywords_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit Keywords")
        dlg.geometry("650x400") # 幅合わせ

        # メインコンテナ
        container = tk.Frame(dlg)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- 左側: リスト ---
        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # ヘッダー
        header_frame = tk.Frame(left_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="Regex Pattern", width=35, anchor="w").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Color", width=15, anchor="w").pack(side=tk.LEFT)

        # スクロールエリア
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

        def add_row(k="", c="#ffffff"):
            row = tk.Frame(scrollable_frame)
            row.pack(fill=tk.X, pady=2, padx=5)
            
            kv, cv = tk.StringVar(value=k), tk.StringVar(value=c)
            
            # Entry配置
            tk.Entry(row, textvariable=kv, width=35).pack(side=tk.LEFT, padx=(0, 5))
            tk.Entry(row, textvariable=cv, width=10).pack(side=tk.LEFT, padx=(0, 5))
            
            # Color Picker
            tk.Button(row, text="Color", command=lambda: cv.set(colorchooser.askcolor(cv.get())[1] or cv.get())).pack(side=tk.LEFT, padx=2)
            
            # Delete Button
            tk.Button(row, text="Del", command=lambda: (row.destroy(), entries.remove((kv,cv)))).pack(side=tk.RIGHT)
            
            entries.append((kv, cv))

        for k, v in self.keyword_colors.items(): add_row(k, v)
        if not entries: add_row()

        # --- 右側: ボタン ---
        right_frame = tk.Frame(container)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        tk.Button(right_frame, text="Add Row", command=add_row, width=10, height=2).pack(side=tk.TOP, pady=5)
        
        def save():
            self.keyword_colors = {k.get(): c.get() for k, c in entries if k.get()}
            self.highlight_keywords()
            dlg.destroy()
        
        # OKボタン (下揃え)
        tk.Frame(right_frame).pack(fill=tk.Y, expand=True)
        tk.Button(right_frame, text="OK", command=save, width=10, height=2, bg="#dddddd").pack(side=tk.BOTTOM, pady=5)

    # 2. Edit Replace Patterns
    def edit_replace_patterns_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit Replace Patterns")
        dlg.geometry("750x400")

        container = tk.Frame(dlg)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- 左側: リスト ---
        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(left_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="Find (Regex)", width=22, anchor="w").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Replace", width=22, anchor="w").pack(side=tk.LEFT)
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
            
            tk.Entry(row, textvariable=sv, width=25).pack(side=tk.LEFT, padx=(0, 5))
            tk.Entry(row, textvariable=rv, width=25).pack(side=tk.LEFT, padx=(0, 5))
            tk.Checkbutton(row, variable=mv).pack(side=tk.LEFT, padx=10)
            tk.Checkbutton(row, variable=rgv).pack(side=tk.LEFT, padx=10)
            
            tk.Button(row, text="Del", command=lambda: (row.destroy(), entries.remove((sv, rv, mv, rgv)))).pack(side=tk.RIGHT)
            
            entries.append((sv, rv, mv, rgv))

        for entry in self.replace_patterns:
            if len(entry) == 4:
                add_row(*entry)
            else:
                add_row(entry[0], entry[1], entry[2], False)

        if not entries:
            add_row()

        # --- 右側: ボタン ---
        right_frame = tk.Frame(container)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        tk.Button(right_frame, text="Add Row", command=add_row, width=10, height=2).pack(side=tk.TOP, pady=5)
        
        def save():
            new_patterns = []
            for s, r, m, rg in entries:
                if s.get():
                    new_patterns.append((s.get(), r.get(), m.get(), rg.get()))
            self.replace_patterns = new_patterns
            messagebox.showinfo("Saved", "Settings saved.\nReload file (F5) to apply replacement changes.")
            dlg.destroy()
        
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
        self.keyword_colors = data.get("colors", {})
        
        loaded_patterns = data.get("replace_patterns", [])
        self.replace_patterns = []
        for p in loaded_patterns:
            if isinstance(p, dict):
                self.replace_patterns.append((
                    p.get("search", ""),
                    p.get("replace", ""),
                    p.get("match_case", False),
                    p.get("use_regex", False)
                ))

        self.highlight_keywords()

    def save_config(self, path):
        data = {
            "colors": self.keyword_colors,
            "replace_patterns": [
                {"search":s, "replace":r, "match_case":m, "use_regex":rg} 
                for s,r,m,rg in self.replace_patterns
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()