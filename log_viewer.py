"""
Embedded Log Viewer v6 (Full Regex Replace Edition)
機能:
 - ファイル読み込み (Shift-JIS/UTF-8自動判別)
 - 行番号表示
 - 高速検索 (Ctrl+F)
 - 設定編集GUI (キーワード色、正規表現置換)
 - 正規表現による検索と置換（グループ参照対応）
 - 設定保存 (JSON)
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
except ImportError:
    ROOT_CLASS = tk.Tk
    DND_FILES = None

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
    """行番号を描画するキャンバス"""
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        self.text_widget.bind('<KeyRelease>', self.redraw)
        self.text_widget.bind('<MouseWheel>', self.redraw)
        self.text_widget.bind('<Configure>', self.redraw)
        self.text_widget.bind('<<Modified>>', self.redraw)

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
        root.title("Embedded Log Viewer (Regex Replace)")
        root.geometry("1100x700")

        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keyword_colors: Dict[str, str] = DEFAULT_CONFIG["colors"].copy()
        # (search, replace, match_case, use_regex)
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

        # --- Text Area ---
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
        
        # Events
        self.text.bind('<KeyRelease>', lambda e: self.linenumbers.redraw())
        self.text.bind('<MouseWheel>', self._on_mousewheel)
        self.text.bind('<Button-4>', self._on_mousewheel)
        self.text.bind('<Button-5>', self._on_mousewheel)
        
        if DND_FILES and hasattr(self.text, 'drop_target_register'):
            self.text.drop_target_register(DND_FILES)
            self.text.dnd_bind('<<Drop>>', self._on_drop_file)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)

        # Internal State
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

    # --- File Ops ---
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

        # Apply Replacements
        if self.replace_patterns:
            data = self._apply_replacements(data)

        self.original_content = data
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", data)
        self.status_var.set(f"Opened: {path} [{used_enc}]")
        
        self.linenumbers.redraw()
        self.highlight_keywords()

    def _apply_replacements(self, content: str) -> str:
        """置換ルールを適用し、Original(Replaced)形式で返す"""
        import re
        matches = []
        for entry in self.replace_patterns:
            # 互換性維持: 3要素ならRegex=Falseとみなす
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
                    # 置換後文字列の生成
                    if use_regex:
                        try:
                            # \1 などを展開する
                            repl_text = m.expand(replace)
                        except re.error:
                            repl_text = replace
                    else:
                        repl_text = replace
                    
                    matches.append((m.start(), m.end(), m.group(0), repl_text))
            except re.error:
                continue

        if not matches: return content

        # 重なりを除去しつつ結合
        matches.sort(key=lambda x: x[0])
        
        out = []
        pos = 0
        for s, e, orig, repl in matches:
            if s < pos: continue
            out.append(content[pos:s])
            # 変更が見やすいように Original(Replaced) 形式にする
            # 改行が含まれると見づらくなるので、簡易的に1行に収まる場合のみ等の調整もアリだが
            # ここではそのまま結合する
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

    # --- Find ---
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

    # --- Config Editors ---
    def edit_keywords_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit Keywords")
        
        header = tk.Frame(dlg)
        header.pack(padx=10, pady=(10,0), fill=tk.X)
        tk.Label(header, text="Regex Pattern").pack(side=tk.LEFT, padx=(5, 80))
        tk.Label(header, text="Color").pack(side=tk.LEFT)

        canvas = tk.Canvas(dlg, borderwidth=0)
        frame = tk.Frame(canvas)
        vsb = tk.Scrollbar(dlg, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        canvas.create_window((4,4), window=frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        frame.bind("<Configure>", on_frame_configure)

        entries = []

        def add_row(k="", c="#ffffff"):
            row = tk.Frame(frame)
            row.pack(fill=tk.X, pady=2)
            kv, cv = tk.StringVar(value=k), tk.StringVar(value=c)
            tk.Entry(row, textvariable=kv, width=25).pack(side=tk.LEFT)
            tk.Entry(row, textvariable=cv, width=10).pack(side=tk.LEFT, padx=5)
            tk.Button(row, text="Color", command=lambda: cv.set(colorchooser.askcolor(cv.get())[1] or cv.get())).pack(side=tk.LEFT)
            tk.Button(row, text="Del", command=lambda: (row.destroy(), entries.remove((kv,cv)))).pack(side=tk.LEFT, padx=5)
            entries.append((kv, cv))

        for k, v in self.keyword_colors.items(): add_row(k, v)
        
        btn_frame = tk.Frame(dlg)
        btn_frame.pack(fill=tk.X, pady=10)
        tk.Button(btn_frame, text="Add Row", command=add_row).pack(side=tk.LEFT, padx=10)
        
        def save():
            self.keyword_colors = {k.get(): c.get() for k, c in entries if k.get()}
            self.highlight_keywords()
            dlg.destroy()
        
        tk.Button(btn_frame, text="OK", command=save, width=10).pack(side=tk.RIGHT, padx=10)

    def edit_replace_patterns_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit Replace Patterns")
        frame = tk.Frame(dlg)
        frame.pack(padx=10, pady=10)
        entries = []

        tk.Label(frame, text="Find (Regex)").grid(row=0, column=0)
        tk.Label(frame, text="Replace").grid(row=0, column=1)
        tk.Label(frame, text="Case").grid(row=0, column=2)
        tk.Label(frame, text="Regex").grid(row=0, column=3)

        def add_row(s="", r="", m=False, rg=True): # Default regex=True
            sv, rv = tk.StringVar(value=s), tk.StringVar(value=r)
            mv, rgv = tk.BooleanVar(value=m), tk.BooleanVar(value=rg)
            
            row_idx = len(entries) + 1
            tk.Entry(frame, textvariable=sv).grid(row=row_idx, column=0)
            tk.Entry(frame, textvariable=rv).grid(row=row_idx, column=1)
            tk.Checkbutton(frame, variable=mv).grid(row=row_idx, column=2)
            tk.Checkbutton(frame, variable=rgv).grid(row=row_idx, column=3)
            
            entries.append((sv, rv, mv, rgv))

        # 既存データのロード
        for entry in self.replace_patterns:
            if len(entry) == 4:
                add_row(*entry)
            else:
                # 古い設定(3要素)の場合はRegex=False扱いにするか、デフォルトに合わせるか
                # ここでは安全に False にしておく
                add_row(entry[0], entry[1], entry[2], False)

        tk.Button(dlg, text="Add", command=add_row).pack()

        def save():
            new_patterns = []
            for s, r, m, rg in entries:
                if s.get():
                    new_patterns.append((s.get(), r.get(), m.get(), rg.get()))
            self.replace_patterns = new_patterns
            messagebox.showinfo("Saved", "Reload file to apply changes.")
            dlg.destroy()
        tk.Button(dlg, text="OK", command=save).pack(pady=5)

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
        
        # Load replace patterns with backward compatibility
        loaded_patterns = data.get("replace_patterns", [])
        self.replace_patterns = []
        for p in loaded_patterns:
            # p can be dict or list depending on version? 
            # Current save format is list of dicts.
            if isinstance(p, dict):
                self.replace_patterns.append((
                    p.get("search", ""),
                    p.get("replace", ""),
                    p.get("match_case", False),
                    p.get("use_regex", False) # Default to false for old configs
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