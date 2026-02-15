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
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True}
    ],
    "replace_patterns": []
}

class LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        for event in ['<KeyRelease>', '<MouseWheel>', '<Configure>', '<<Modified>>', '<Button-1>']:
            self.text_widget.bind(event, self.redraw)

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
    def __init__(self, master, app, path, content, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged
        self.source_files: List[str] = [] # マージ時に各行の由来ファイルを保持する用

        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # 左: ログ表示
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=750)
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 右: コメント・属性表示
        right_frame = tk.Frame(self.paned_window)
        self.paned_window.add(right_frame, minsize=100, stretch="always", width=450)
        self.hsb_cmt = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        self.comment_text = tk.Text(right_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa",
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        def sync_yview(*args):
            self.text.yview(*args); self.comment_text.yview(*args); self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)
        self.hsb_log.config(command=self.text.xview)
        self.hsb_cmt.config(command=self.comment_text.xview)

        def on_mousewheel(event):
            delta = int(-1*(event.delta/120)) if event.delta else 0
            self.text.yview_scroll(delta, "units"); self.comment_text.yview_scroll(delta, "units"); self.linenumbers.redraw()
            return "break"
        for w in [self.text, self.comment_text]:
            w.bind('<MouseWheel>', on_mousewheel)

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1300x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns_config = []
        self.use_keyword_filter = False
        self.last_search_keyword = ""

        self._build_ui()
        if os.path.exists(self.config_path): self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="マージ...", command=self.merge_logs_action)
        fmenu.add_separator()
        fmenu.add_command(label="エクスポート (HTML)...", command=self.export_to_excel)
        menubar.add_cascade(label="ファイル", menu=fmenu)
        
        cmenu = tk.Menu(menubar, tearoff=0)
        cmenu.add_command(label="設定読み込み...", command=self.load_config_dialog)
        cmenu.add_command(label="設定保存...", command=self.save_config_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="フィルタ設定の編集...", command=self.edit_keywords_dialog)
        cmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        menubar.add_cascade(label="設定", menu=cmenu)
        self.root.config(menu=menubar)

        toolbar = tk.Frame(self.root); toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=12, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e3f2fd").pack(side=tk.LEFT, padx=10)

        self.notebook = ttk.Notebook(self.root); self.notebook.pack(fill=tk.BOTH, expand=True)
        self.status_var = tk.StringVar(value="Ready"); tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    def open_file(self):
        paths = filedialog.askopenfilenames()
        for p in paths: self._open_file_path(p)

    def close_tab(self):
        t = self.get_current_tab()
        if t: self.notebook.forget(t)

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        tab = LogTab(self.notebook, self, path, content)
        self.notebook.add(tab, text=os.path.basename(path))
        self.notebook.select(tab); self.apply_display_update(tab)

    # --- Merge Logic ---
    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs()]
        target_tabs = [t for t in tabs if isinstance(t, LogTab) and not t.is_merged]
        if len(target_tabs) < 2: return

        ts_len = simpledialog.askinteger("マージ", "時刻ソート用の先頭文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return

        all_entries = []
        for t in target_tabs:
            fname = os.path.basename(t.file_path)
            for line in t.original_content.splitlines():
                if line.strip(): all_entries.append((line[:ts_len], line, fname))
        all_entries.sort(key=lambda x: x[0])

        merged_content = "\n".join([x[1] for x in all_entries])
        m_tab = LogTab(self.notebook, self, "Merged", merged_content, is_merged=True)
        m_tab.source_files = [x[2] for x in all_entries] # 由来ファイルを保存
        
        self.notebook.add(m_tab, text="[マージ結果]")
        self.notebook.select(m_tab); self.apply_display_update(m_tab)

    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text=f"フィルタ: {'ON' if self.use_keyword_filter else 'OFF'}", bg="#bbdefb" if self.use_keyword_filter else "SystemButtonFace")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def apply_display_update(self, tab: LogTab):
        # 置換適用後のテキスト生成
        processed_data = tab.original_content
        if self.replace_patterns_config:
            processed_data = self._apply_replacements(processed_data)
        
        lines = processed_data.splitlines()
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append((re.compile(itm["pattern"], re.I), itm.get("comment", ""), itm.get("color", "")))
                except: pass

        final_lines, final_comments = [], []
        # マージ由来ファイルリスト（行数不一致防止のため空文字でパディング）
        src_files = tab.source_files if tab.is_merged else [""] * len(lines)

        for i, line in enumerate(lines):
            matched_cmt, matched_color, is_match = "", "", False
            for pat, cmt, color in kw_rules:
                if pat.search(line):
                    is_match, matched_cmt, matched_color = True, cmt, color
                    break
            
            if self.use_keyword_filter and not is_match: continue
            
            final_lines.append(line)
            # 由来ファイル名とコメントを結合して右側に表示
            src_name = f"[{src_files[i]}] " if src_files[i] else ""
            final_comments.append(f"{src_name}{matched_cmt}")

        tab.text.delete("1.0", tk.END); tab.text.insert("1.0", "\n".join(final_lines))
        tab.comment_text.delete("1.0", tk.END); tab.comment_text.insert("1.0", "\n".join(final_comments))
        
        self.highlight_keywords(tab, kw_rules)
        tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        for item in self.replace_patterns_config:
            if not item.get("enabled", True): continue
            try:
                # 文字列の直後に (説明) を付与するロジック
                content = re.sub(item["search"], lambda m: f"{m.group(0)}({m.expand(item['replace'])})", content, flags=re.I)
            except: pass
        return content

    def highlight_keywords(self, tab: LogTab, rules):
        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for pat_obj, cmt, color in rules:
            if not color: continue
            tag_name = f"kw_{abs(hash(pat_obj.pattern))}"
            tab.text.tag_configure(tag_name, background=color)
            start = "1.0"
            while True:
                pos = tab.text.search(pat_obj.pattern, start, stopindex=tk.END, nocase=True, regexp=True)
                if not pos: break
                # マッチした正確な長さを取得
                match_text = pat_obj.search(tab.text.get(pos, f"{pos} lineend")).group(0)
                end = f"{pos}+{len(match_text)}c"
                tab.text.tag_add(tag_name, pos, end); start = end

    # --- 以下、設定ダイアログ・プリセットメニューなどのUI復元 ---
    def create_preset_menu(self, btn, entry):
        m = tk.Menu(self.root, tearoff=0)
        presets = [("整数", r"\d+"), ("16進数", r"0x[0-9A-Fa-f]+"), ("IPアドレス", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), ("[]内", r"\[.*?\]"), ("Key=Val", r"\w+=\S+")]
        for l, r in presets: m.add_command(label=l, command=lambda t=r: entry.insert(tk.INSERT, t))
        m.tk_popup(btn.winfo_rootx(), btn.winfo_rooty() + btn.winfo_height())

    def edit_keywords_dialog(self):
        # 前述の構成通りの詳細な編集ダイアログを表示
        self._generic_edit_dialog("フィルタ設定の編集", "keywords", ["pattern", "color", "comment"])

    def edit_replace_patterns_dialog(self):
        # 前述の構成通りの詳細な編集ダイアログを表示
        self._generic_edit_dialog("説明パターンの編集", "replace_patterns", ["search", "replace"])

    def _generic_edit_dialog(self, title, config_key, fields):
        dlg = tk.Toplevel(self.root); dlg.title(title); dlg.geometry("1000x500"); dlg.grab_set()
        main_fr = tk.Frame(dlg); main_fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        canvas = tk.Canvas(main_fr); scr = tk.Scrollbar(main_fr, command=canvas.yview); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scr.pack(side=tk.RIGHT, fill=tk.Y); canvas.config(yscrollcommand=scr.set)
        inner = tk.Frame(canvas); canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.config(scrollregion=canvas.bbox("all")))

        rows = []
        def add_row(data=None):
            r = tk.Frame(inner); r.pack(fill=tk.X, pady=2)
            vars = {f: tk.StringVar(value=data.get(f, "") if data else "") for f in fields}
            vars["enabled"] = tk.BooleanVar(value=data.get("enabled", True) if data else True)
            tk.Checkbutton(r, variable=vars["enabled"]).pack(side=tk.LEFT)
            for f in fields:
                e = tk.Entry(r, textvariable=vars[f], width=25 if f != "comment" else 50)
                e.pack(side=tk.LEFT, padx=2)
                if f in ["pattern", "search"]:
                    b = tk.Button(r, text="▼", width=2); b.pack(side=tk.LEFT)
                    b.config(command=lambda btn=b, ent=e: self.create_preset_menu(btn, ent))
            tk.Button(r, text="削除", command=lambda: [r.destroy(), rows.remove(vars)]).pack(side=tk.LEFT)
            rows.append(vars)

        for d in getattr(self, f"{config_key}_config"): add_row(d)
        tk.Button(dlg, text="行を追加", command=add_row).pack(pady=5)
        def save():
            new_cfg = []
            for r in rows:
                item = {f: r[f].get() for f in fields}; item["enabled"] = r["enabled"].get()
                new_cfg.append(item)
            setattr(self, f"{config_key}_config", new_cfg)
            dlg.destroy(); t = self.get_current_tab(); 
            if t: self.apply_display_update(t)
        tk.Button(dlg, text="OK", command=save, width=10, bg="#ddd").pack(pady=5)

    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if p: self.load_config(p)
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if p: self.save_config(p)
    def load_config(self, p):
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f); self.keywords_config = d.get("keywords", []); self.replace_patterns_config = d.get("replace_patterns", [])
        t = self.get_current_tab(); 
        if t: self.apply_display_update(t)
    def save_config(self, p):
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"keywords":self.keywords_config, "replace_patterns":self.replace_patterns_config}, f, indent=2, ensure_ascii=False)

    def export_to_excel(self):
        t = self.get_current_tab(); 
        if not t: return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p: return
        try:
            l, c = t.text.get("1.0", "end-1c").splitlines(), t.comment_text.get("1.0", "end-1c").splitlines()
            h = ["<html><meta charset='utf-8'><style>td{border:1px solid #ccc; font-family:monospace;}</style><body><table>"]
            for i, line in enumerate(l):
                h.append(f"<tr><td>{i+1}</td><td><pre>{html.escape(line)}</pre></td><td>{html.escape(c[i] if i<len(c) else '')}</td></tr>")
            with open(p, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</table></body></html>")
            messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS(); app = LogViewerApp(root); root.mainloop()