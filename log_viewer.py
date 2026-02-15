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
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 2},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0}
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
    def __init__(self, master, app, path, content, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged
        self.source_files: List[str] = []

        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=800)
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

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
        self.hsb_log.config(command=self.text.xview); self.hsb_cmt.config(command=self.comment_text.xview)
        def on_mw(e):
            d = int(-1*(e.delta/120)) if e.delta else 0
            self.text.yview_scroll(d, "units"); self.comment_text.yview_scroll(d, "units"); self.linenumbers.redraw()
            return "break"
        for w in [self.text, self.comment_text]: w.bind('<MouseWheel>', on_mw)

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1450x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns_config = []
        self.use_keyword_filter = False
        self.keywords_dlg_ref = None
        self.replace_dlg_ref = None

        self._build_ui()
        if os.path.exists(self.config_path): self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        fmenu.add_separator()
        fmenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        fmenu.add_separator()
        fmenu.add_command(label="終了", command=self.root.quit)
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

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        tab = LogTab(self.notebook, self, path, content)
        self.notebook.add(tab, text=os.path.basename(path))
        self.notebook.select(tab); self.apply_display_update(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
        target_tabs = [t for t in tabs if not t.is_merged]
        if len(target_tabs) < 2: return
        
        ts_len = simpledialog.askinteger("マージ", "時刻ソート用の先頭文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return

        # ブロック認識用のルール準備
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append((re.compile(itm["pattern"], re.I), int(itm.get("extra_lines", 0))))
                except: pass

        all_blocks = [] # (sort_key, List[lines], filename)
        
        for t in target_tabs:
            fn = os.path.basename(t.file_path)
            lines = t.original_content.splitlines()
            if not lines: continue

            # 1. 有効な時刻を抽出・補完する (空白時刻の行が先頭に行くのを防ぐ)
            effective_ts = []
            last_valid_ts = ""
            for line in lines:
                ts_part = line[:ts_len]
                # 修正: 先頭が空白の行は、時刻ではなく詳細行とみなして、直前の時刻を継続させる
                if ts_part.strip() and len(line) > 0 and not line[0].isspace():
                    last_valid_ts = ts_part
                effective_ts.append(last_valid_ts)
            
            # 先頭が空白だった場合のバックフィル
            first_valid_ts = next((t for t in effective_ts if t), "0"*ts_len)
            effective_ts = [t if t else first_valid_ts for t in effective_ts]

            i = 0
            while i < len(lines):
                line = lines[i]
                if not line.strip():
                    i += 1; continue
                
                # ブロック分割判定
                extra = 0
                for pat, ex in kw_rules:
                    if pat.search(line):
                        extra = ex
                        break
                
                block_lines = lines[i : i + extra + 1]
                sort_key = effective_ts[i] # 補完された時刻をソートキーにする
                
                # 2. 時刻文字列を持たない行(インデント行など)が、設定行数を超えて続いている場合の処理
                # 直前のブロックと同じファイル由来なら、直前のブロックに結合させて「1かたまり」にする
                is_header_timestamp_empty = (len(line) > 0 and line[0].isspace())
                
                if is_header_timestamp_empty and all_blocks and all_blocks[-1][2] == fn:
                    all_blocks[-1][1].extend(block_lines)
                else:
                    all_blocks.append((sort_key, block_lines, fn))
                
                i += extra + 1

        # ソート (補完された時刻キーを使うため、インデント行も正しい位置に来る)
        all_blocks.sort(key=lambda x: x[0])

        final_merged_lines = []
        final_source_files = []
        for _, b_lines, fname in all_blocks:
            final_merged_lines.extend(b_lines)
            final_source_files.extend([fname] * len(b_lines))

        m_tab = LogTab(self.notebook, self, "Merged", "\n".join(final_merged_lines), is_merged=True)
        m_tab.source_files = final_source_files
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
        
        orig_lines = data.splitlines()
        num_lines = len(orig_lines)
        line_attrs = [None] * num_lines
        
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try:
                    kw_rules.append({
                        "regex": re.compile(itm["pattern"], re.I),
                        "comment": itm.get("comment", ""),
                        "color": itm.get("color", "#ffffff"),
                        "extra": int(itm.get("extra_lines", 0))
                    })
                except: pass

        # 行ごとのマッチング属性の決定
        for idx in range(num_lines):
            for rule in kw_rules:
                if rule["regex"].search(orig_lines[idx]):
                    for j in range(idx, min(idx + rule["extra"] + 1, num_lines)):
                        if line_attrs[j] is None: line_attrs[j] = rule
                    break

        flines, fcmts, tag_info = [], [], []
        srcs = tab.source_files if tab.is_merged else [""] * num_lines

        for i in range(num_lines):
            match = line_attrs[i]
            if self.use_keyword_filter and match is None: continue
            
            flines.append(orig_lines[i])
            src_name = f"[{srcs[i]}] " if srcs[i] else ""
            m_cmt = match["comment"] if match else ""
            fcmts.append(f"{src_name}{m_cmt}")
            if match and match["color"] != "#ffffff":
                tag_info.append((len(flines), match["color"]))

        tab.text.delete("1.0", tk.END); tab.text.insert("1.0", "\n".join(flines))
        tab.comment_text.delete("1.0", tk.END); tab.comment_text.insert("1.0", "\n".join(fcmts))
        
        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for l_num, col in tag_info:
            tname = f"kw_{col.replace('#','')}"
            tab.text.tag_configure(tname, background=col)
            tab.text.tag_add(tname, f"{l_num}.0", f"{l_num}.end")
        tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        for itm in self.replace_patterns_config:
            if itm.get("enabled", True):
                try: content = re.sub(itm["search"], lambda m: f"{m.group(0)}({m.expand(itm['replace'])})", content, flags=re.I)
                except: pass
        return content

    # --- UI Components ---
    def create_preset_menu(self, parent_btn, entry_widget):
        menu = tk.Menu(self.root, tearoff=0)
        presets = [("--- 数値 ---",None),("整数",r"\d+"),("16進",r"0x[0-9A-Fa-f]+"),("IP",r"\d{1,3}(\.\d{1,3}){3}"),("[]内",r"\[.*?\]"),("Key=Val",r"\w+=\S+")]
        for l, r in presets:
            if r is None: menu.add_separator(); menu.add_command(label=l, state="disabled")
            else: menu.add_command(label=l, command=lambda t=r: entry_widget.insert(tk.INSERT, t))
        menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())

    # --- Dialogs ---
    def edit_keywords_dialog(self):
        if self.keywords_dlg_ref and self.keywords_dlg_ref.winfo_exists(): self.keywords_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); self.keywords_dlg_ref = dlg
        dlg.title("フィルタ設定の編集")
        dlg.geometry("1150x500"); dlg.transient(self.root); dlg.grab_set()
        
        fr = tk.Frame(dlg); fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1); l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hdr = tk.Frame(l_fr); hdr.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(hdr, width=135).pack(side=tk.LEFT)
        tk.Label(hdr, text="正規表現パターン", width=30, anchor="w").pack(side=tk.LEFT, padx=5)
        tk.Frame(hdr, width=35).pack(side=tk.LEFT)
        tk.Label(hdr, text="色", width=10, anchor="w").pack(side=tk.LEFT)
        tk.Frame(hdr, width=55).pack(side=tk.LEFT)
        tk.Label(hdr, text="コメント", width=25, anchor="w").pack(side=tk.LEFT, padx=5)
        tk.Label(hdr, text="+行", width=5, anchor="w").pack(side=tk.LEFT, padx=5)

        cv = tk.Canvas(l_fr, highlightthickness=0); sc = tk.Scrollbar(l_fr, command=cv.yview)
        sf = tk.Frame(cv); cv.configure(yscrollcommand=sc.set)
        sc.pack(side=tk.RIGHT, fill=tk.Y); cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cv_win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(cv_win, width=e.width))

        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, (en, kv, cvv, cmtv, exv) in enumerate(entries):
                r = tk.Frame(sf); r.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(r, variable=en).pack(side=tk.LEFT)
                up = tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)); up.pack(side=tk.LEFT)
                dw = tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)); dw.pack(side=tk.LEFT)
                if i==0: up.config(state="disabled")
                if i==len(entries)-1: dw.config(state="disabled")
                tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                e_k = tk.Entry(r, textvariable=kv, width=32); e_k.pack(side=tk.LEFT, padx=5)
                b_h = tk.Button(r, text="▼", width=2, command=lambda b=None, e=e_k: self.create_preset_menu(b_h, e_k)); b_h.pack(side=tk.LEFT)
                tk.Entry(r, textvariable=cvv, width=8).pack(side=tk.LEFT, padx=2)
                tk.Button(r, text="色選択", command=lambda v=cvv: v.set(colorchooser.askcolor(v.get())[1] or v.get())).pack(side=tk.LEFT)
                tk.Entry(r, textvariable=cmtv, width=50).pack(side=tk.LEFT, padx=10)
                tk.Entry(r, textvariable=exv, width=4).pack(side=tk.LEFT)

        def add(k="", c="#ffffff", m="", x="0", n=True):
            entries.append((tk.BooleanVar(value=n), tk.StringVar(value=k), tk.StringVar(value=c), tk.StringVar(value=m), tk.StringVar(value=str(x)))); refresh()
        def delete(idx): del entries[idx]; refresh()
        def move(idx, d): entries[idx], entries[idx+d] = entries[idx+d], entries[idx]; refresh()
        for it in self.keywords_config: add(it.get("pattern"), it.get("color"), it.get("comment"), it.get("extra_lines", 0), it.get("enabled", True))
        if not entries: add()
        
        btn_fr = tk.Frame(fr); btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        tk.Button(btn_fr, text="行を追加", command=add, width=10).pack(pady=5)
        def save():
            self.keywords_config = [{"pattern":kv.get(),"color":cvv.get(),"comment":cmtv.get(),"extra_lines":exv.get(),"enabled":en.get()} for en,kv,cvv,cmtv,exv in entries if kv.get()]
            dlg.destroy(); t = self.get_current_tab(); 
            if t: self.apply_display_update(t)
        tk.Button(btn_fr, text="OK", command=save, width=10, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    def edit_replace_patterns_dialog(self):
        if self.replace_dlg_ref and self.replace_dlg_ref.winfo_exists(): self.replace_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); self.replace_dlg_ref = dlg
        dlg.title("説明パターンの編集")
        dlg.geometry("950x450"); dlg.grab_set()
        fr = tk.Frame(dlg); fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1); l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hdr = tk.Frame(l_fr); hdr.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(hdr, width=135).pack(side=tk.LEFT)
        tk.Label(hdr, text="正規表現パターン", width=35, anchor="w").pack(side=tk.LEFT, padx=5)
        tk.Frame(hdr, width=30).pack(side=tk.LEFT)
        tk.Label(hdr, text="説明", width=40, anchor="w").pack(side=tk.LEFT)
        cv = tk.Canvas(l_fr, highlightthickness=0); sc = tk.Scrollbar(l_fr, command=cv.yview)
        sf = tk.Frame(cv); cv.configure(yscrollcommand=sc.set)
        sc.pack(side=tk.RIGHT, fill=tk.Y); cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cv_win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(cv_win, width=e.width))
        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, (en, pv, dv) in enumerate(entries):
                r = tk.Frame(sf); r.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(r, variable=en).pack(side=tk.LEFT)
                up = tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)); up.pack(side=tk.LEFT)
                dw = tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)); dw.pack(side=tk.LEFT)
                if i==0: up.config(state="disabled")
                if i==len(entries)-1: dw.config(state="disabled")
                tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                e_p = tk.Entry(r, textvariable=pv, width=35); e_p.pack(side=tk.LEFT, padx=5)
                b_h = tk.Button(r, text="▼", width=2, command=lambda b=None, e=e_p: self.create_preset_menu(b_h, e_p)); b_h.pack(side=tk.LEFT)
                tk.Entry(r, textvariable=dv, width=60).pack(side=tk.LEFT, padx=10)
        def add(p="", d="", n=True): entries.append((tk.BooleanVar(value=n), tk.StringVar(value=p), tk.StringVar(value=d))); refresh()
        def delete(idx): del entries[idx]; refresh()
        def move(idx, d): entries[idx], entries[idx+d] = entries[idx+d], entries[idx]; refresh()
        for it in self.replace_patterns_config: add(it.get("search"), it.get("replace"), it.get("enabled", True))
        if not entries: add()
        btn_fr = tk.Frame(fr); btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        tk.Button(btn_fr, text="行を追加", command=add, width=10).pack(pady=5)
        def save():
            self.replace_patterns_config = [{"search":pv.get(),"replace":dv.get(),"enabled":en.get()} for en,pv,dv in entries if pv.get()]
            dlg.destroy(); t = self.get_current_tab(); 
            if t: self.apply_display_update(t)
        tk.Button(btn_fr, text="OK", command=save, width=10, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    # --- IO & Export ---
    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")]); 
        if p: self.load_config(p)
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json"); 
        if p:
            with open(p, "w", encoding="utf-8") as f: json.dump({"keywords":self.keywords_config, "replace_patterns":self.replace_patterns_config}, f, indent=2, ensure_ascii=False)
    def load_config(self, p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f); self.keywords_config = d.get("keywords", []); self.replace_patterns_config = d.get("replace_patterns", [])
            t = self.get_current_tab(); 
            if t: self.apply_display_update(t)
        except: pass

    def export_to_excel(self):
        tab = self.get_current_tab()
        if not tab: return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not path: return
        try:
            log_lines = tab.text.get("1.0", "end-1c").splitlines()
            cmt_lines = tab.comment_text.get("1.0", "end-1c").splitlines()
            rules = []
            for it in self.keywords_config:
                if it.get("enabled", True):
                    try: rules.append((re.compile(it["pattern"], re.I), it.get("color", "#ffffff"), int(it.get("extra_lines", 0))))
                    except: pass
            html_colors = ["#ffffff"] * len(log_lines)
            for idx in range(len(log_lines)):
                for pat, col, extra in rules:
                    if pat.search(log_lines[idx]):
                        for j in range(idx, min(idx + extra + 1, len(log_lines))): html_colors[j] = col
                        break
            h = ['<html><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:monospace;} th{background:#ddd;border:1px solid #999;} td{border:1px solid #ccc;padding:2px 4px;white-space:pre-wrap;}</style></head><body><table>']
            h.append('<thead><tr><th>Line</th><th>Log Content</th><th>Comment</th></tr></thead><tbody>')
            for i, line in enumerate(log_lines):
                c = cmt_lines[i] if i < len(cmt_lines) else ""
                h.append(f'<tr style="background:{html_colors[i]}"><td>{i+1}</td><td>{html.escape(line)}</td><td>{html.escape(c)}</td></tr>')
            with open(path, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</tbody></table></body></html>")
            messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS(); app = LogViewerApp(root); root.mainloop()