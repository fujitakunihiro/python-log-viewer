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

# --- Constants & Colors ---
VSYNC_TAG = "<VSYNC>"
VSYNC_REGEX = r"V_START|V-Sync|VIRTUAL V-SYNC|\[VIRTUAL V-SYNC\]"
VSYNC_MARKER = "--- [VIRTUAL V-SYNC] ---"
VIRTUAL_SRC_NAME = "(Virtual)"

class Tooltip:
    """Hover tooltip for displaying text on mouse over"""
    def __init__(self):
        self.tooltip = None
        self.id = None
        
    def show(self, event, text):
        """Show tooltip at mouse position"""
        if not text or not text.strip():
            self.hide()
            return
        
        # Cancel any pending hide
        if self.id:
            event.widget.after_cancel(self.id)
            self.id = None
            
        # Remove old tooltip if exists
        self.hide()
        
        # Create tooltip window
        self.tooltip = tw = tk.Toplevel(event.widget)
        tw.wm_overrideredirect(True)
        tw.wm_attributes("-topmost", True)
        
        # Create label with text
        label = tk.Label(tw, text=text, background="#ffffcc", foreground="#000000", 
                         relief=tk.SOLID, borderwidth=1, font=("Consolas", 9),
                         padx=5, pady=3, wraplength=300)
        label.pack()
        
        # Position tooltip near cursor
        x = event.x_root + 10
        y = event.y_root + 10
        tw.wm_geometry(f"+{x}+{y}")
        
    def hide(self):
        """Hide tooltip"""
        if self.tooltip:
            try:
                self.tooltip.destroy()
            except:
                pass
            self.tooltip = None

class UIColors:
    BG = "#efe6d5"          # 全体の背景（ライムストーン）
    PANEL_BG = "#ffffff"    # パネルやキャンバスの背景（クリーンな白）
    HEADER_BG = "#708090"   # ヘッダー背景（スレートグレー）
    HEADER_FG = "#ffffff"   # ヘッダーテキスト
    ACCENT = "#708090"      # アクセント1（スレートグレー）
    ACCENT_HOVER = "#5c6a78"# アクセント1のホバー
    ROSE = "#d4a3b3"        # アクセント2（マカロンローズ）
    ROSE_HOVER = "#c291a1"  # アクセント2のホバー
    TEXT = "#4a4f54"        # 基本テキスト
    TEXT_BG = "#ffffff"     # テキストエリア背景
    BORDER = "#d1cbbd"      # 各種境界線

def apply_french_theme(widget):
    """ダイアログ内の標準ウィジェットにフレンチテーマを一括適用するヘルパー"""
    if isinstance(widget, tk.Button) or isinstance(widget, tk.Entry) or isinstance(widget, tk.Text) or isinstance(widget, tk.Canvas):
        return
    try:
        if isinstance(widget, (tk.Frame, tk.LabelFrame)):
            widget.configure(bg=UIColors.BG)
        elif isinstance(widget, tk.Label):
            widget.configure(bg=UIColors.BG, fg=UIColors.TEXT)
        elif isinstance(widget, (tk.Radiobutton, tk.Checkbutton)):
            widget.configure(bg=UIColors.BG, fg=UIColors.TEXT, activebackground=UIColors.BG, selectcolor=UIColors.PANEL_BG)
    except tk.TclError:
        pass
    for child in widget.winfo_children():
        apply_french_theme(child)

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "keywords":[
        {"file_pattern": ".*", "pattern": r".*ERROR.*", "color": "#f8d7da", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"file_pattern": ".*", "pattern": "WARN",       "color": "#fff3cd", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 2},
        {"file_pattern": ".*", "pattern": "INFO",       "color": "#d1e7dd", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0},
        {"file_pattern": ".*", "pattern": r"--- \[VIRTUAL V-SYNC\] ---", "color": "#e2d9f3", "comment": "仮想V同期タイミング", "enabled": True, "extra_lines": 0},
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
        "start_time_val": "0.0"
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
            self.create_text(40, y, anchor="ne", text=linenum, fill="#888888", font=("Consolas", 10))
            i = self.text_widget.index(f"{i}+1line")

class LogTab(tk.Frame):
    def __init__(self, master, app, path, content, source_files_list=None, source_file_paths=None, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged
        
        self.source_file_names = source_files_list if source_files_list else ([os.path.basename(path)] if path else[])
        # Store full paths for each source file (for tooltip display)
        self.source_file_paths = source_file_paths if source_file_paths else {}
        if not self.source_file_paths and path and path != "Merged":
            self.source_file_paths = {os.path.basename(path): path}
        
        self.line_source_map: List[str] =[]
        self.status_texts: Dict[str, tk.Text] = {}
        self.status_frames: Dict[str, tk.Frame] = {}  # 区間フレームを保存
        self.configure(bg=UIColors.BG)
        self._create_layout()

    def _create_layout(self):
        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=6, bg=UIColors.BORDER, bd=0)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=650)
        
        header_text = "[View]" if self.is_merged else (self.source_file_names[0] if self.source_file_names else "Log Content")
        tk.Label(left_frame, text=header_text, bg=UIColors.HEADER_BG, fg=UIColors.HEADER_FG, font=("Yu Gothic UI", 10, "bold"), relief=tk.FLAT, pady=6).pack(side=tk.TOP, fill=tk.X)
        
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.text = tk.Text(left_frame, wrap=tk.NONE, xscrollcommand=self.hsb_log.set, bg=UIColors.TEXT_BG, fg=UIColors.TEXT, relief=tk.FLAT, bd=0, font=("Consolas", 10))
        self.text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.text.tag_config("found", background=UIColors.ACCENT_HOVER, foreground="white")
        
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg=UIColors.BG, highlightthickness=0)
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        
        self.timediff_text = tk.Text(left_frame, width=12, wrap=tk.NONE, bg="#faf9f6", fg="#999999", relief=tk.FLAT, bd=0, font=("Consolas", 10))
        self.timediff_text.tag_configure("sel", background="#cce8ff", foreground="black")
        if not self.is_merged:
            self.timediff_text.pack(side=tk.LEFT, fill=tk.Y)

        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)
        
        cmt_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
        self.paned_window.add(cmt_frame, minsize=50, stretch="always", width=250)
        
        self.hsb_cmt = tk.Scrollbar(cmt_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(cmt_frame, text="Comment / Tags", bg=UIColors.HEADER_BG, fg=UIColors.HEADER_FG, font=("Yu Gothic UI", 10, "bold"), relief=tk.FLAT, pady=6).pack(side=tk.TOP, fill=tk.X)
        
        self.comment_text = tk.Text(cmt_frame, wrap=tk.NONE, bg=UIColors.TEXT_BG, fg="#5c7a99", xscrollcommand=self.hsb_cmt.set, relief=tk.FLAT, bd=0, font=("Consolas", 10))
        self.comment_text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)
        
        for fname in self.source_file_names:
            st_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
            self.status_frames[fname] = st_frame  # フレームを保存（add の前に保存）
            # Advanced ON時のみ paned_window に追加
            if self.app.advance_mode:
                self.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
            tk.Label(st_frame, text=f"{fname}の区間", bg=UIColors.HEADER_BG, fg=UIColors.HEADER_FG, font=("Yu Gothic UI", 9, "bold"), relief=tk.FLAT, pady=6).pack(side=tk.TOP, fill=tk.X)
            
            hsb = tk.Scrollbar(st_frame, orient=tk.HORIZONTAL)
            hsb.pack(side=tk.BOTTOM, fill=tk.X)
            
            st_text = tk.Text(st_frame, wrap=tk.NONE, bg="#faf9f6", fg=UIColors.TEXT, xscrollcommand=hsb.set, relief=tk.FLAT, bd=0, font=("Consolas", 10))
            st_text.tag_configure("sel", background="#cce8ff", foreground="black")
            st_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hsb.config(command=st_text.xview)
            self.status_texts[fname] = st_text
            
        self.all_texts =[self.text, self.timediff_text, self.comment_text] + list(self.status_texts.values())
        
        # カーソル行のハイライト設定
        for w in self.all_texts:
            w.tag_configure("cursor_line", background="#fff0f5", underline=True)
            w.bind('<ButtonRelease-1>', self.update_cursor_line)
            w.bind('<KeyRelease>', self.update_cursor_line)
        
        # === 完全なスクロール同期ロジック ===
        self.syncing = False
        def on_scroll_set(*args):
            if self.syncing: return
            self.syncing = True
            try:
                self.vsb.set(*args)
                for t in self.all_texts:
                    t.yview_moveto(args[0])
                self.linenumbers.redraw()
            finally:
                self.syncing = False

        for t in self.all_texts:
            t.configure(yscrollcommand=on_scroll_set)

        def sync_yview(*args):
            for t in self.all_texts:
                t.yview(*args)
            self.linenumbers.redraw()
            
        self.vsb.config(command=sync_yview)
        
        def on_mw(e):
            d = int(-1*(e.delta/120)) if e.delta else 0
            for t in self.all_texts: 
                t.yview_scroll(d, "units")
            self.linenumbers.redraw()
            return "break"
            
        for t in self.all_texts: 
            t.bind('<MouseWheel>', on_mw)

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
        self.root.configure(bg=UIColors.BG)
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=UIColors.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=UIColors.BORDER, foreground=UIColors.TEXT, padding=[15, 5], font=("Yu Gothic UI", 9, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", UIColors.PANEL_BG)], foreground=[("selected", "#000000")])
        
        self.keywords_config =[x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.sections_config =[x.copy() for x in DEFAULT_CONFIG["sections"]]
        self.replace_patterns_config =[]
        self.vsync_config = DEFAULT_CONFIG["vsync_auto_insert"].copy()
        
        self.use_keyword_filter = False
        self.show_vsync_lines = False 
        self.advance_mode = False
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
            try:
                self.load_config(self.config_path)
            except Exception as e:
                print(f"Failed to load config: {e}")
        else:
            # config.jsonが存在しない場合は初期設定を保存
            try:
                self.save_config(self.config_path)
            except:
                pass
            
        self.toggle_vsync_display(force_update=True)
        self.toggle_filter(force_update=True)

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
        self.cmenu = cmenu
        cmenu.add_command(label="設定読み込み...", command=self.load_config_dialog)
        cmenu.add_command(label="設定保存...", command=self.save_config_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="フィルタ設定の編集 (行単位)...", command=self.edit_keywords_dialog)
        # 「区間設定の編集」と「V周期設定」は Advanced ON時のみ追加
        cmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        cmenu.add_separator()
        # Advancedモード
        cmenu.add_command(label="Advancedモード", command=self.toggle_advance_mode)
        menubar.add_cascade(label="設定", menu=cmenu)
        
        self.root.config(menu=menubar)
        
        toolbar = tk.Frame(self.root, bg=UIColors.BG)
        toolbar.pack(fill=tk.X, padx=5, pady=8)
        
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=14, command=self.toggle_filter, bg=UIColors.ACCENT, fg="white", relief=tk.FLAT, font=("Yu Gothic UI", 9, "bold"), activebackground=UIColors.ACCENT_HOVER, activeforeground="white", cursor="hand2")
        self.btn_kw_filter.pack(side=tk.LEFT, padx=5)
        
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#ffffff", fg=UIColors.TEXT, relief=tk.FLAT, font=("Yu Gothic UI", 9, "bold"), activebackground=UIColors.BORDER, cursor="hand2", padx=10).pack(side=tk.LEFT, padx=10)
        
        self.btn_vsync_toggle = tk.Button(toolbar, text="仮想V周期表示: ON", width=18, command=self.toggle_vsync_display, bg=UIColors.ROSE, fg="white", relief=tk.FLAT, font=("Yu Gothic UI", 9, "bold"), activebackground=UIColors.ROSE_HOVER, activeforeground="white", cursor="hand2")
        # Advanced OFF時は非表示のため、pack は toggle_advance_mode()で行う
        
        self.lbl_vsync_info = tk.Label(toolbar, text="", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9))
        # Advanced OFF時は非表示のため、pack は toggle_advance_mode()で行う
        self._update_vsync_info_label()
        
        self.btn_advance = tk.Button(toolbar, text="Advanced: OFF", width=14, command=self.toggle_advance_mode, bg=UIColors.BORDER, fg=UIColors.TEXT, relief=tk.FLAT, font=("Yu Gothic UI", 9, "bold"), activebackground=UIColors.ACCENT_HOVER, cursor="hand2")
        self.btn_advance.pack(side=tk.RIGHT, padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind tooltip events to notebook tabs
        self.notebook.bind('<Motion>', self._on_notebook_motion)
        self.notebook.bind('<Leave>', self._on_notebook_leave)
        
        # Bind drag-drop events for tab reordering
        self.notebook.bind('<Button-1>', self._on_tab_press)
        self.notebook.bind('<ButtonRelease-1>', self._on_tab_release)
        
        self.notebook_tooltip = Tooltip()
        self._dragged_tab_idx = None
        
        self.status_var = tk.StringVar(value="準備完了")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9)).pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=2)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e:[self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None
    
    def _on_notebook_motion(self, event):
        """Show tooltip when hovering over notebook tabs"""
        try:
            # Get which tab is at the cursor position
            tab_id = self.notebook.index(f"@{event.x},{event.y}")
            if tab_id is None:
                self.notebook_tooltip.hide()
                return
            
            # Get the tab widget
            tab = self.notebook.nametowidget(self.notebook.tabs()[tab_id])
            
            if isinstance(tab, LogTab):
                # Get file path
                if tab.file_path and tab.file_path != "Merged":
                    self.notebook_tooltip.show(event, tab.file_path)
                else:
                    self.notebook_tooltip.hide()
            else:
                self.notebook_tooltip.hide()
        except:
            self.notebook_tooltip.hide()
    
    def _on_notebook_leave(self, event):
        """Hide tooltip when mouse leaves notebook"""
        self.notebook_tooltip.hide()
    
    def _on_tab_press(self, event):
        """Record which tab is being dragged"""
        try:
            self._dragged_tab_idx = self.notebook.index(f"@{event.x},{event.y}")
        except:
            self._dragged_tab_idx = None
    
    def _on_tab_release(self, event):
        """Handle tab reordering on mouse release"""
        if self._dragged_tab_idx is None:
            return
        
        try:
            drop_idx = self.notebook.index(f"@{event.x},{event.y}")
        except:
            self._dragged_tab_idx = None
            return
        
        # If dropped on same tab or invalid position, do nothing
        if drop_idx is None or drop_idx == self._dragged_tab_idx:
            self._dragged_tab_idx = None
            return
        
        # Get tab ID and move it
        try:
            tabs = list(self.notebook.tabs())
            dragged_tab_id = tabs[self._dragged_tab_idx]

            # Resolve actual widget for the dragged tab
            dragged_widget = self.notebook.nametowidget(dragged_tab_id)

            # Preserve tab options (text, image, compound, etc.) if any
            try:
                tab_opts = self.notebook.tab(dragged_tab_id)
            except Exception:
                tab_opts = {}

            # Remove the tab (keeps the widget alive)
            try:
                self.notebook.forget(dragged_widget)
            except Exception:
                # fallback: forget by id
                try:
                    self.notebook.forget(dragged_tab_id)
                except Exception:
                    pass

            # Re-insert at new position
            new_idx = drop_idx if drop_idx < self._dragged_tab_idx else drop_idx - 1
            try:
                # Insert the widget and restore its text (and other options if present)
                if 'text' in tab_opts:
                    self.notebook.insert(new_idx, dragged_widget, text=tab_opts.get('text', ''))
                else:
                    self.notebook.insert(new_idx, dragged_widget)

                # Restore other tab options (safely)
                try:
                    restore = {k: v for k, v in tab_opts.items() if k != 'text'}
                    if restore:
                        self.notebook.tab(dragged_widget, **restore)
                except Exception:
                    pass

                # Reselect the moved tab
                self.notebook.select(dragged_widget)
            except Exception:
                # If insertion by widget fails, attempt a fallback using tab id
                try:
                    self.notebook.insert(new_idx, dragged_tab_id)
                    self.notebook.select(dragged_tab_id)
                except Exception:
                    pass
        except:
            pass
        finally:
            self._dragged_tab_idx = None

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
            tab = LogTab(self.notebook, self, path, new_content, source_files_list=[fname], source_file_paths={fname: path}, is_merged=True)
            tab.line_source_map = new_src_map
            self.notebook.add(tab, text=fname)
            self.notebook.select(tab)
            self.apply_display_update(tab)
        else:
            tab = LogTab(self.notebook, self, path, content, source_files_list=[fname], source_file_paths={fname: path})
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
        src_paths_map = {}  # Map source names to full paths
        
        for t in target_tabs:
            fn = os.path.basename(t.file_path)
            if fn not in unique_srcs: 
                unique_srcs.append(fn)
                src_paths_map[fn] = t.file_path  # Store full path
            
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
        
        seen_virtual_lines = set()
        
        for skey, bl, src_name in all_blocks:
            if src_name == VIRTUAL_SRC_NAME and len(bl) == 1 and (VSYNC_MARKER in bl[0] or "[VIRTUAL TIMER]" in bl[0]):
                vt_key = bl[0].strip()
                if vt_key in seen_virtual_lines:
                    continue
                seen_virtual_lines.add(vt_key)
                
            final_lines.extend(bl)
            final_src.extend([src_name] * len(bl))
            
        m_tab = LogTab(self.notebook, self, "Merged", "\n".join(final_lines), source_files_list=unique_srcs, source_file_paths=src_paths_map, is_merged=True)
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
        dlg.geometry("400x180")
        dlg.configure(bg=UIColors.BG)
        self.vsync_settings_dlg_ref = dlg
        
        conf = self.vsync_config
        
        tk.Label(dlg, text="V周期(仮想)挿入の起点とタイミングを設定します。", anchor="w", font=("Yu Gothic UI", 9, "bold")).pack(pady=10, padx=10, fill=tk.X)

        frame_start = tk.LabelFrame(dlg, text="開始設定", font=("Yu Gothic UI", 9, "bold"), bg=UIColors.BG)
        frame_start.pack(fill=tk.X, padx=10, pady=(5, 5))
        
        f_start_time = tk.Frame(frame_start, bg=UIColors.BG)
        f_start_time.pack(anchor="w", padx=5, pady=5)
        tk.Label(f_start_time, text="指定した時刻(秒)から強制開始:", bg=UIColors.BG, fg=UIColors.TEXT).pack(side=tk.LEFT)
        e_start_time = tk.Entry(f_start_time, width=15, relief=tk.SOLID, bd=1, highlightthickness=0)
        e_start_time.pack(side=tk.LEFT, padx=5)
        e_start_time.insert(0, str(conf.get("start_time_val", "0.0")))

        f_manual = tk.Frame(frame_start, bg=UIColors.BG)
        f_manual.pack(anchor="w", padx=5, pady=5)
        tk.Label(f_manual, text="挿入間隔 (ms):", bg=UIColors.BG, fg=UIColors.TEXT).pack(side=tk.LEFT)
        e_ms = tk.Entry(f_manual, width=10, relief=tk.SOLID, bd=1, highlightthickness=0)
        e_ms.pack(side=tk.LEFT, padx=5)
        e_ms.insert(0, str(conf.get("manual_ms", 16.666)))
        
        apply_french_theme(dlg)

        def save_conf():
            try: ms = float(e_ms.get())
            except: ms = 16.666
            
            self.vsync_config = {
                "enabled": True, 
                "time_pattern": r"^\[?\s*(\d+(?:\.\d+)?)\]?",
                "manual_ms": ms,
                "start_time_val": e_start_time.get()
            }
            messagebox.showinfo("保存", "設定は次回ファイルオープン時から適用されます。保存するには『設定 > 設定保存...』を選択してください。")
            self._update_vsync_info_label()
            dlg.destroy()

        btn_box = tk.Frame(dlg, bg=UIColors.BG)
        btn_box.pack(pady=10, fill=tk.X)
        tk.Button(btn_box, text="OK", command=save_conf, bg=UIColors.ROSE, fg="white", font=("Yu Gothic UI", 9, "bold"), relief=tk.FLAT, cursor="hand2", width=15).pack(side=tk.RIGHT, padx=10)

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
    
    def save_config(self, filepath=None):
        """configを保存（ダイアログなし）"""
        self.save_config_dialog_silent(filepath)

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
        start_time_val_str = self.vsync_config.get("start_time_val", "0.0")
        
        start_time = None
        start_line_idx = -1
        
        try:
            start_time = float(start_time_val_str)
            for i, ts in enumerate(timestamps_temp):
                if ts is not None and abs(ts - start_time) < 0.000001:
                    start_line_idx = i
                    break
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
                    lines_v.append(line + "  <<<[V-SYNC 起点]")
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
                    v_line = f"{format_sec(exp_ts)} ---[VIRTUAL TIMER] Wait Time {dur_ms}ms End ---"
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
            v_line = f"{format_sec(exp_ts)} ---[VIRTUAL TIMER] Wait Time {dur_ms}ms End ---"
            lines_final.append(v_line)
            src_map_final.append(VIRTUAL_SRC_NAME)

        return "\n".join(lines_final), src_map_final

    # --- Filter & Display ---
    def toggle_filter(self, force_update=False):
        if not force_update:
            self.use_keyword_filter = not self.use_keyword_filter
        if self.use_keyword_filter:
            self.btn_kw_filter.config(text="フィルタ: ON", bg=UIColors.ROSE, activebackground=UIColors.ROSE_HOVER)
        else:
            self.btn_kw_filter.config(text="フィルタ: OFF", bg=UIColors.ACCENT, activebackground=UIColors.ACCENT_HOVER)
        
        if not force_update:
            t = self.get_current_tab()
            if t: self.apply_display_update(t)

    def toggle_vsync_display(self, force_update=False):
        if not force_update:
            self.show_vsync_lines = not self.show_vsync_lines
        if self.show_vsync_lines:
            self.btn_vsync_toggle.config(text="仮想V周期表示: ON", bg=UIColors.ROSE, activebackground=UIColors.ROSE_HOVER)
        else:
            self.btn_vsync_toggle.config(text="仮想V周期表示: OFF", bg=UIColors.ACCENT, activebackground=UIColors.ACCENT_HOVER)
        
        self._update_vsync_info_label()
            
        if not force_update:
            t = self.get_current_tab()
            if t: self.apply_display_update(t)
    
    def toggle_advance_mode(self):
        self.advance_mode = not self.advance_mode
        if self.advance_mode:
            self.btn_advance.config(text="Advanced: ON", bg=UIColors.ROSE, activebackground=UIColors.ROSE_HOVER)
        else:
            self.btn_advance.config(text="Advanced: OFF", bg=UIColors.BORDER, activebackground=UIColors.ACCENT_HOVER)
        
        # メニュー項目を追加/削除
        try:
            if self.advance_mode:
                # Advanced ON時：「区間設定の編集」と「V周期設定」を追加
                self.cmenu.insert(4, "command", label="区間設定の編集 (開始-終了)...", command=self.edit_sections_dialog)
                self.cmenu.insert(5, "separator")
                self.cmenu.insert(7, "command", label="V周期(仮想)挿入の設定...", command=self.open_vsync_settings_dialog)
                self.cmenu.insert(8, "separator")
            else:
                # Advanced OFF時：メニュー項目を削除
                # 逆順で削除（インデックスがずれないようにするため）
                self.cmenu.delete(8)  # separator
                self.cmenu.delete(7)  # V周期設定
                self.cmenu.delete(5)  # separator
                self.cmenu.delete(4)  # 区間設定の編集
        except:
            pass
        
        # V周期表示ボタンを表示/非表示
        if self.advance_mode:
            # Advanced ON時：V周期ボタン表示
            self.btn_vsync_toggle.pack(side=tk.LEFT, padx=5)
            self.lbl_vsync_info.pack(side=tk.LEFT, padx=10)
        else:
            # Advanced OFF時：V周期ボタン非表示
            self.btn_vsync_toggle.pack_forget()
            self.lbl_vsync_info.pack_forget()
        
        # すべてのタブの区間フレームを追加/削除
        for tab_idx in range(len(self.notebook.tabs())):
            try:
                tab = self.notebook.nametowidget(self.notebook.tabs()[tab_idx])
                if isinstance(tab, LogTab):
                    for fn, st_frame in tab.status_frames.items():
                        if self.advance_mode:
                            # Advanced ON：フレームを paned_window に追加
                            try:
                                tab.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
                            except:
                                pass  # 既に追加されている場合
                        else:
                            # Advanced OFF：フレームを paned_window から削除
                            try:
                                tab.paned_window.remove(st_frame)
                            except:
                                pass  # 既に削除されている場合
            except:
                pass
        
        # 現在のタブを更新して区間情報を再表示
        t = self.get_current_tab()
        if t: self.apply_display_update(t)
    
    def _update_vsync_info_label(self):
        start_time = self.vsync_config.get("start_time_val", "0.0")
        manual_ms = self.vsync_config.get("manual_ms", 16.666)
        self.lbl_vsync_info.config(text=f"起点: {start_time}秒 / 間隔: {manual_ms}ms")

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
        ml_rules =[]  # 複数行マッチ用ルール
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try:
                    extra_lines = int(itm.get("extra_lines", 0))
                    # +行が1以上の場合、複数行マッチとして処理
                    is_multiline = extra_lines >= 1
                    flags = re.I | (re.DOTALL if is_multiline else 0)
                    
                    rule = {
                        "file_pat_re": re.compile(itm.get("file_pattern", ".*") or ".*", re.I),
                        "regex": re.compile(itm["pattern"], flags),
                        "comment": itm.get("comment", ""),
                        "color": itm.get("color", "#ffffff"),
                        "extra": extra_lines,
                        "multiline": is_multiline
                    }
                    
                    if is_multiline:
                        ml_rules.append(rule)
                    else:
                        kw_rules.append(rule)
                except: 
                    pass
                
        has_timer_rule = any("VIRTUAL TIMER" in str(r.get("pattern", "")) for r in self.keywords_config)
        if not has_timer_rule:
            kw_rules.append({
                "file_pat_re": re.compile(".*"),
                "regex": re.compile(r"\[VIRTUAL TIMER\]", re.I),
                "comment": "タイマー満了",
                "color": "#ffe8d6",
                "extra": 0,
                "multiline": False
            })

        # 複数行マッチの処理
        full_text = "\n".join(lines)
        multiline_matches = {}  # {行番号: ルールインデックス} の辞書
        
        for rule_idx, ml_rule in enumerate(ml_rules):
            try:
                # 複数行正規表現マッチを実行
                matches_found = list(ml_rule["regex"].finditer(full_text))
                pattern_str = ml_rule["regex"].pattern
                print(f"[DEBUG] Rule {rule_idx}: pattern='{pattern_str}' found {len(matches_found)} matches")
                
                for match in matches_found:
                    start_pos = match.start()
                    end_pos = match.end()
                    
                    # 開始位置から行番号を計算
                    start_line = full_text[:start_pos].count("\n")
                    end_line = full_text[:end_pos].count("\n")
                    
                    print(f"  Match: start_line={start_line}, end_line={end_line}")
                    print(f"  Match text: {repr(match.group()[:50])}")
                    
                    # ファイルパターンチェック
                    file_pattern_ok = False
                    for src_idx in range(start_line, min(end_line + 1, len(srcs))):
                        src = srcs[src_idx]
                        if ml_rule["file_pat_re"].search(src):
                            file_pattern_ok = True
                            print(f"    src_idx={src_idx}, src='{src}' -> OK")
                            break
                        else:
                            print(f"    src_idx={src_idx}, src='{src}' -> NOT OK")
                    
                    if not file_pattern_ok:
                        print(f"  File pattern check FAILED")
                        continue
                    
                    print(f"  File pattern check PASSED")
                    
                    # マッチの開始行から「extra_lines」分の行を色付け対象に追加
                    # +行が設定されていればそれを使用、なければマッチ範囲全体を使用
                    if ml_rule["extra"] > 0:
                        # +行が指定されている場合
                        color_end = min(start_line + ml_rule["extra"] + 1, len(lines))
                    else:
                        # +行が0の場合、マッチ範囲全体を色付け
                        color_end = min(end_line + 1, len(lines))
                    
                    for idx in range(start_line, color_end):
                        if idx not in multiline_matches:
                            multiline_matches[idx] = rule_idx
            except Exception as e:
                print(f"Multiline regex error: {e}")

        # マッチして色付けを実施
        for idx, rule_idx in multiline_matches.items():
            if idx < len(line_attrs) and rule_idx < len(ml_rules):
                ml_rule = ml_rules[rule_idx]
                if line_attrs[idx]["priority"] < 20:
                    line_attrs[idx]["color"] = ml_rule["color"]
                    base_cmt = line_attrs[idx]["comment"]
                    new_cmt = ml_rule["comment"]
                    line_attrs[idx]["comment"] = f"{base_cmt} {new_cmt}".strip()
                    line_attrs[idx]["priority"] = 20

        for idx in range(len(lines)):
            if "<<< [V-SYNC 起点]" in lines[idx]:
                if line_attrs[idx]["priority"] < 30:
                    line_attrs[idx]["color"] = UIColors.ROSE 
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
        is_visible =[True] * len(lines)
        
        for i in range(len(lines)):
            if not self.show_vsync_lines and VSYNC_MARKER in lines[i]:
                is_visible[i] = False
            else:
                attr = line_attrs[i]
                if self.use_keyword_filter:
                    if "[VIRTUAL TIMER]" in lines[i] or "<<< [V-SYNC 起点]" in lines[i]:
                        is_visible[i] = True 
                    elif attr["priority"] == 0: 
                        is_visible[i] = False
                    elif re_vsync.search(lines[i]):
                        is_in_section = any(status_buffers[fn][i][0] != "" for fn in tab.source_file_names)
                        if not is_in_section:
                            is_visible[i] = False
                            
        if self.use_keyword_filter and self.show_vsync_lines:
            vsync_to_show = set()
            for idx, vis in enumerate(is_visible):
                if vis and not re_vsync.search(lines[idx]):
                    for j in range(idx - 1, -1, -1):
                        if re_vsync.search(lines[j]):
                            vsync_to_show.add(j)
                            break
                    for j in range(idx + 1, len(lines)):
                        if re_vsync.search(lines[j]):
                            vsync_to_show.add(j)
                            break
            for j in vsync_to_show:
                is_visible[j] = True
        
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
        
        # Advanced モード時のみ区間情報を表示
        if self.advance_mode:
            # Advanced ON時：区間フレームの内容を更新
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
        self.find_window_ref.configure(bg=UIColors.BG)
        self.find_window_ref.transient(self.root) 

        tk.Label(self.find_window_ref, text="検索文字列:", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9, "bold")).pack(pady=(10, 0))
        
        entry = tk.Entry(self.find_window_ref, width=40, relief=tk.SOLID, bd=1, highlightthickness=0)
        entry.pack(pady=5, padx=10)
        entry.insert(0, self.last_search_keyword)
        entry.select_range(0, tk.END)
        entry.focus_set()

        btn_frame = tk.Frame(self.find_window_ref, bg=UIColors.BG)
        btn_frame.pack(pady=10)

        def do_find_next():
            self.last_search_keyword = entry.get()
            self.find_next()

        def do_find_prev():
            self.last_search_keyword = entry.get()
            self.find_prev()

        tk.Button(btn_frame, text="次を検索 (Enter)", command=do_find_next, bg=UIColors.ACCENT, fg="white", relief=tk.FLAT, font=("Yu Gothic UI", 9, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="前を検索 (Shift+Ent)", command=do_find_prev, bg=UIColors.ACCENT, fg="white", relief=tk.FLAT, font=("Yu Gothic UI", 9, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=5)

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
        dlg.geometry("1400x550")
        dlg.configure(bg=UIColors.BG)
        setattr(self, ref_attr, dlg)
        
        fr = tk.Frame(dlg, bg=UIColors.BG)
        fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        l_fr = tk.Frame(fr, bg=UIColors.BG, relief=tk.FLAT, highlightbackground=UIColors.BORDER, highlightthickness=1)
        l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        wrapper = tk.Frame(l_fr, bg=UIColors.BG)
        wrapper.pack(fill=tk.BOTH, expand=True)
        
        hdr = tk.Frame(wrapper, bg=UIColors.HEADER_BG)
        hdr.pack(fill=tk.X)
        
        cv = tk.Canvas(wrapper, bg=UIColors.PANEL_BG, highlightthickness=0)
        sc_y = tk.Scrollbar(wrapper, orient=tk.VERTICAL, command=cv.yview)
        sc_x = tk.Scrollbar(wrapper, orient=tk.HORIZONTAL, command=cv.xview)
        sf = tk.Frame(cv, bg=UIColors.PANEL_BG)
        cv.configure(yscrollcommand=sc_y.set, xscrollcommand=sc_x.set)
        
        sc_y.pack(side=tk.RIGHT, fill=tk.Y)
        sc_x.pack(side=tk.BOTTOM, fill=tk.X)
        cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        win = cv.create_window((0,0), window=sf, anchor="nw")
        
        def on_configure(e):
            cv.configure(scrollregion=cv.bbox("all"))
        sf.bind("<Configure>", on_configure)

        col_defs =[]
        col_idx = 1
        col_defs.append((0, "btn", "", 135))
        for f in fields:
            if f == "file_pattern": col_defs.append((col_idx, f, "対象ファイル(正規表現)", 145))
            elif f == "pattern": col_defs.append((col_idx, f, "正規表現", 165))
            elif f == "search": col_defs.append((col_idx, f, "検索文字列", 165))
            elif f == "name": col_defs.append((col_idx, f, "区間名", 115))
            elif f == "start": col_defs.append((col_idx, f, "【開始】開始パターン", 115))
            elif f == "start_wait": col_defs.append((col_idx, f, "【開始】+V待", 45))
            elif f == "end": col_defs.append((col_idx, f, "【終了】終了パターン", 145))
            elif f == "end_wait": col_defs.append((col_idx, f, "【終了】+V待", 45))
            elif f == "duration_ms": col_defs.append((col_idx, f, "【終了】持続(ms)", 95))
            elif f == "color": col_defs.append((col_idx, f, "色", 105))
            elif f == "replace": col_defs.append((col_idx, f, "置換/説明", 165))
            elif f == "comment": col_defs.append((col_idx, f, "コメント", 145))
            elif f == "extra_lines": col_defs.append((col_idx, f, "+行", 45))
            col_idx += 1

        for c_idx, c_id, c_txt, c_w in col_defs:
            h_cell = tk.Frame(hdr, bg=UIColors.HEADER_BG, width=c_w, height=28)
            h_cell.pack_propagate(False)
            h_cell.grid(row=0, column=c_idx, sticky="w", padx=2, pady=2)
            if c_txt:
                tk.Label(h_cell, text=c_txt, bg=UIColors.HEADER_BG, fg=UIColors.HEADER_FG, font=("Yu Gothic UI", 9, "bold"), anchor="w").pack(side=tk.LEFT, fill=tk.BOTH)

        entries =[]
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, item in enumerate(entries):
                f_btn = tk.Frame(sf, bg=UIColors.PANEL_BG, width=135, height=28)
                f_btn.pack_propagate(False)
                f_btn.grid(row=i, column=0, sticky="w", padx=2, pady=2)
                
                tk.Checkbutton(f_btn, variable=item["enabled"], bg=UIColors.PANEL_BG, activebackground=UIColors.PANEL_BG).pack(side=tk.LEFT)
                tk.Button(f_btn, text="↑", width=2, command=lambda idx=i: move(idx, -1), bg=UIColors.BORDER, fg=UIColors.TEXT, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=1)
                tk.Button(f_btn, text="↓", width=2, command=lambda idx=i: move(idx, 1), bg=UIColors.BORDER, fg=UIColors.TEXT, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=1)
                tk.Button(f_btn, text="削除", width=3, command=lambda idx=i: delete(idx), bg="#e8c5c5", fg=UIColors.TEXT, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=2)
                
                for c_idx, c_id, c_txt, c_w in col_defs:
                    if c_id == "btn": continue
                    
                    f_cell = tk.Frame(sf, bg=UIColors.PANEL_BG, width=c_w, height=28)
                    f_cell.pack_propagate(False)
                    f_cell.grid(row=i, column=c_idx, sticky="w", padx=2, pady=2)
                    
                    if c_id == "file_pattern":
                        tk.Entry(f_cell, textvariable=item["file_pattern"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "pattern":
                        tk.Entry(f_cell, textvariable=item["pattern"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "search":
                        tk.Entry(f_cell, textvariable=item["search"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "name":
                        tk.Entry(f_cell, textvariable=item["name"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "start":
                        tk.Entry(f_cell, textvariable=item["start"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "start_wait":
                        tk.Checkbutton(f_cell, variable=item["start_wait"], bg=UIColors.PANEL_BG, activebackground=UIColors.PANEL_BG).pack(side=tk.LEFT)
                    elif c_id == "end":
                        tk.Entry(f_cell, textvariable=item["end"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                        if key == "sections":
                             tk.Button(f_cell, text="V", width=4, command=lambda v=item["end"]: v.set(VSYNC_TAG), bg=UIColors.ROSE, fg="white", relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, fill=tk.Y, padx=1)
                    elif c_id == "end_wait":
                        tk.Checkbutton(f_cell, variable=item["end_wait"], bg=UIColors.PANEL_BG, activebackground=UIColors.PANEL_BG).pack(side=tk.LEFT)
                    elif c_id == "duration_ms":
                        tk.Entry(f_cell, textvariable=item["duration_ms"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "color":
                        tk.Entry(f_cell, textvariable=item["color"], width=7, relief=tk.SOLID, bd=1, highlightthickness=0).pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                        tk.Button(f_cell, text="色", command=lambda v=item["color"]: v.set(colorchooser.askcolor(v.get())[1] or v.get()), bg=UIColors.ACCENT, fg="white", relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, fill=tk.Y, padx=1)
                    elif c_id == "replace":
                        tk.Entry(f_cell, textvariable=item["replace"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "comment":
                        tk.Entry(f_cell, textvariable=item["comment"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)
                    elif c_id == "extra_lines":
                        tk.Entry(f_cell, textvariable=item["extra_lines"], relief=tk.SOLID, bd=1, highlightthickness=0).pack(fill=tk.BOTH, expand=True)

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

        btn_fr = tk.Frame(fr, bg=UIColors.BG, width=250)
        btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        btn_fr.pack_propagate(False)
        tk.Button(btn_fr, text="行を追加", command=add, width=20, height=2, bg=UIColors.ACCENT, fg="white", font=("Yu Gothic UI", 9, "bold"), relief=tk.FLAT, cursor="hand2").pack(pady=5)
        
        info_text = ""
        if key == "sections":
            info_text = (
                "【区間設定の使い方】\n\n"
                "■開始パターン\n"
                " 区間の開始条件(正規表現)です。\n"
                "[+V待]で、合致後の次のV周期から\n"
                " 区間を開始します。\n\n"
                "■終了パターン\n"
                " 区間の終了条件(正規表現)です。\n"
                "[V周期]ボタンで<VSYNC>を入力可能です。\n"
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
                " 抽出対象に含めるかを指定します。\n\n"
                "■制約\n"
                " 正規表現の先頭、末尾に.*を付けないでください。\n"
                " 例：[100013.500000] [INFO] System Halting...\n"
                "                     xxxx\n"
                "                     yyyy\n"
                "                     zzzz\n"
                " を抽出したい場合は、正規表現に\n"
                " System.*Halting.*xxxx.*yyyy.*zzzz\n"
                " と設定してください。"
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
            info_lbl = tk.Label(btn_fr, text=info_text, justify=tk.LEFT, anchor="nw", bg="#faf9f6", fg=UIColors.TEXT, relief=tk.FLAT, bd=1, highlightbackground=UIColors.BORDER, highlightthickness=1, padx=12, pady=12, font=("Yu Gothic UI", 9), wraplength=230)
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
            # 設定変更時に自動的にconfig.jsonを保存
            self.save_config()
            
            dlg.destroy()
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.apply_display_update(w)
                except: pass

        tk.Button(btn_fr, text="OK", command=save, width=20, bg=UIColors.ROSE, fg="white", font=("Yu Gothic UI", 9, "bold"), relief=tk.FLAT, cursor="hand2", height=2).pack(side=tk.BOTTOM, pady=5)

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
            
            self._update_vsync_info_label()
            # すべてのタブに対して表示を更新
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab):
                        self.apply_display_update(w)
                except:
                    pass
        except Exception as e:
            print(f"Failed to load config from {p}: {e}")

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