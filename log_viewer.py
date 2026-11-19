from __future__ import annotations

import json
import os
import re
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, ttk
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

# --- エラー検出（HTML 版と同じ既定値。config.json の error_rules / error_colors） ---
DEFAULT_ERROR_COLORS = {"error": "#ff3b30", "warn": "#ff9f0a"}
DEFAULT_ERROR_RULES = (
    [{"keyword": k, "type": "error", "word": True, "case": False, "enabled": True}
     for k in ["ERROR", "FATAL", "CRITICAL", "SEVERE", "PANIC", "Traceback"]]
    + [{"keyword": r"\w*(Exception|Error)\b", "type": "error", "word": False, "case": True, "enabled": True}]
    + [{"keyword": k, "type": "error", "word": False, "case": False, "enabled": True} for k in ["失敗", "異常", "エラー"]]
    + [{"keyword": k, "type": "warn", "word": True, "case": False, "enabled": True}
       for k in ["WARN", "WARNING", "timeout", "timed out", "retry", "retrying"]]
    + [{"keyword": "警告", "type": "warn", "word": False, "case": False, "enabled": True}]
)
ERR_NONE, ERR_WARN, ERR_ERR = 0, 1, 2
DEFAULT_GAP_MS = 100.0
# 時刻: 既定のパターンは秒数のみ。表示では hh:mm:ss(.fff) も読む（HTML 版と同じ）
PY_DEFAULT_TS = r"^\[?\s*(\d+(?:\.\d+)?)\]?"
EXT_DEFAULT_TS = r"^\[?\s*(\d{1,2}:\d{2}:\d{2}(?:\.\d+)?|\d+(?:\.\d+)?)\]?"
GAP_TOP = 20
# 間隔の色（しきい値の 1/10 以上: 黄、1/3 以上: 橙、しきい値以上: 赤）
GAP_COLORS = {1: "#fff4c2", 2: "#ffd9a8", 3: "#ffc9c4"}
GAP_RED = "#d70015"
# マージ元ファイルごとの色（ファイル列の丸・行番号の左の帯）
FILE_COLORS = ["#0a84ff", "#ff9f0a", "#30d158", "#bf5af2", "#ff375f", "#5ac8fa", "#ffd60a", "#a2845e"]
VIRTUAL_FILE_COLOR = "#c7c7cc"


def clamp_level(v) -> int:
    """優先度は 1〜3（3 が一番強い）。それ以外は 1。"""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 1
    return n if n in (2, 3) else 1


def _word_wrap(p: str) -> str:
    """英単語の途中では一致させない（ERROR は NOERROR / ERRORS に一致しない）"""
    return rf"(?<![A-Za-z0-9_])(?:{p})(?![A-Za-z0-9_])"


def compile_error_rules(rules) -> Tuple[Dict[str, List[Any]], List[str]]:
    """種類・大小区別ごとに 1 つの正規表現にまとめる。戻り値: ({"error": [re...], "warn": [re...]}, エラー文)"""
    parts = {"error": {"i": [], "c": []}, "warn": {"i": [], "c": []}}
    errors = []
    for k, r in enumerate(rules or []):
        kw = str(r.get("keyword", "") or "").strip()
        if r.get("enabled", True) is False or not kw:
            continue
        typ = "warn" if r.get("type") == "warn" else "error"
        src = _word_wrap(kw) if r.get("word") else kw
        try:
            re.compile(src)
        except re.error as e:
            errors.append(f"エラー検出{k + 1}「{kw}」: {e}")
            continue
        parts[typ]["c" if r.get("case") else "i"].append(f"(?:{src})")
    groups = {"error": [], "warn": []}
    for typ in ("error", "warn"):
        if parts[typ]["i"]:
            groups[typ].append(re.compile("|".join(parts[typ]["i"]), re.I))
        if parts[typ]["c"]:
            groups[typ].append(re.compile("|".join(parts[typ]["c"])))
    return groups, errors


def detect_errors(lines: List[str], srcs: List[str], groups) -> List[int]:
    """行ごとの種類（0: なし、1: 警告、2: エラー）。仮想行は対象外"""
    out = [ERR_NONE] * len(lines)
    for i, line in enumerate(lines):
        if i < len(srcs) and srcs[i] == VIRTUAL_SRC_NAME:
            continue
        if any(rx.search(line) for rx in groups["error"]):
            out[i] = ERR_ERR
        elif any(rx.search(line) for rx in groups["warn"]):
            out[i] = ERR_WARN
    return out


def error_message_key(line: str, re_ts) -> str:
    """同じ内容のエラーをまとめるための文: 行頭の時刻を除き、16進数・数字を # にする"""
    m = re_ts.match(line) if re_ts else None
    t = line[m.end():] if m else line
    t = re.sub(r"0x[0-9a-f]+", "#", t, flags=re.I)
    t = re.sub(r"\b[0-9a-f]{8,}\b", "#", t, flags=re.I)
    t = re.sub(r"\d+(?:\.\d+)?", "#", t)
    return re.sub(r"\s+", " ", t).strip()[:300]


def gap_level(g, threshold) -> int:
    if not threshold or threshold <= 0 or g is None or g < threshold / 10:
        return 0
    return 3 if g >= threshold else 2 if g >= threshold / 3 else 1


def darker(color: str, k: float = 0.75) -> str:
    """#rrggbb を少し暗くする（行番号の文字色など）"""
    m = re.fullmatch(r"#([0-9a-fA-F]{6})", color or "")
    if not m:
        return color
    v = int(m.group(1), 16)
    r, g, b = (v >> 16) & 255, (v >> 8) & 255, v & 255
    return f"#{int(r * k):02x}{int(g * k):02x}{int(b * k):02x}"

class UIColors:
    """Web 版（log_viewer.html）と同じ配色"""
    BG = "#f5f5f7"          # 全体の背景
    PANEL_BG = "#ffffff"    # 表・パネルの背景
    SURFACE_2 = "#fafafc"   # 少し沈んだ面（行番号・経過・間隔の列、見出し）
    SURFACE_3 = "#f0f0f3"   # ボタンの控えめな面
    HEADER_BG = "#fafafc"   # 列の見出し
    HEADER_FG = "#6e6e73"   # 見出しの文字
    ACCENT = "#0071e3"      # 青（主なボタン・ON の状態）
    ACCENT_HOVER = "#0077ed"
    ROSE = "#0071e3"        # 以前のアクセント2。主なボタン（OK など）は青にそろえる
    ROSE_HOVER = "#0077ed"
    MERGE = "#5e5ce6"       # マージのボタン
    MERGE_HOVER = "#6b69f0"
    TEXT = "#1d1d1f"        # 基本の文字
    TEXT_2 = "#6e6e73"      # 補助の文字
    TEXT_3 = "#86868b"      # 薄い文字（行番号・経過など）
    TEXT_BG = "#ffffff"
    BORDER = "#d2d2d7"      # 入力欄・ボタンの枠
    SEP = "#e5e5ea"         # 区切り線
    SEL = "#b3d7ff"         # 選択した文字
    CURSOR_LINE = "#eaf2fd" # 選択している行
    FOUND = "#ffb340"       # 検索で見つかった文字
    DANGER_BG = "#fdecea"   # 削除ボタン
    DANGER_FG = "#d70015"
    ORIGIN_ROW = "#f3d6df"  # V周期の起点の行
    UI_FONT = "Yu Gothic UI"


def section_header(parent, text, size=9):
    """列の見出し: 薄い面に灰色の文字、下に細い区切り線（Web 版の見出しと同じ見え方）"""
    lbl = tk.Label(parent, text=text, bg=UIColors.HEADER_BG, fg=UIColors.HEADER_FG, font=(UIColors.UI_FONT, size, "bold"),
                   relief=tk.FLAT, pady=7, anchor="w", padx=10)
    lbl.pack(side=tk.TOP, fill=tk.X)
    tk.Frame(parent, bg=UIColors.SEP, height=1).pack(side=tk.TOP, fill=tk.X)
    return lbl


def flat_button(parent, text, command, primary=False, **kw):
    """平らなボタン。primary は青地に白、それ以外は白地に枠"""
    if primary:
        opts = dict(bg=UIColors.ACCENT, fg="white", activebackground=UIColors.ACCENT_HOVER, activeforeground="white", highlightthickness=0)
    else:
        opts = dict(bg="#ffffff", fg=UIColors.TEXT, activebackground=UIColors.SURFACE_3, activeforeground=UIColors.TEXT,
                    highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.BORDER)
    opts.update(relief=tk.FLAT, bd=0, cursor="hand2", font=(UIColors.UI_FONT, 9, "bold"), padx=12, pady=4)
    opts.update(kw)
    return tk.Button(parent, text=text, command=command, **opts)

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

def _normalize_user_pattern(pat: str) -> str:
    """Normalize user-entered pattern shortcuts to valid regex.

    - Replace percent signs (%) with '\\s*' so users can use '%' as a
      short-hand for whitespace sequences.
    """
    if not isinstance(pat, str):
        return pat
    p = pat.strip()
    p = p.replace('%', r'\\s*')

    # Keep a single '.*' as-is, but trim redundant wrappers around a pattern.
    if len(p) > 4 and p.startswith('.*') and p.endswith('.*'):
        p = p[2:-2].strip()

    if len(p) > 6 and p.startswith('^.*') and p.endswith('.*$'):
        p = p[3:-3].strip()

    return p


def _group_log_entries(lines: List[str], sources: List[str]) -> List[Tuple[int, int]]:
    """Return (start, end) ranges for logical, possibly multiline log entries."""
    if not lines:
        return []

    groups: List[Tuple[int, int]] = []
    start = 0
    for idx in range(1, len(lines)):
        source_changed = idx < len(sources) and sources[idx] != sources[idx - 1]
        is_continuation = not lines[idx] or lines[idx][0].isspace()
        if source_changed or not is_continuation:
            groups.append((start, idx))
            start = idx
    groups.append((start, len(lines)))
    return groups


def _find_keyword_matches(
    lines: List[str], sources: List[str], rules: List[Dict[str, Any]]
) -> Tuple[Dict[int, int], Dict[int, int]]:
    """Return matched lines and the matched entry starts used for comments."""
    matches: Dict[int, int] = {}
    match_starts: Dict[int, int] = {}
    for start, end in _group_log_entries(lines, sources):
        entry_text = "\n".join(lines[start:end])
        entry_source = sources[start] if start < len(sources) else ""
        best_idx, best_level = -1, 0
        for rule_idx, rule in enumerate(rules):
            if not rule["file_pat_re"].search(entry_source):
                continue
            if not rule["regex"].search(entry_text):
                continue
            # 一致したフィルタのうち優先度が一番強いもの（同じ強さなら上にあるもの）を使う
            level = rule.get("level", 1)
            if level > best_level:
                best_idx, best_level = rule_idx, level
                if level >= 3:
                    break
        if best_idx >= 0:
            rule = rules[best_idx]
            # 1 件のログ（字下げされた続きの行を含む）全体に色を付ける
            for idx in range(start, end):
                matches.setdefault(idx, best_idx)
            if matches.get(start) == best_idx:
                match_starts[start] = best_idx
    return matches, match_starts

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
            try:
                event.widget.after_cancel(self.id)
            except Exception:
                pass
            self.id = None

        # Remove old tooltip if exists
        self.hide()

        # Create tooltip window
        self.tooltip = tw = tk.Toplevel(event.widget)
        tw.wm_overrideredirect(True)
        try:
            tw.wm_attributes("-topmost", True)
        except Exception:
            pass

        # Create label with text
        label = tk.Label(tw, text=text, background="#1e1e20", foreground="#ffffff",
                         relief=tk.FLAT, borderwidth=0, font=(UIColors.UI_FONT, 9),
                         padx=9, pady=5, wraplength=320, justify=tk.LEFT)
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

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "keywords":[
        {"file_pattern": ".*", "pattern": r".*ERROR.*", "color": "#f8d7da", "comment": "重大なエラー発生", "enabled": True},
        {"file_pattern": ".*", "pattern": "WARN",       "color": "#fff3cd", "comment": "警告メッセージ",   "enabled": True},
        {"file_pattern": ".*", "pattern": "INFO",       "color": "#d1e7dd", "comment": "正常動作ログ",     "enabled": True},
        {"file_pattern": ".*", "pattern": r"--- \[VIRTUAL V-SYNC\] ---", "color": "#e2d9f3", "comment": "仮想V同期タイミング", "enabled": True},
        {"file_pattern": ".*", "pattern": r"--- \[VIRTUAL TIMER\].*", "color": "#ffe0b2", "comment": "タイマー満了", "enabled": True}
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
    },
    "error_rules": [dict(r) for r in DEFAULT_ERROR_RULES],
    "error_colors": dict(DEFAULT_ERROR_COLORS),
}

class LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget, owner=None, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        self.owner = owner
        for ev in['<KeyRelease>', '<MouseWheel>', '<Configure>', '<<Modified>>', '<Button-1>']:
            self.text_widget.bind(ev, self.redraw, add="+")

    def redraw(self, *args):
        self.delete("all")
        tab = self.owner
        nums = getattr(tab, "disp_numbers", None)
        errs = getattr(tab, "disp_err", None)
        gaps = getattr(tab, "disp_gap", None)
        srcs = getattr(tab, "disp_src", None) if getattr(tab, "src_text", None) is not None else None
        app = getattr(tab, "app", None)
        width = int(self.cget("width"))
        i = self.text_widget.index("@0,0")
        while True:
            dline = self.text_widget.dlineinfo(i)
            if dline is None: break
            y, h = dline[1], dline[3]
            n = int(str(i).split(".")[0]) - 1
            label = nums[n] if nums is not None and n < len(nums) else str(n + 1)
            e = errs[n] if errs is not None and n < len(errs) else ERR_NONE
            color, font = UIColors.TEXT_3, ("Consolas", 10)
            if srcs is not None and n < len(srcs):
                self.create_rectangle(0, y, 3, y + h, fill=tab.file_colors.get(srcs[n], VIRTUAL_FILE_COLOR), outline="")
            if e and app is not None:
                c = app.error_colors["error" if e == ERR_ERR else "warn"]
                self.create_oval(4, y + h / 2 - 3.5, 11, y + h / 2 + 3.5, fill=c, outline="")
                color, font = darker(c, 0.8), ("Consolas", 10, "bold")
            self.create_text(width - 4, y, anchor="ne", text=label, fill=color, font=font)
            # しきい値以上の間隔があいた行の上に赤い線
            if gaps is not None and app is not None and n < len(gaps) and gap_level(gaps[n], app.gap_ms) == 3:
                self.create_line(0, y, width, y, fill=GAP_RED, width=2)
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
        self.vsb = ttk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=5, bg=UIColors.SEP, bd=0)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=650)
        
        # 見出し: 1 つのファイルならファイル名、マージ結果なら「ログ」
        header_text = self.source_file_names[0] if len(self.source_file_names) == 1 else "ログ"
        section_header(left_frame, header_text)
        
        self.hsb_log = ttk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.text = tk.Text(left_frame, wrap=tk.NONE, xscrollcommand=self.hsb_log.set, bg=UIColors.TEXT_BG, fg=UIColors.TEXT, relief=tk.FLAT, bd=0, font=("Consolas", 10))
        self.text.tag_configure("sel", background=UIColors.SEL, foreground="black")
        self.text.tag_config("found", background=UIColors.FOUND, foreground=UIColors.TEXT)
        
        self.linenumbers = LineNumberCanvas(left_frame, self.text, owner=self, width=58, bg=UIColors.SURFACE_2, highlightthickness=0)
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        
        self.timediff_text = tk.Text(left_frame, width=12, wrap=tk.NONE, bg=UIColors.SURFACE_2, fg=UIColors.TEXT_3, relief=tk.FLAT, bd=0, font=("Consolas", 10))
        self.timediff_text.tag_configure("sel", background=UIColors.SEL, foreground="black")
        if not self.is_merged:
            self.timediff_text.pack(side=tk.LEFT, fill=tk.Y)

        # 前の行（表示中）からの時間差 [ms]
        self.gap_text = tk.Text(left_frame, width=11, wrap=tk.NONE, bg=UIColors.SURFACE_2, fg=UIColors.TEXT_3, relief=tk.FLAT, bd=0, padx=6, font=("Consolas", 10))
        self.gap_text.tag_configure("sel", background=UIColors.SEL, foreground="black")
        self.gap_text.tag_configure("right", justify=tk.RIGHT)
        for lv, col in GAP_COLORS.items():
            self.gap_text.tag_configure(f"g{lv}", background=col, foreground="#4a4f54")
        self.gap_text.tag_configure("g3", foreground=GAP_RED, font=("Consolas", 10, "bold"))
        self.gap_text.pack(side=tk.LEFT, fill=tk.Y)
        self._gap_tip = Tooltip()
        self.gap_text.bind("<Enter>", lambda e: self._gap_tip.show(e, "間隔(ms): 表示中の前の行からの時間差"))
        self.gap_text.bind("<Leave>", lambda e: self._gap_tip.hide())

        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)
        
        # ファイル列: どのファイルの行か（色の丸＋名前）。2 つ以上のファイルをマージしたときだけ出す
        self.src_text = None
        self.file_colors = {fn: FILE_COLORS[k % len(FILE_COLORS)] for k, fn in enumerate(self.source_file_names)}
        if len(self.source_file_names) > 1:
            src_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
            self.paned_window.add(src_frame, minsize=60, stretch="never", width=140)
            section_header(src_frame, "ファイル")
            hsb_src = ttk.Scrollbar(src_frame, orient=tk.HORIZONTAL)
            hsb_src.pack(side=tk.BOTTOM, fill=tk.X)
            self.src_text = tk.Text(src_frame, wrap=tk.NONE, bg=UIColors.TEXT_BG, fg=UIColors.TEXT, xscrollcommand=hsb_src.set, relief=tk.FLAT, bd=0, padx=4, font=("Consolas", 10))
            self.src_text.tag_configure("sel", background=UIColors.SEL, foreground="black")
            for fn, col in self.file_colors.items():
                self.src_text.tag_configure(f"dot_{col[1:]}", foreground=col)
            self.src_text.tag_configure(f"dot_{VIRTUAL_FILE_COLOR[1:]}", foreground=VIRTUAL_FILE_COLOR)
            self.src_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hsb_src.config(command=self.src_text.xview)

        cmt_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
        self.paned_window.add(cmt_frame, minsize=50, stretch="always", width=250)
        
        self.hsb_cmt = ttk.Scrollbar(cmt_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        
        section_header(cmt_frame, "コメント")
        
        self.comment_text = tk.Text(cmt_frame, wrap=tk.NONE, bg=UIColors.TEXT_BG, fg=UIColors.TEXT_2, xscrollcommand=self.hsb_cmt.set, relief=tk.FLAT, bd=0, font=("Consolas", 10))
        self.comment_text.tag_configure("sel", background=UIColors.SEL, foreground="black")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)
        
        for fname in self.source_file_names:
            st_frame = tk.Frame(self.paned_window, bg=UIColors.PANEL_BG)
            self.status_frames[fname] = st_frame  # フレームを保存（add の前に保存）
            # Advanced ON時のみ paned_window に追加
            if self.app.advance_mode:
                self.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
            section_header(st_frame, f"{fname}の区間")
            
            hsb = ttk.Scrollbar(st_frame, orient=tk.HORIZONTAL)
            hsb.pack(side=tk.BOTTOM, fill=tk.X)
            
            st_text = tk.Text(st_frame, wrap=tk.NONE, bg=UIColors.SURFACE_2, fg=UIColors.TEXT, xscrollcommand=hsb.set, relief=tk.FLAT, bd=0, font=("Consolas", 10))
            st_text.tag_configure("sel", background=UIColors.SEL, foreground="black")
            st_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hsb.config(command=st_text.xview)
            self.status_texts[fname] = st_text
            
        self.all_texts =[self.text, self.timediff_text, self.gap_text] + ([self.src_text] if self.src_text else []) + [self.comment_text] + list(self.status_texts.values())
        
        # 読み取り専用: 文字の入力・Enter・貼り付けでは書き換わらない。
        # クリックでフォーカスを移すので、矢印キーでの移動・選択・Ctrl+C は使える
        for w in self.all_texts:
            w.configure(state=tk.DISABLED, insertwidth=2, insertofftime=0)
            w.bind('<Button-1>', lambda e: e.widget.focus_set(), add="+")
            w.bind('<Control-c>', lambda e: (e.widget.event_generate("<<Copy>>"), "break")[1])

        # カーソル行のハイライト設定
        for w in self.all_texts:
            w.tag_configure("cursor_line", background=UIColors.CURSOR_LINE)
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
            t.bind('<Alt-Down>', lambda e: (self.app.next_gap(1), "break")[1])
            t.bind('<Alt-Up>', lambda e: (self.app.next_gap(-1), "break")[1])

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
        
        self._apply_style()
        
        self.keywords_config =[x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.sections_config =[x.copy() for x in DEFAULT_CONFIG["sections"]]
        self.replace_patterns_config =[]
        self.vsync_config = DEFAULT_CONFIG["vsync_auto_insert"].copy()
        
        self.min_level = 0               # 0: フィルタなし、1〜3: その優先度以上のフィルタに一致した行だけ表示
        self.error_rules_config = [dict(r) for r in DEFAULT_ERROR_RULES]
        self.error_colors = dict(DEFAULT_ERROR_COLORS)
        self.gap_ms = DEFAULT_GAP_MS     # この時間(ms)以上あいた行を強調（0 で強調しない）
        self.extra_config: Dict[str, Any] = {}   # このアプリが使わない項目も、保存のときに残す
        self.gap_win = None
        self.err_win = None
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
        self.root.bind('<F9>', lambda e: self.next_error(1))
        self.root.bind('<Shift-F9>', lambda e: self.next_error(-1))

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
        self._sync_filter_combo()
        self._sync_gap_input()

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="再読み込み", command=self.reload_file, accelerator="F5")
        fmenu.add_separator()
        fmenu.add_command(label="マージして表示...", command=self.merge_logs_action)
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
        self._build_config_menu()
        menubar.add_cascade(label="設定", menu=cmenu)

        vmenu = tk.Menu(menubar, tearoff=0)
        vmenu.add_command(label="次のエラー", command=lambda: self.next_error(1), accelerator="F9")
        vmenu.add_command(label="前のエラー", command=lambda: self.next_error(-1), accelerator="Shift+F9")
        vmenu.add_command(label="エラー一覧...", command=self.open_error_list)
        vmenu.add_separator()
        vmenu.add_command(label="次の間隔の大きい所", command=lambda: self.next_gap(1), accelerator="Alt+↓")
        vmenu.add_command(label="前の間隔の大きい所", command=lambda: self.next_gap(-1), accelerator="Alt+↑")
        vmenu.add_command(label="間隔ランキング...", command=self.open_gap_ranking)
        menubar.add_cascade(label="移動", menu=vmenu)
        
        self.root.config(menu=menubar)
        
        toolbar = tk.Frame(self.root, bg=UIColors.BG)
        toolbar.pack(fill=tk.X, padx=10, pady=(10, 6))
        
        # フィルタ: なし / 優先度 1 以上 / 2 以上 / 3 以上
        self.FILTER_LABELS = ["フィルタなし", "優先度 1以上", "優先度 2以上", "優先度 3以上"]
        self.filter_var = tk.StringVar(value=self.FILTER_LABELS[0])
        self.cmb_filter = ttk.Combobox(toolbar, textvariable=self.filter_var, values=self.FILTER_LABELS, state="readonly", width=13, font=("Yu Gothic UI", 9))
        self.cmb_filter.pack(side=tk.LEFT, padx=5)
        self.cmb_filter.bind("<<ComboboxSelected>>", lambda e: self.set_filter_level(self.FILTER_LABELS.index(self.filter_var.get())))
        self._filter_tip = Tooltip()
        self.cmb_filter.bind("<Enter>", lambda e: self._filter_tip.show(e, "選んだ優先度以上のフィルタに一致した行だけを表示（3 が一番強い）"))
        self.cmb_filter.bind("<Leave>", lambda e: self._filter_tip.hide())

        flat_button(toolbar, "ログをマージ", self.merge_logs_action, bg=UIColors.MERGE, fg="white", activebackground=UIColors.MERGE_HOVER,
                    activeforeground="white", highlightthickness=0, padx=14).pack(side=tk.LEFT, padx=10)
        
        self.btn_vsync_toggle = flat_button(toolbar, "仮想V周期表示: ON", self.toggle_vsync_display, width=16)
        # Advanced OFF時は非表示のため、pack は toggle_advance_mode()で行う
        
        self.lbl_vsync_info = tk.Label(toolbar, text="", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9))
        # Advanced OFF時は非表示のため、pack は toggle_advance_mode()で行う
        self._update_vsync_info_label()
        
        self.btn_advance = flat_button(toolbar, "Advanced: OFF", self.toggle_advance_mode, width=13)
        self.btn_advance.pack(side=tk.RIGHT, padx=5)

        # エラー・警告の件数（クリックでエラー一覧）
        self.err_box = tk.Frame(toolbar, bg="#ffffff", highlightbackground=UIColors.BORDER, highlightthickness=1, cursor="hand2", padx=4)
        self.err_box.pack(side=tk.RIGHT, padx=8)
        self.lbl_err = tk.Label(self.err_box, text="● エラー 0", bg="#ffffff", fg="#999999", font=("Yu Gothic UI", 9, "bold"), padx=6, pady=3, cursor="hand2")
        self.lbl_warn = tk.Label(self.err_box, text="● 警告 0", bg="#ffffff", fg="#999999", font=("Yu Gothic UI", 9, "bold"), padx=6, pady=3, cursor="hand2")
        self.lbl_err.pack(side=tk.LEFT)
        self.lbl_warn.pack(side=tk.LEFT)
        for w in (self.err_box, self.lbl_err, self.lbl_warn):
            w.bind("<Button-1>", lambda e: self.open_error_list())
        self._err_tip = Tooltip()
        self.err_box.bind("<Enter>", lambda e: self._err_tip.show(e, "クリック: エラー一覧　F9 / Shift+F9: 次 / 前のエラー"))
        self.err_box.bind("<Leave>", lambda e: self._err_tip.hide())

        # 間隔のしきい値（ms）と間隔ランキング
        gap_box = tk.Frame(toolbar, bg=UIColors.BG)
        gap_box.pack(side=tk.RIGHT, padx=8)
        flat_button(gap_box, "⏱ ランキング", self.open_gap_ranking, font=(UIColors.UI_FONT, 9)).pack(side=tk.LEFT, padx=(0, 8))
        self.gap_var = tk.StringVar(value="")
        self.ent_gap = tk.Entry(gap_box, textvariable=self.gap_var, width=7, justify=tk.RIGHT, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT, font=("Consolas", 10))
        self.ent_gap.pack(side=tk.LEFT)
        tk.Label(gap_box, text="ms以上を強調", bg=UIColors.BG, fg=UIColors.TEXT_2, font=(UIColors.UI_FONT, 9)).pack(side=tk.LEFT, padx=(5, 0))
        self.ent_gap.bind("<Return>", lambda e: self._apply_gap_input())
        self.ent_gap.bind("<FocusOut>", lambda e: self._apply_gap_input())
        self._gap_input_tip = Tooltip()
        self.ent_gap.bind("<Enter>", lambda e: self._gap_input_tip.show(e, "この時間以上あいた行を強調（空欄で強調しない）。Alt+↓ / Alt+↑ で次 / 前の該当行へ"))
        self.ent_gap.bind("<Leave>", lambda e: self._gap_input_tip.hide())

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 4))
        
        # Bind tooltip events to notebook tabs
        self.notebook.bind('<Motion>', self._on_notebook_motion)
        self.notebook.bind('<Leave>', self._on_notebook_leave)
        
        # Bind drag-drop events for tab reordering
        self.notebook.bind('<Button-1>', self._on_tab_press)
        self.notebook.bind('<ButtonRelease-1>', self._on_tab_release)
        
        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self._on_tab_changed())
        self.notebook_tooltip = Tooltip()
        self._dragged_tab_idx = None
        
        self.status_var = tk.StringVar(value="準備完了")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", bg=UIColors.BG, fg=UIColors.TEXT_2, font=(UIColors.UI_FONT, 9)).pack(fill=tk.X, side=tk.BOTTOM, padx=12, pady=(2, 6))

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e:[self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def _apply_style(self):
        """ttk の部品を Web 版に近い見た目にする（平らで、薄い枠と細いスクロールバー）"""
        C = UIColors
        style = ttk.Style()
        style.theme_use("clam")
        ui = (C.UI_FONT, 9)
        self.root.option_add("*Font", ui)
        self.root.option_add("*TCombobox*Listbox.font", ui)
        self.root.option_add("*TCombobox*Listbox.selectBackground", C.ACCENT)
        self.root.option_add("*Menu.font", ui)
        style.configure(".", font=ui, background=C.BG, foreground=C.TEXT, bordercolor=C.BORDER, lightcolor=C.BG, darkcolor=C.BG, focuscolor=C.ACCENT)
        # タブ: 選んでいるタブは表と同じ白、ほかは背景に溶け込ませる
        style.configure("TNotebook", background=C.BG, borderwidth=0, bordercolor=C.BG, lightcolor=C.BG, darkcolor=C.BG, tabmargins=[6, 4, 6, 0])
        style.configure("TNotebook.Tab", background=C.BG, foreground=C.TEXT_2, padding=[16, 7], font=(C.UI_FONT, 9, "bold"),
                        borderwidth=0, bordercolor=C.BG, lightcolor=C.BG, darkcolor=C.BG, focuscolor=C.BG)
        style.map("TNotebook.Tab",
                  background=[("selected", C.PANEL_BG), ("active", "#ebebf0")],
                  foreground=[("selected", C.TEXT), ("active", C.TEXT)],
                  lightcolor=[("selected", C.PANEL_BG)], darkcolor=[("selected", C.PANEL_BG)], bordercolor=[("selected", C.PANEL_BG)])
        # スクロールバー: 細く、矢印は目立たせない
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", troughcolor=C.SURFACE_2, background="#d1d1d6", bordercolor=C.SURFACE_2,
                            lightcolor="#d1d1d6", darkcolor="#d1d1d6", arrowcolor=C.TEXT_3, gripcount=0, arrowsize=11, relief=tk.FLAT)
            style.map(f"{orient}.TScrollbar", background=[("active", "#aeaeb2"), ("pressed", "#8e8e93")],
                      lightcolor=[("active", "#aeaeb2")], darkcolor=[("active", "#aeaeb2")])
        # 選択欄
        style.configure("TCombobox", fieldbackground="#ffffff", background="#ffffff", foreground=C.TEXT, bordercolor=C.BORDER,
                        lightcolor="#ffffff", darkcolor="#ffffff", arrowcolor=C.TEXT_2, padding=[6, 3])
        style.map("TCombobox", fieldbackground=[("readonly", "#ffffff")], selectbackground=[("readonly", "#ffffff")],
                  selectforeground=[("readonly", C.TEXT)], bordercolor=[("focus", C.ACCENT)])
        # 一覧（間隔ランキング・エラー一覧）
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground=C.TEXT, rowheight=26, borderwidth=0, font=ui)
        style.configure("Treeview.Heading", background=C.SURFACE_2, foreground=C.TEXT_2, relief=tk.FLAT, font=(C.UI_FONT, 9, "bold"),
                        bordercolor=C.SEP, lightcolor=C.SURFACE_2, darkcolor=C.SURFACE_2, padding=[6, 5])
        style.map("Treeview", background=[("selected", C.ACCENT)], foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", C.SURFACE_3)])

    @property
    def use_keyword_filter(self) -> bool:
        return self.min_level > 0

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

                # Refresh all LogTab displays to fix possible layout corruption
                try:
                    for tid in self.notebook.tabs():
                        w = self.notebook.nametowidget(tid)
                        if isinstance(w, LogTab):
                            try:
                                self.apply_display_update(w)
                            except Exception:
                                pass
                except Exception:
                    pass
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
        if not tab:
            return

        if getattr(tab, "file_path", "") == "Merged":
            self.notebook.forget(tab)
            tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
            target_tabs = [t for t in tabs if getattr(t, "file_path", "") and t.file_path != "Merged"]

            for t in target_tabs:
                if os.path.exists(t.file_path):
                    content = self._read_text_file(t.file_path)
                    self._refresh_tab_content(t, content)
                    self.apply_display_update(t)

            if len(target_tabs) >= 2:
                self.merge_logs_action(auto_ts_len=self.last_merge_ts_len)
            return

        if not tab.file_path or not os.path.exists(tab.file_path):
            return

        content = self._read_text_file(tab.file_path)
        self._refresh_tab_content(tab, content)
        self.apply_display_update(tab)
        self.status_var.set(f"再読み込み完了: {os.path.basename(tab.file_path)}")

    def _refresh_tab_content(self, tab: LogTab, content: str) -> None:
        fname = os.path.basename(tab.file_path) if getattr(tab, "file_path", "") else ""
        if self.vsync_config.get("enabled", True) and fname:
            lines = content.splitlines()
            new_content, new_src_map = self._process_vsync_insertion(content, [fname] * len(lines), [fname])
            tab.original_content = new_content
            tab.line_source_map = new_src_map
        else:
            tab.original_content = content
            tab.line_source_map = []

    def _open_file_path(self, path: str):
        content = self._read_text_file(path)
        fname = os.path.basename(path)
        if self.vsync_config.get("enabled", True):
            lines = content.splitlines()
            new_content, new_src_map = self._process_vsync_insertion(content, [fname] * len(lines), [fname])
            tab = LogTab(self.notebook, self, path, new_content, source_files_list=[fname], source_file_paths={fname: path}, is_merged=True)
            tab.line_source_map = new_src_map
        else:
            tab = LogTab(self.notebook, self, path, content, source_files_list=[fname], source_file_paths={fname: path})
        tab.base_title = fname
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
            ts_len = self._ask_merge_ts_len(initial=self.last_merge_ts_len)
            if ts_len is None:
                return
            self.last_merge_ts_len = ts_len
        
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
                # 字下げされた続きの行（と空行）は、直前の行と一緒に並べる
                actual_extra = 0
                while i + actual_extra + 1 < len(raw_lines):
                    next_line = raw_lines[i + actual_extra + 1]
                    if next_line and not next_line[0].isspace():
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
        m_tab.base_title = "マージ結果"
        self.notebook.add(m_tab, text="マージ結果")
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
        e_start_time = tk.Entry(f_start_time, width=15, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT)
        e_start_time.pack(side=tk.LEFT, padx=5)
        e_start_time.insert(0, str(conf.get("start_time_val", "0.0")))

        f_manual = tk.Frame(frame_start, bg=UIColors.BG)
        f_manual.pack(anchor="w", padx=5, pady=5)
        tk.Label(f_manual, text="挿入間隔 (ms):", bg=UIColors.BG, fg=UIColors.TEXT).pack(side=tk.LEFT)
        e_ms = tk.Entry(f_manual, width=10, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT)
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

    def _ask_merge_ts_len(self, initial=19) -> Optional[int]:
        """Custom ask-integer dialog for merge timestamp length."""
        dlg = tk.Toplevel(self.root)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.title("マージ")
        dlg.resizable(False, False)
        try:
            dlg.configure(bg=UIColors.BG)
        except tk.TclError:
            pass

        res = {"value": None}

        content = tk.Frame(dlg, bg=UIColors.BG)
        content.pack(padx=16, pady=14)

        input_frame = tk.Frame(content, bg=UIColors.BG)
        input_frame.pack(fill=tk.X)
        tk.Label(input_frame, text="時刻ソート用の先頭文字数:", anchor="w", font=("Yu Gothic UI", 9, "bold"), bg=UIColors.BG, fg=UIColors.TEXT).pack(side=tk.LEFT)
        ent = tk.Entry(input_frame, width=7, justify=tk.RIGHT, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT)
        ent.pack(side=tk.LEFT, padx=(10, 0))
        ent.insert(0, str(initial))

        btn_frame = tk.Frame(content, bg=UIColors.BG)
        btn_frame.pack(anchor="e", pady=(14, 0))

        def on_ok():
            try:
                v = int(ent.get())
                if v < 0:
                    return
                res["value"] = v
            except Exception:
                res["value"] = None
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        ok = tk.Button(btn_frame, text="OK", width=10, command=on_ok, bg=UIColors.ROSE, fg="white", font=("Yu Gothic UI", 9, "bold"), relief=tk.FLAT, cursor="hand2")
        ok.pack(side=tk.LEFT, padx=(0, 8))
        cancel = tk.Button(btn_frame, text="キャンセル", width=10, command=on_cancel, bg="#ffffff", fg=UIColors.TEXT, relief=tk.FLAT, cursor="hand2")
        cancel.pack(side=tk.LEFT)

        dlg.bind('<Return>', lambda e: on_ok())
        dlg.bind('<Escape>', lambda e: on_cancel())

        # Apply theme to children
        try:
            apply_french_theme(dlg)
        except Exception:
            pass

        ent.focus_set()
        self.root.wait_window(dlg)
        return res["value"]
    def save_config_dialog_silent(self, filepath=None):
        target_path = filepath if filepath else self.config_path
        data = dict(self.extra_config)
        data.update({
            "keywords": self.keywords_config,
            "sections": self.sections_config,
            "replace_patterns": self.replace_patterns_config,
            "vsync_auto_insert": self.vsync_config,
            "error_rules": self.error_rules_config,
            "error_colors": self.error_colors,
            "gap_threshold_ms": self.gap_ms,
        })
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

    def _read_text_file(self, path: str) -> str:
        if not path or not os.path.exists(path):
            return ""
        for encoding in ("utf-8", "cp932", "shift_jis", "latin-1"):
            try:
                with open(path, "r", encoding=encoding) as fh:
                    return fh.read()
            except (UnicodeDecodeError, OSError):
                continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
        except OSError:
            return ""

    def _valid_color(self, c) -> bool:
        if not isinstance(c, str) or not c.strip():
            return False
        try:
            self.root.winfo_rgb(c.strip())
            return True
        except tk.TclError:
            return False

    def _safe_color(self, c, default="#ffffff") -> str:
        return c.strip() if self._valid_color(c) else default

    def _compile_section_rules(self) -> List[dict]:
        section_rules = []
        for s in self.sections_config:
            if not s.get("enabled", True):
                continue
            try:
                fp = s.get("file_pattern", ".*") or ".*"
                end_pat = s["end"]
                is_vsync_end = False
                if end_pat == VSYNC_TAG:
                    end_pat = VSYNC_REGEX
                    is_vsync_end = True

                end_re = re.compile(end_pat, re.I) if end_pat else None
                try:
                    dur_ms = float(s.get("duration_ms", 0) or 0)
                except Exception:
                    dur_ms = 0.0

                section_rules.append({
                    "start": re.compile(s["start"], re.I),
                    "start_wait": s.get("start_wait", False),
                    "end": end_re,
                    "end_str": end_pat,
                    "end_wait": s.get("end_wait", False),
                    "duration_ms": dur_ms,
                    "name": s["name"],
                    "color": self._safe_color(s.get("color", "#ffffff")),
                    "file_pat_re": re.compile(fp, re.I),
                    "is_vsync_end": is_vsync_end,
                })
            except Exception as exc:
                print(f"Regex error in section setup: {exc}")
        return section_rules

    def _compile_keyword_rules(self):
        rules = []
        for itm in self.keywords_config:
            if not itm.get("enabled", True):
                continue
            try:
                rule = {
                    "file_pat_re": re.compile(itm.get("file_pattern", ".*") or ".*", re.I),
                    "regex": re.compile(_normalize_user_pattern(itm["pattern"]), re.I | re.DOTALL),
                    "comment": itm.get("comment", ""),
                    "color": self._safe_color(itm.get("color", "#ffffff")),
                    "level": clamp_level(itm.get("priority", 1)),
                }
                rules.append(rule)
            except Exception:
                continue

        has_timer_rule = any("VIRTUAL TIMER" in str(r.get("pattern", "")) for r in self.keywords_config)
        if not has_timer_rule:
            rules.append({
                "file_pat_re": re.compile(".*"),
                "regex": re.compile(r"\[VIRTUAL TIMER\]", re.I),
                "comment": "タイマー満了",
                "color": "#ffe8d6",
                "level": 1,
            })
        return rules

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
        section_rules = self._compile_section_rules()

        try:
            re_vsync = re.compile(VSYNC_REGEX, re.I)
        except Exception:
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
    def set_filter_level(self, level: int):
        self.min_level = max(0, min(3, int(level)))
        self._sync_filter_combo()
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def toggle_filter(self, force_update=False):
        """以前の「フィルタ ON/OFF」: OFF なら 優先度 1 以上、ON なら フィルタなし"""
        if not force_update:
            self.set_filter_level(0 if self.min_level else 1)
        else:
            self._sync_filter_combo()

    def _sync_filter_combo(self):
        self.filter_var.set(self.FILTER_LABELS[self.min_level])

    def toggle_vsync_display(self, force_update=False):
        if not force_update:
            self.show_vsync_lines = not self.show_vsync_lines
        if self.show_vsync_lines:
            self.btn_vsync_toggle.config(text="仮想V周期表示: ON", bg=UIColors.ACCENT, fg="white", activebackground=UIColors.ACCENT_HOVER, activeforeground="white", highlightbackground=UIColors.ACCENT)
        else:
            self.btn_vsync_toggle.config(text="仮想V周期表示: OFF", bg="#ffffff", fg=UIColors.TEXT, activebackground=UIColors.SURFACE_3, activeforeground=UIColors.TEXT, highlightbackground=UIColors.BORDER)
        
        self._update_vsync_info_label()
            
        if not force_update:
            t = self.get_current_tab()
            if t: self.apply_display_update(t)
    
    def toggle_advance_mode(self):
        self.advance_mode = not self.advance_mode
        if self.advance_mode:
            self.btn_advance.config(text="Advanced: ON", bg=UIColors.ACCENT, fg="white", activebackground=UIColors.ACCENT_HOVER, activeforeground="white", highlightbackground=UIColors.ACCENT)
        else:
            self.btn_advance.config(text="Advanced: OFF", bg="#ffffff", fg=UIColors.TEXT, activebackground=UIColors.SURFACE_3, activeforeground=UIColors.TEXT, highlightbackground=UIColors.BORDER)
        
        # メニュー項目を作り直す（区間設定・V周期設定は Advanced ON 時のみ）
        self._build_config_menu()
        
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
    
    def _build_config_menu(self):
        m = self.cmenu
        m.delete(0, "end")
        m.add_command(label="設定読み込み...", command=self.load_config_dialog)
        m.add_command(label="設定保存...", command=self.save_config_dialog)
        m.add_separator()
        m.add_command(label="フィルタ設定の編集 (行単位)...", command=self.edit_keywords_dialog)
        m.add_command(label="エラー検出の設定...", command=self.edit_error_rules_dialog)
        if self.advance_mode:
            m.add_command(label="区間設定の編集 (開始-終了)...", command=self.edit_sections_dialog)
        m.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        if self.advance_mode:
            m.add_command(label="V周期(仮想)挿入の設定...", command=self.open_vsync_settings_dialog)
        m.add_separator()
        m.add_command(label=("✓ " if self.advance_mode else "") + "Advancedモード", command=self.toggle_advance_mode)

    def _update_vsync_info_label(self):
        start_time = self.vsync_config.get("start_time_val", "0.0")
        manual_ms = self.vsync_config.get("manual_ms", 16.666)
        self.lbl_vsync_info.config(text=f"起点: {start_time}秒 / 間隔: {manual_ms}ms")

    def apply_display_update(self, tab: LogTab):
        data = tab.original_content
        if self.replace_patterns_config: data = self._apply_replacements(data)
        lines = data.splitlines()
        
        line_attrs =[{"color": "#ffffff", "comment": "", "priority": 0, "level": 0} for _ in range(len(lines))]
        
        srcs = tab.line_source_map if tab.line_source_map else (tab.source_file_names * len(lines))
        if len(srcs) < len(lines): srcs.extend([""] * (len(lines) - len(srcs))) 

        section_rules = self._compile_section_rules()

        re_ts = self._ts_regex()

        timestamps =[]
        ts_raw = []
        for line in lines:
            m = re_ts.search(line)
            if m:
                timestamps.append(self._parse_time_seconds(m.group(1)))
                ts_raw.append(m.group(1))
            else:
                timestamps.append(None)
                ts_raw.append("")

        active_states= {fn: None for fn in tab.source_file_names}
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

        keyword_rules = self._compile_keyword_rules()

        # 字下げされた継続行を先頭行とまとめて、1件のログとして判定する。
        keyword_matches, match_starts = _find_keyword_matches(lines, srcs, keyword_rules)
        for idx, rule_idx in keyword_matches.items():
            if idx < len(line_attrs) and rule_idx < len(keyword_rules):
                rule = keyword_rules[rule_idx]
                if line_attrs[idx]["priority"] < 20:
                    line_attrs[idx]["color"] = rule["color"]
                    # 複数行ログは全行を色付けするが、コメントは先頭行だけに表示する。
                    if match_starts.get(idx) == rule_idx:
                        base_cmt = line_attrs[idx]["comment"]
                        new_cmt = rule["comment"]
                        line_attrs[idx]["comment"] = f"{base_cmt} {new_cmt}".strip()
                    line_attrs[idx]["priority"] = 20
                    line_attrs[idx]["level"] = rule.get("level", 1)

        for idx in range(len(lines)):
            if "<<< [V-SYNC 起点]" in lines[idx]:
                if line_attrs[idx]["priority"] < 30:
                    line_attrs[idx]["color"] = UIColors.ORIGIN_ROW 
                    line_attrs[idx]["comment"] = f"{line_attrs[idx]['comment']}[基準位置]".strip()
                    line_attrs[idx]["priority"] = 30

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
                    elif attr["priority"] == 20 and attr["level"] < self.min_level:
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

        # 実際の行番号（仮想行は数えない）。マージ結果ではマージ後の通し番号になる
        real_no, cnt = [], 0
        for i in range(len(lines)):
            if srcs[i] == VIRTUAL_SRC_NAME:
                real_no.append("")
            else:
                cnt += 1
                real_no.append(str(cnt))
        err_groups, err_msgs = compile_error_rules(self.error_rules_config)
        err_all = detect_errors(lines, srcs, err_groups)
        disp_idx, disp_gap = [], []
        prev_t = None
        for i in range(len(lines)):
            if not is_visible[i]:
                continue
            disp_idx.append(i)
            t = timestamps[i]
            if srcs[i] == VIRTUAL_SRC_NAME or t is None:
                disp_gap.append(None)
                continue
            disp_gap.append(None if prev_t is None else (t - prev_t) * 1000.0)
            prev_t = t
        tab.all_lines, tab.all_ts_raw, tab.all_err = lines, ts_raw, err_all
        tab.disp_idx = disp_idx
        tab.disp_gap = disp_gap
        tab.disp_err = [err_all[i] for i in disp_idx]
        tab.disp_numbers = [real_no[i] for i in disp_idx]
        tab.n_err = sum(1 for e in err_all if e == ERR_ERR)
        tab.n_warn = sum(1 for e in err_all if e == ERR_WARN)
        tab.err_msgs = err_msgs

        flines, fcmts, ftimediffs = [], [], []
        main_tags = []
        final_st_lines = {fn: [] for fn in tab.source_file_names}
        final_st_tags = {fn: [] for fn in tab.source_file_names}

        line_count = 0
        base_ts = None

        for i in range(len(lines)):
            if not is_visible[i]:
                continue

            if base_ts is None and timestamps[i] is not None:
                base_ts = timestamps[i]

            line_count += 1
            flines.append(lines[i])

            if timestamps[i] is not None and base_ts is not None:
                ftimediffs.append(f"{(timestamps[i] - base_ts):.6f}")
            else:
                ftimediffs.append("")

            base_cmt = line_attrs[i]['comment']
            fcmts.append(base_cmt)

            if line_attrs[i]["color"] != "#ffffff":
                main_tags.append((line_count, line_attrs[i]["color"]))

            for fn in tab.source_file_names:
                txt, col = status_buffers[fn][i]
                final_st_lines[fn].append(txt)
                if col != "#ffffff":
                    final_st_tags[fn].append((line_count, col))

        # 列はふだん読み取り専用（Enter などで書き換わらないように）。書き込む間だけ編集できる状態にする
        for w in tab.all_texts:
            w.configure(state=tk.NORMAL)
        tab.gap_text.delete("1.0", tk.END)
        tab.disp_src = [srcs[i] for i in disp_idx]
        if tab.src_text is not None:
            tab.src_text.delete("1.0", tk.END)
            if flines:
                tab.src_text.insert("1.0", "\n".join(f"● {'(仮想)' if sname == VIRTUAL_SRC_NAME else sname}" for sname in tab.disp_src))
                for n, sname in enumerate(tab.disp_src, start=1):
                    col = tab.file_colors.get(sname, VIRTUAL_FILE_COLOR)
                    tab.src_text.tag_add(f"dot_{col[1:]}", f"{n}.0", f"{n}.1")
        if flines:
            tab.gap_text.insert("1.0", "\n".join("" if g is None else f"{g:,.3f}" for g in disp_gap), "right")
            for n, g in enumerate(disp_gap, start=1):
                lv = gap_level(g, self.gap_ms)
                if lv:
                    tab.gap_text.tag_add(f"g{lv}", f"{n}.0", f"{n}.end")

        if flines:
            tab.text.delete("1.0", tk.END)
            tab.text.insert("1.0", "\n".join(flines))

            tab.timediff_text.delete("1.0", tk.END)
            tab.timediff_text.insert("1.0", "\n".join(ftimediffs))

            tab.comment_text.delete("1.0", tk.END)
            tab.comment_text.insert("1.0", "\n".join(fcmts))
        else:
            tab.text.delete("1.0", tk.END)
            tab.timediff_text.delete("1.0", tk.END)
            tab.comment_text.delete("1.0", tk.END)

        # Advanced モード時のみ区間情報を表示
        if self.advance_mode:
            for fn in tab.source_file_names:
                w = tab.status_texts[fn]
                if final_st_lines[fn]:
                    w.delete("1.0", tk.END)
                    w.insert("1.0", "\n".join(final_st_lines[fn]))
                else:
                    w.delete("1.0", tk.END)
                for tag in list(w.tag_names()):
                    if tag.startswith("st_"):
                        w.tag_delete(tag)
                for ln, col in final_st_tags[fn]:
                    tn = f"st_{col.replace('#','')}"
                    w.tag_configure(tn, background=col)
                    w.tag_add(tn, f"{ln}.0", f"{ln}.end")

        for tag in list(tab.text.tag_names()):
            if tag.startswith("kw_"):
                tab.text.tag_delete(tag)
        for ln, col in main_tags:
            tn = f"kw_{col.replace('#','')}"
            tab.text.tag_configure(tn, background=col)
            tab.text.tag_add(tn, f"{ln}.0", f"{ln}.end")

        for w in tab.all_texts:
            w.configure(state=tk.DISABLED)
        tab.linenumbers.redraw()
        tab.update_cursor_line()
        self._update_tab_badge(tab)
        if tab is self.get_current_tab():
            self._update_err_box()
            self._refresh_panels()
            if err_msgs:
                self.status_var.set("無効なエラー検出の設定: " + " / ".join(err_msgs))

    def _apply_replacements(self, content: str) -> str:
        for itm in self.replace_patterns_config:
            if itm.get("enabled", True):
                try: content = re.sub(itm["search"], lambda m: f"{m.group(0)}({m.expand(itm['replace'])})", content, flags=re.I)
                except: pass
        return content

    # --- 間隔・エラー ---
    def _ts_regex(self):
        """表示・間隔・エラー一覧に使う時刻の正規表現。
        既定のパターン（秒数のみ）のときは、HTML 版と同じく hh:mm:ss(.fff) も読む"""
        ts_pat = self.vsync_config.get("time_pattern", PY_DEFAULT_TS)
        if ts_pat == PY_DEFAULT_TS:
            ts_pat = EXT_DEFAULT_TS
        try:
            return re.compile(ts_pat)
        except re.error:
            return re.compile(r"^\[?\s*(\d+(?:\.\d+)?)\]?")

    def _sync_gap_input(self):
        v = self.gap_ms
        self.gap_var.set("" if not v else (str(int(v)) if float(v).is_integer() else str(v)))
        self.ent_gap.config(bg="#ffffff")

    def _apply_gap_input(self):
        raw = self.gap_var.get().strip()
        try:
            v = 0.0 if raw == "" else float(raw)
            if v < 0:
                raise ValueError
        except ValueError:
            self.ent_gap.config(bg="#ffe0e0")
            self.status_var.set("間隔は 0 以上の数値で入力してください（空欄で強調しない）")
            return
        self.ent_gap.config(bg="#ffffff")
        if v == self.gap_ms:
            return
        self.gap_ms = v
        self.save_config()
        t = self.get_current_tab()
        if t:
            self.apply_display_update(t)
            n = sum(1 for g in t.disp_gap if g is not None and v and g >= v)
            self.status_var.set(f"{v:g} ms 以上あいた所: {n} か所（Alt+↓ で移動）" if v else "間隔の強調をやめました")

    def _current_line(self, tab) -> int:
        try:
            return int(tab.text.index("insert").split(".")[0])
        except Exception:
            return 0

    def goto_display_line(self, tab, n: int):
        """表示中の n 行目（1 始まり）を選んで見えるようにする"""
        pos = f"{n}.0"
        tab.text.mark_set("insert", pos)
        tab.text.see(pos)
        tab.update_cursor_line()
        tab.linenumbers.redraw()
        tab.text.focus_set()

    def next_gap(self, direction: int):
        tab = self.get_current_tab()
        if not tab or not getattr(tab, "disp_gap", None):
            return
        if not self.gap_ms:
            self.status_var.set("ツールバーの「ms以上を強調」に、強調する間隔を入れてください")
            self.ent_gap.focus_set()
            return
        gaps = tab.disp_gap
        n = self._current_line(tab) - 1 + direction
        while 0 <= n < len(gaps):
            g = gaps[n]
            if g is not None and g >= self.gap_ms:
                self.goto_display_line(tab, n + 1)
                total = sum(1 for x in gaps if x is not None and x >= self.gap_ms)
                self.status_var.set(f"前の行から {g:,.3f} ms（{self.gap_ms:g} ms 以上: {total} か所）")
                self._mark_panels()
                return
            n += direction
        self.status_var.set(f"これより{'後' if direction > 0 else '前'}に {self.gap_ms:g} ms 以上あいた所はありません")

    def next_error(self, direction: int):
        tab = self.get_current_tab()
        if not tab or getattr(tab, "disp_err", None) is None:
            return
        if not tab.n_err and not tab.n_warn:
            self.status_var.set("エラー・警告は見つかっていません")
            return
        want = ERR_ERR if tab.n_err else ERR_WARN
        kind = "エラー" if want == ERR_ERR else "警告"
        errs = tab.disp_err
        total = tab.n_err if want == ERR_ERR else tab.n_warn
        vis = sum(1 for e in errs if e == want)
        n = self._current_line(tab) - 1 + direction
        while 0 <= n < len(errs):
            if errs[n] == want:
                self.goto_display_line(tab, n + 1)
                k = sum(1 for e in errs[:n + 1] if e == want)
                hidden = f"（{total - vis} 件はフィルタで非表示）" if vis < total else ""
                self.status_var.set(f"{kind} {k} / {vis} 件目{hidden}")
                self._mark_panels()
                return
            n += direction
        self.status_var.set(f"これより{'後' if direction > 0 else '前'}に{kind}はありません" if vis else f"{kind}はすべてフィルタで非表示です")

    # --- タブの件数・ツールバーの件数 ---
    def _badge_image(self, color: str):
        cache = self.__dict__.setdefault("_badge_cache", {})
        if color not in cache:
            img = tk.PhotoImage(width=10, height=10)
            for y in range(10):
                dx = int(((4.6 ** 2) - (y - 4.5) ** 2) ** 0.5) if abs(y - 4.5) < 4.6 else -1
                if dx >= 0:
                    img.put(color, to=(max(0, 5 - dx), y, min(10, 5 + dx), y + 1))
            cache[color] = img
        return cache[color]

    def _update_tab_badge(self, tab):
        base = getattr(tab, "base_title", None)
        if base is None:
            try:
                base = tab.base_title = self.notebook.tab(tab, "text")
            except tk.TclError:
                return
        try:
            if tab.n_err:
                self.notebook.tab(tab, text=f"{base}  {tab.n_err}", image=self._badge_image(self.error_colors["error"]), compound=tk.RIGHT)
            elif tab.n_warn:
                self.notebook.tab(tab, text=f"{base}  {tab.n_warn}", image=self._badge_image(self.error_colors["warn"]), compound=tk.RIGHT)
            else:
                self.notebook.tab(tab, text=base, image="")
        except tk.TclError:
            pass

    def _update_err_box(self):
        tab = self.get_current_tab()
        ne = getattr(tab, "n_err", 0) if tab else 0
        nw = getattr(tab, "n_warn", 0) if tab else 0
        self.lbl_err.config(text=f"● エラー {ne}", fg=darker(self.error_colors["error"], 0.85) if ne else "#999999")
        self.lbl_warn.config(text=f"● 警告 {nw}", fg=darker(self.error_colors["warn"], 0.75) if nw else "#999999")

    def _on_tab_changed(self):
        self._update_err_box()
        self._refresh_panels()

    def _refresh_panels(self):
        if self.gap_win is not None and self.gap_win.winfo_exists():
            self._render_gap_ranking()
        if self.err_win is not None and self.err_win.winfo_exists():
            self._render_error_list()

    def _mark_panels(self):
        """一覧の中で、今の行に当たる項目を選んだ状態にする"""
        tab = self.get_current_tab()
        if not tab:
            return
        n = self._current_line(tab)
        if self.gap_win is not None and self.gap_win.winfo_exists():
            tree = self.gap_win.tree
            iid = str(n)
            tree.selection_set(iid) if tree.exists(iid) else tree.selection_remove(tree.selection())
        if self.err_win is not None and self.err_win.winfo_exists():
            w = self.err_win
            for k, g in enumerate(w.groups):
                if n in g["rows"]:
                    w.tree.selection_set(str(k))
                    w.tree.see(str(k))
                    break

    def _panel_window(self, title, geometry):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry(geometry)
        win.configure(bg=UIColors.BG)
        win.transient(self.root)
        win.bind("<Escape>", lambda e: win.destroy())
        return win

    # --- 間隔ランキング ---
    def open_gap_ranking(self):
        if self.gap_win is not None and self.gap_win.winfo_exists():
            self.gap_win.lift()
            self._render_gap_ranking()
            return
        win = self.gap_win = self._panel_window("間隔ランキング", "640x480")
        win.sub = tk.Label(win, text="", anchor="w", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9))
        win.sub.pack(fill=tk.X, padx=10, pady=(8, 4))
        fr = tk.Frame(win, bg=UIColors.BG)
        fr.pack(fill=tk.BOTH, expand=True, padx=10)
        tree = ttk.Treeview(fr, columns=("rank", "ms", "line", "log"), show="headings", selectmode="browse")
        for col, label, w, anchor in (("rank", "順位", 50, tk.E), ("ms", "間隔(ms)", 110, tk.E), ("line", "行", 70, tk.E), ("log", "ログ", 380, tk.W)):
            tree.heading(col, text=label)
            tree.column(col, width=w, anchor=anchor, stretch=(col == "log"))
        for lv, col in GAP_COLORS.items():
            tree.tag_configure(f"g{lv}", background=col)
        sb = ttk.Scrollbar(fr, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        win.tree = tree
        tk.Label(win, text="表示中の行で、前の行との差が大きい順。クリックでその行へ。Alt+↓ / Alt+↑ でしきい値以上の行を順に移動",
                 anchor="w", bg=UIColors.BG, fg=UIColors.TEXT_3, font=("Yu Gothic UI", 8), wraplength=600, justify=tk.LEFT).pack(fill=tk.X, padx=10, pady=6)

        def on_select(_e=None):
            sel = tree.selection()
            tab = self.get_current_tab()
            if not sel or not tab:
                return
            n = int(sel[0])
            self.goto_display_line(tab, n)
            g = tab.disp_gap[n - 1]
            if g is not None:
                self.status_var.set(f"前の行から {g:,.3f} ms")
        tree.bind("<ButtonRelease-1>", on_select)
        tree.bind("<Return>", on_select)
        self._render_gap_ranking()

    def _render_gap_ranking(self):
        win = self.gap_win
        tree = win.tree
        tree.delete(*tree.get_children())
        tab = self.get_current_tab()
        if not tab or not getattr(tab, "disp_gap", None):
            win.sub.config(text="ログを開いてください")
            return
        top = sorted(((g, n) for n, g in enumerate(tab.disp_gap) if g is not None and g > 0), key=lambda x: -x[0])[:GAP_TOP]
        cnt = sum(1 for g in tab.disp_gap if g is not None and self.gap_ms and g >= self.gap_ms)
        base = getattr(tab, "base_title", "")
        win.sub.config(text=f"{base}　·　{self.gap_ms:g} ms 以上: {cnt} か所" if self.gap_ms else base)
        for k, (g, n) in enumerate(top, start=1):
            lv = gap_level(g, self.gap_ms)
            line = tab.all_lines[tab.disp_idx[n]]
            tree.insert("", tk.END, iid=str(n + 1), values=(k, f"{g:,.3f}", tab.disp_numbers[n], line), tags=(f"g{lv}",) if lv else ())
        if not top:
            win.sub.config(text="時刻のある行が 2 行以上ありません")

    # --- エラー一覧 ---
    def open_error_list(self):
        if self.err_win is not None and self.err_win.winfo_exists():
            self.err_win.lift()
            self._render_error_list()
            return
        win = self.err_win = self._panel_window("エラー一覧", "760x500")
        tab = self.get_current_tab()
        win.type_var = tk.StringVar(value="warn" if tab and not getattr(tab, "n_err", 0) and getattr(tab, "n_warn", 0) else "error")
        win.sort_var = tk.StringVar(value="件数の多い順")
        bar = tk.Frame(win, bg=UIColors.BG)
        bar.pack(fill=tk.X, padx=10, pady=(8, 4))
        win.rb_err = tk.Radiobutton(bar, text="エラー", variable=win.type_var, value="error", indicatoron=False, padx=12, pady=3,
                                    bg="#ffffff", selectcolor=UIColors.SURFACE_3, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, font=("Yu Gothic UI", 9, "bold"), command=self._render_error_list)
        win.rb_warn = tk.Radiobutton(bar, text="警告", variable=win.type_var, value="warn", indicatoron=False, padx=12, pady=3,
                                     bg="#ffffff", selectcolor=UIColors.SURFACE_3, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, font=("Yu Gothic UI", 9, "bold"), command=self._render_error_list)
        win.rb_err.pack(side=tk.LEFT)
        win.rb_warn.pack(side=tk.LEFT, padx=(2, 0))
        cmb = ttk.Combobox(bar, textvariable=win.sort_var, values=["件数の多い順", "出た順"], state="readonly", width=12)
        cmb.pack(side=tk.RIGHT)
        cmb.bind("<<ComboboxSelected>>", lambda e: self._render_error_list())
        win.sub = tk.Label(win, text="", anchor="w", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9))
        win.sub.pack(fill=tk.X, padx=10)
        fr = tk.Frame(win, bg=UIColors.BG)
        fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)
        tree = ttk.Treeview(fr, columns=("count", "msg", "when", "line"), show="headings", selectmode="browse")
        for col, label, w, anchor in (("count", "件数", 60, tk.E), ("msg", "内容（数字は # にまとめる）", 380, tk.W), ("when", "時刻（最初〜最後）", 200, tk.W), ("line", "最初の行", 70, tk.E)):
            tree.heading(col, text=label)
            tree.column(col, width=w, anchor=anchor, stretch=(col == "msg"))
        sb = ttk.Scrollbar(fr, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        win.tree = tree
        win.groups = []
        win.cursor = {}
        tk.Label(win, text="数字・16進数を除いて同じ文のものを 1 つにまとめています。クリックで最初の行へ、続けてクリックで次の発生へ。F9 で順に移動",
                 anchor="w", bg=UIColors.BG, fg=UIColors.TEXT_3, font=("Yu Gothic UI", 8), wraplength=720, justify=tk.LEFT).pack(fill=tk.X, padx=10, pady=6)

        def on_click(event):
            iid = tree.identify_row(event.y)
            tab = self.get_current_tab()
            if not iid or not tab:
                return
            k = int(iid)
            g = win.groups[k]
            nxt = (win.cursor.get(k, -1) + 1) % len(g["rows"])
            win.cursor[k] = nxt
            self.goto_display_line(tab, g["rows"][nxt])
            tree.selection_set(iid)
            self.status_var.set(f"このまとまりの {nxt + 1} / {len(g['rows'])} 件目")
        tree.bind("<ButtonRelease-1>", on_click)
        self._render_error_list()

    def _render_error_list(self):
        win = self.err_win
        tree = win.tree
        tree.delete(*tree.get_children())
        win.groups, win.cursor = [], {}
        tab = self.get_current_tab()
        if not tab or getattr(tab, "disp_err", None) is None:
            win.sub.config(text="ログを開いてください")
            return
        want = ERR_WARN if win.type_var.get() == "warn" else ERR_ERR
        kind = "エラー" if want == ERR_ERR else "警告"
        v_err = sum(1 for e in tab.disp_err if e == ERR_ERR)
        v_warn = sum(1 for e in tab.disp_err if e == ERR_WARN)
        win.rb_err.config(text=f"エラー {v_err}", fg=darker(self.error_colors["error"], 0.85) if v_err else "#999999")
        win.rb_warn.config(text=f"警告 {v_warn}", fg=darker(self.error_colors["warn"], 0.75) if v_warn else "#999999")
        re_ts = self._ts_regex()
        groups: Dict[str, Dict[str, Any]] = {}
        for n, e in enumerate(tab.disp_err, start=1):
            if e != want:
                continue
            i = tab.disp_idx[n - 1]
            key = error_message_key(tab.all_lines[i], re_ts) or tab.all_lines[i]
            groups.setdefault(key, {"key": key, "rows": [], "idx": []})
            groups[key]["rows"].append(n)
            groups[key]["idx"].append(i)
        lst = list(groups.values())
        if win.sort_var.get() == "件数の多い順":
            lst.sort(key=lambda g: (-len(g["rows"]), g["rows"][0]))
        else:
            lst.sort(key=lambda g: g["rows"][0])
        win.groups = lst
        total = tab.n_err if want == ERR_ERR else tab.n_warn
        vis = v_err if want == ERR_ERR else v_warn
        hidden = f"（{total - vis} 件は非表示）" if vis < total else ""
        win.sub.config(text=f"{getattr(tab, 'base_title', '')}　·　{len(lst)} 種類 / {vis} 件{hidden}" if lst else
                       (f"{kind}はすべてフィルタで非表示です" if total else f"{kind}は見つかっていません"))
        color = self.error_colors["error" if want == ERR_ERR else "warn"]
        tree.tag_configure("kind", foreground=UIColors.TEXT)   # 種類の色は上の切り替えに出すので、一覧は読みやすい黒にする
        for k, g in enumerate(lst):
            t0, t1 = tab.all_ts_raw[g["idx"][0]], tab.all_ts_raw[g["idx"][-1]]
            when = t0 if len(g["rows"]) == 1 else (f"{t0} 〜 {t1}" if t0 and t1 else "")
            first_no = tab.disp_numbers[g["rows"][0] - 1]
            tree.insert("", tk.END, iid=str(k), values=(len(g["rows"]), g["key"], when, first_no), tags=("kind",))

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
        
        entry = tk.Entry(self.find_window_ref, width=40, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT)
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
        self._edit_dlg("フィルタ設定の編集 ※正規表現にマッチした行を抽出し、指定の色とコメントを付与します。", "keywords",["file_pattern", "pattern", "priority", "color","comment"])

    def edit_error_rules_dialog(self):
        self._edit_dlg("エラー検出の設定 ※キーワードを含む行をエラー・警告として知らせます。", "error_rules", ["keyword", "type", "word", "case"])
        
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
        dlg.configure(bg=UIColors.BG)
        setattr(self, ref_attr, dlg)
        
        fr = tk.Frame(dlg, bg=UIColors.BG)
        fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        l_fr = tk.Frame(fr, bg=UIColors.BG, relief=tk.FLAT, highlightbackground=UIColors.BORDER, highlightthickness=1)
        
        wrapper = tk.Frame(l_fr, bg=UIColors.BG)
        wrapper.pack(fill=tk.BOTH, expand=True)
        
        hdr = tk.Frame(wrapper, bg=UIColors.HEADER_BG)
        hdr.pack(fill=tk.X)
        
        cv = tk.Canvas(wrapper, bg=UIColors.PANEL_BG, highlightthickness=0)
        sc_y = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=cv.yview)
        sc_x = ttk.Scrollbar(wrapper, orient=tk.HORIZONTAL, command=cv.xview)
        sf = tk.Frame(cv, bg=UIColors.PANEL_BG)
        cv.configure(yscrollcommand=sc_y.set, xscrollcommand=sc_x.set)
        
        sc_y.pack(side=tk.RIGHT, fill=tk.Y)
        sc_x.pack(side=tk.BOTTOM, fill=tk.X)
        cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        cv.create_window((0,0), window=sf, anchor="nw")

        scroll_update_id = {"value": None}
        def update_scroll_region():
            scroll_update_id["value"] = None
            if dlg.winfo_exists():
                cv.configure(scrollregion=cv.bbox("all"))

        def on_configure(_event=None):
            # Hundreds of child widgets can emit a configure event each. Collapse
            # them into one scroll-region update after the current render batch.
            if scroll_update_id["value"] is not None:
                try:
                    dlg.after_cancel(scroll_update_id["value"])
                except Exception:
                    pass
            scroll_update_id["value"] = dlg.after_idle(update_scroll_region)
        sf.bind("<Configure>", on_configure)

        header_tip = Tooltip()
        HEADER_TIPS = {
            "priority": "ログレベル 3が最優先（1が最弱）",
            "keyword": "この文字列を含む行を検出する。正規表現も使える（例: NG|E\\d+）",
            "type": "エラー: F9 で移動。警告: エラーが無いときに F9 で移動",
            "word": "ON: 英単語として一致したときだけ（ERROR は NOERROR や ERRORS に一致しない）",
            "case": "ON: 大文字と小文字を区別する",
        }
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
            elif f == "priority": col_defs.append((col_idx, f, "優先度", 62))
            elif f == "keyword": col_defs.append((col_idx, f, "キーワード（正規表現）", 230))
            elif f == "type": col_defs.append((col_idx, f, "種類", 80))
            elif f == "word": col_defs.append((col_idx, f, "単語単位", 62))
            elif f == "case": col_defs.append((col_idx, f, "大小区別", 62))
            col_idx += 1

        config_count = len(getattr(self, f"{key}_config"))
        table_width = sum(column[3] + 4 for column in col_defs)
        desired_width = min(dlg.winfo_screenwidth() - 60, max(820, table_width + 310))
        minimum_height = 470 if key == "sections" else 310
        desired_height = min(
            dlg.winfo_screenheight() - 80,
            max(minimum_height, 185 + min(max(config_count, 1), 12) * 30),
        )
        dlg.geometry(f"{desired_width}x{desired_height}")
        dlg.minsize(min(820, desired_width), min(300, desired_height))

        for c_idx, c_id, c_txt, c_w in col_defs:
            h_cell = tk.Frame(hdr, bg=UIColors.HEADER_BG, width=c_w, height=28)
            h_cell.pack_propagate(False)
            h_cell.grid(row=0, column=c_idx, sticky="w", padx=2, pady=2)
            if c_txt:
                h_lbl = tk.Label(h_cell, text=c_txt, bg=UIColors.HEADER_BG, fg=UIColors.HEADER_FG, font=("Yu Gothic UI", 9, "bold"), anchor="w")
                h_lbl.pack(side=tk.LEFT, fill=tk.BOTH)
                tip_text = HEADER_TIPS.get(c_id)
                if tip_text:
                    h_lbl.bind("<Enter>", lambda e, t=tip_text: header_tip.show(e, t))
                    h_lbl.bind("<Leave>", lambda e: header_tip.hide())

        entries =[]
        render_state = {"generation": 0}
        simple_entry_fields = {"file_pattern", "pattern", "search", "name", "start", "duration_ms", "replace", "comment", "keyword"}
        bool_fields = {"start_wait", "end_wait", "word", "case"}
        render_batch_size = 8

        def render_row(i, item):
            f_btn = tk.Frame(sf, bg=UIColors.PANEL_BG, width=135, height=28)
            f_btn.pack_propagate(False)
            f_btn.grid(row=i, column=0, sticky="w", padx=2, pady=2)

            tk.Checkbutton(f_btn, variable=item["enabled"], bg=UIColors.PANEL_BG, activebackground=UIColors.PANEL_BG).pack(side=tk.LEFT)
            tk.Button(f_btn, text="↑", width=2, command=lambda idx=i: move(idx, -1), bg=UIColors.SURFACE_3, fg=UIColors.TEXT_2, activebackground=UIColors.SEP, relief=tk.FLAT, bd=0, cursor="hand2").pack(side=tk.LEFT, padx=1)
            tk.Button(f_btn, text="↓", width=2, command=lambda idx=i: move(idx, 1), bg=UIColors.SURFACE_3, fg=UIColors.TEXT_2, activebackground=UIColors.SEP, relief=tk.FLAT, bd=0, cursor="hand2").pack(side=tk.LEFT, padx=1)
            tk.Button(f_btn, text="削除", width=3, command=lambda idx=i: delete(idx), bg=UIColors.DANGER_BG, fg=UIColors.DANGER_FG, activebackground="#fbd5d2", activeforeground=UIColors.DANGER_FG, relief=tk.FLAT, bd=0, cursor="hand2").pack(side=tk.LEFT, padx=2)

            for c_idx, c_id, _c_txt, c_w in col_defs:
                if c_id == "btn":
                    continue

                f_cell = tk.Frame(sf, bg=UIColors.PANEL_BG, width=c_w, height=28)
                f_cell.pack_propagate(False)
                f_cell.grid(row=i, column=c_idx, sticky="w", padx=2, pady=2)

                if c_id in simple_entry_fields:
                    tk.Entry(f_cell, textvariable=item[c_id], relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT).pack(fill=tk.BOTH, expand=True)
                elif c_id in bool_fields:
                    tk.Checkbutton(f_cell, variable=item[c_id], bg=UIColors.PANEL_BG, activebackground=UIColors.PANEL_BG).pack(side=tk.LEFT)
                elif c_id == "priority":
                    om = tk.OptionMenu(f_cell, item["priority"], "3", "2", "1")
                    om.config(relief=tk.FLAT, bg="#ffffff", highlightthickness=0, font=("Consolas", 9))
                    om.pack(fill=tk.BOTH, expand=True)
                elif c_id == "type":
                    ttk.Combobox(f_cell, textvariable=item["type"], values=["エラー", "警告"], state="readonly", width=6).pack(fill=tk.BOTH, expand=True)
                elif c_id == "end":
                    tk.Entry(f_cell, textvariable=item["end"], relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT).pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    if key == "sections":
                        tk.Button(f_cell, text="V", width=4, command=lambda v=item["end"]: v.set(VSYNC_TAG), bg=UIColors.ROSE, fg="white", relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, fill=tk.Y, padx=1)
                elif c_id == "color":
                    tk.Entry(f_cell, textvariable=item["color"], width=7, relief=tk.FLAT, bd=0, highlightthickness=1, highlightbackground=UIColors.BORDER, highlightcolor=UIColors.ACCENT).pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                    tk.Button(f_cell, text="色", command=lambda v=item["color"]: v.set(colorchooser.askcolor(v.get())[1] or v.get()), bg=UIColors.ACCENT, fg="white", relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, fill=tk.Y, padx=1)

        def refresh():
            render_state["generation"] += 1
            generation = render_state["generation"]
            for widget in sf.winfo_children():
                widget.destroy()

            loading = tk.Label(sf, text="設定を読み込み中...", bg=UIColors.PANEL_BG, fg=UIColors.TEXT, padx=20, pady=12)
            loading.grid(row=0, column=0, sticky="w")

            def render_batch(start=0):
                if generation != render_state["generation"] or not dlg.winfo_exists():
                    return
                if start == 0:
                    loading.destroy()
                end = min(start + render_batch_size, len(entries))
                for row_index in range(start, end):
                    render_row(row_index, entries[row_index])
                if end < len(entries):
                    dlg.after(1, lambda: render_batch(end))
                else:
                    on_configure()

            # Return control to Tk first so the dialog itself appears immediately.
            dlg.after_idle(render_batch)

        def add(data=None, refresh_ui=True):
            item = {"enabled": tk.BooleanVar(value=data.get("enabled", True) if data else True)}
            item["_orig"] = dict(data) if data else {}   # 編集画面に出ない項目（HTML 版の項目など）も保存で残す
            for f in fields:
                if f in bool_fields:
                    # 新しく追加したエラー検出のルールは「単語単位」を ON にする
                    item[f] = tk.BooleanVar(value=bool(data.get(f, False)) if data else (f == "word"))
                elif f == "priority":
                    item[f] = tk.StringVar(value=str(clamp_level(data.get("priority", 1)) if data else 1))
                elif f == "type":
                    item[f] = tk.StringVar(value="警告" if data and data.get("type") == "warn" else "エラー")
                else:
                    def_val = ".*" if f == "file_pattern" else ""
                    val = data.get(f, def_val) if data and f in data else def_val
                    item[f] = tk.StringVar(value=str(val))
            entries.append(item)
            if refresh_ui:
                refresh()
            
        def delete(i): 
            del entries[i]
            refresh()
            
        def move(i, d): 
            if 0 <= i+d < len(entries): 
                entries[i], entries[i+d] = entries[i+d], entries[i]
                refresh()

        cfg = getattr(self, f"{key}_config")
        for c in cfg:
            add(c, refresh_ui=False)
        if not entries:
            add(None, refresh_ui=False)
        refresh()

        btn_fr = tk.Frame(fr, bg=UIColors.BG, width=250)
        btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        btn_fr.pack_propagate(False)
        # Reserve the operation panel first. Packing the expanding table first
        # pushed these controls outside the visible area on narrower screens.
        l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        flat_button(btn_fr, "＋ 行を追加", add, primary=True, width=20, pady=8).pack(pady=5, fill=tk.X)
        
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
                "【使い方】\n\n"
                "正規表現に一致したログを抽出し、色とコメントを付けます。\n\n"
                "字下げされた行は、直前の行とまとめて1件として判定します。\n\n"
                "「対象ファイル」はファイル名の正規表現です。\n\n"
                "■優先度（1〜3、3が一番強い）\n"
                "1行に複数一致したら、優先度が一番強いものの色とコメントが付きます。\n"
                "ツールバーの「優先度 N以上」で、その強さ以上のフィルタに一致した行だけを表示できます。"
            )
        elif key == "error_rules":
            info_text = (
                "【エラー検出の使い方】\n\n"
                "キーワードを含む行を、エラー・警告として知らせます。\n\n"
                "■知らせ方\n"
                " ・行番号の左に色の印\n"
                " ・タブとツールバーに件数\n"
                " ・F9 / Shift+F9 で次 / 前のエラーへ\n\n"
                "■項目\n"
                " ・キーワード: 正規表現も使えます\n"
                " ・種類: 両方に一致したらエラー\n"
                " ・単語単位: ERROR は NOERROR や\n"
                "   error_count に一致しません。\n"
                "   日本語のキーワードでは外してください\n"
                " ・大小区別: 大文字と小文字を区別\n\n"
                "すべて消して OK を押すと、\nエラー検出をしなくなります。"
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

        color_vars = {}
        if key == "error_rules":
            cat = tk.LabelFrame(btn_fr, text="種類の色", bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9, "bold"))
            cat.pack(fill=tk.X, pady=(6, 0))
            row = tk.Frame(cat, bg=UIColors.BG)
            row.pack(fill=tk.X, padx=6, pady=6)
            for typ, label in (("error", "エラー"), ("warn", "警告")):
                var = color_vars[typ] = tk.StringVar(value=self.error_colors[typ])
                btn = tk.Button(row, text="  ", width=3, bg=var.get(), activebackground=var.get(), relief=tk.FLAT, cursor="hand2")
                def pick(v=var, b=None):
                    c = colorchooser.askcolor(v.get(), parent=dlg)[1]
                    if c:
                        v.set(c)
                btn.config(command=pick)
                var.trace_add("write", lambda *_a, b=btn, v=var: b.config(bg=v.get(), activebackground=v.get()))
                btn.pack(side=tk.LEFT, padx=(0, 4))
                tk.Label(row, text=label, bg=UIColors.BG, fg=UIColors.TEXT, font=("Yu Gothic UI", 9)).pack(side=tk.LEFT, padx=(0, 10))

            def reset_defaults():
                entries.clear()
                for r in DEFAULT_ERROR_RULES:
                    add(r, refresh_ui=False)
                refresh()
                for typ, v in color_vars.items():
                    v.set(DEFAULT_ERROR_COLORS[typ])
            tk.Button(cat, text="既定に戻す", command=reset_defaults, bg="#ffffff", fg=UIColors.TEXT, relief=tk.FLAT, cursor="hand2", font=("Yu Gothic UI", 9)).pack(anchor="e", padx=6, pady=(0, 6))

        if info_text:
            info_lbl = tk.Label(btn_fr, text=info_text, justify=tk.LEFT, anchor="nw", bg="#ffffff", fg=UIColors.TEXT_2, relief=tk.FLAT, bd=0, highlightbackground=UIColors.SEP, highlightthickness=1, padx=12, pady=12, font=("Yu Gothic UI", 9), wraplength=230)
            info_lbl.pack(fill=tk.BOTH, expand=True, pady=10)
        
        def save():
            new_cfg =[]
            errs = []
            for n, item in enumerate(entries, start=1):
                valid = False
                for k in["pattern", "search", "start", "keyword"]:
                    if k in fields and item[k].get(): valid = True
                if valid:
                    d = dict(item["_orig"])
                    for f in fields:
                        v = item[f].get()
                        if f == "priority":
                            v = clamp_level(v)
                        elif f == "type":
                            v = "warn" if v == "警告" else "error"
                        d[f] = v
                    d["enabled"] = item["enabled"].get()
                    if key == "error_rules" and d["enabled"]:
                        try:
                            re.compile(d["keyword"])
                        except re.error as e:
                            errs.append(f"{n}行目「{d['keyword']}」: {e}")
                    new_cfg.append(d)
            if errs:
                messagebox.showerror("修正が必要です", "正規表現が正しくありません（無効にすれば保存できます）:\n" + "\n".join(errs), parent=dlg)
                return

            setattr(self, f"{key}_config", new_cfg)
            if color_vars:
                self.error_colors = {k: v.get() for k, v in color_vars.items()}
            # 設定変更時に自動的にconfig.jsonを保存
            self.save_config()
            
            dlg.destroy()
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.apply_display_update(w)
                except: pass

        flat_button(btn_fr, "OK", save, primary=True, width=20, pady=8).pack(side=tk.BOTTOM, pady=5, fill=tk.X)

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
                # 項目が無い設定（以前の設定）は既定のルールを使う。空の配列なら検出しない
                rules = d.get("error_rules")
                self.error_rules_config = rules if isinstance(rules, list) else [dict(r) for r in DEFAULT_ERROR_RULES]
                ec = d.get("error_colors") if isinstance(d.get("error_colors"), dict) else {}
                self.error_colors = {k: ec.get(k) if self._valid_color(ec.get(k)) else v for k, v in DEFAULT_ERROR_COLORS.items()}
                try:
                    self.gap_ms = max(0.0, float(d.get("gap_threshold_ms", self.gap_ms)))
                except (TypeError, ValueError):
                    self.gap_ms = DEFAULT_GAP_MS
                known = {"keywords", "sections", "replace_patterns", "vsync_auto_insert", "error_rules", "error_colors", "gap_threshold_ms"}
                self.extra_config = {k: v for k, v in d.items() if k not in known}

            self._update_vsync_info_label()
            self._sync_gap_input()
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

if __name__ == "__main__":
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()
