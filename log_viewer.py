"""Simple Tkinter log viewer

要件:
- tkinterでGUIを作る
- ファイルを開いてテキストを表示する
- 特定のキーワード（ERROR, WARN, INFO）を色付けする
- キーワードと色を設定ファイル(JSON)で保存・読み込みできる

使い方:
 - 起動: python log_viewer.py
 - File -> Open でログファイルを開く
 - Config -> Load/Save で JSON 設定を読み書き
 - Config -> Edit Keywords でキーワードと色を編集
 - Config -> Edit Replace で文字列を別の文字列に置き換えを編集

このファイルは最小限の実用的実装です。
"""


from __future__ import annotations

import json
import os
import re
import sys
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox
from typing import Dict
# --- DnD ---
try:
	from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
	TkinterDnD = None
	DND_FILES = None


DEFAULT_CONFIG = {
	"ERROR": "#ff0000",
	"WARN": "#ff8800",
	"INFO": "#008800",
}


class LogViewerApp:
	def __init__(self, root: tk.Tk) -> None:
		self.root = root
		root.title("Log Viewer")

		self.config_path = os.path.join(os.path.dirname(__file__), "config.json")
		self.keyword_colors: Dict[str, str] = DEFAULT_CONFIG.copy()
		self.replace_patterns: list[tuple[str, str, bool]] = []  # (search, replace, match_case)

		self._build_ui()
		# load config if exists
		if os.path.exists(self.config_path):
			try:
				self.load_config(self.config_path)
			except Exception:
				# non-fatal
				print("Failed to load default config", file=sys.stderr)

	def _build_ui(self) -> None:
		menubar = tk.Menu(self.root)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="Open...", command=self.open_file)
		filemenu.add_command(label="Replace...", command=self.replace_dialog)
		filemenu.add_separator()
		filemenu.add_command(label="Exit", command=self.root.quit)
		menubar.add_cascade(label="File", menu=filemenu)

		configmenu = tk.Menu(menubar, tearoff=0)
		configmenu.add_command(label="Load Config...", command=self.load_config_dialog)
		configmenu.add_command(label="Save Config...", command=self.save_config_dialog)
		configmenu.add_separator()
		configmenu.add_command(label="Edit Keywords...", command=self.edit_keywords_dialog)
		configmenu.add_command(label="Edit Replace...", command=self.edit_replace_patterns_dialog)
		menubar.add_cascade(label="Config", menu=configmenu)

		self.root.config(menu=menubar)

		# Text widget with vertical scrollbar
		frame = tk.Frame(self.root)
		frame.pack(fill=tk.BOTH, expand=True)

		self.text = tk.Text(frame, wrap=tk.NONE)
		self.vsb = tk.Scrollbar(frame, orient=tk.VERTICAL, command=self.text.yview)
		self.hsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.text.xview)
		self.text.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)

		self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
		self.hsb.pack(side=tk.BOTTOM, fill=tk.X)
		self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

		# Drag & Drop support
		if TkinterDnD and hasattr(self.text, 'drop_target_register'):
			self.text.drop_target_register(DND_FILES)
			self.text.dnd_bind('<<Drop>>', self._on_drop_file)

		# status bar
		self.status = tk.Label(self.root, text="Ready", anchor=tk.W)
		self.status.pack(fill=tk.X, side=tk.BOTTOM)

	def _on_drop_file(self, event):
		path = event.data.strip()
		if path.startswith('{') and path.endswith('}'):
			path = path[1:-1]
		if ' ' in path:
			path = path.split(' ')[0]
		if os.path.isfile(path):
			self._open_file_path(path)

	def _open_file_path(self, path: str) -> None:
		try:
			with open(path, "r", encoding="utf-8", errors="replace") as f:
				data = f.read()
		except Exception as e:
			messagebox.showerror("Open file", f"Failed to open file:\n{e}")
			return


		before = data
		after = data
		replaced = False
		if self.replace_patterns:
			for search, replace, match_case in self.replace_patterns:
				if match_case:
					new_after = after.replace(search, replace)
				else:
					new_after = re.sub(re.escape(search), replace, after, flags=re.IGNORECASE)
				if new_after != after:
					replaced = True
				after = new_after

		self.text.delete("1.0", tk.END)
		self.text.insert("1.0", after)
		if replaced:
			self.status.config(text=f"Opened and replaced text: {path}")
		else:
			self.status.config(text=f"Opened: {path}")
		self.highlight_keywords()



	# ---------- file / config operations ----------
	def open_file(self) -> None:
		path = filedialog.askopenfilename(title="Open log file", filetypes=[("All files", "*")])
		if not path:
			return
		self._open_file_path(path)

	def load_config_dialog(self) -> None:
		path = filedialog.askopenfilename(title="Load config", defaultextension=".json", filetypes=[("JSON files","*.json"), ("All files","*")])
		if not path:
			return
		try:
			self.load_config(path)
			messagebox.showinfo("Load config", "Config loaded")
		except Exception as e:
			messagebox.showerror("Load config", f"Failed to load config:\n{e}")

	def save_config_dialog(self) -> None:
		path = filedialog.asksaveasfilename(title="Save config", defaultextension=".json", filetypes=[("JSON files","*.json"), ("All files","*")])
		if not path:
			return
		try:
			self.save_config(path)
			messagebox.showinfo("Save config", "Config saved")
		except Exception as e:
			messagebox.showerror("Save config", f"Failed to save config:\n{e}")

	def load_config(self, path: str) -> None:
		with open(path, "r", encoding="utf-8") as f:
			data = json.load(f)
		if not isinstance(data, dict):
			raise ValueError("Config must be a JSON object")
			
		# Load keyword colors
		colors = data.get("colors", {})
		if not isinstance(colors, dict):
			raise ValueError("'colors' must be a JSON object mapping keywords to color strings")
		self.keyword_colors = {str(k): str(v) for k, v in colors.items()}
		
		# Load replace patterns
		patterns = data.get("replace_patterns", [])
		if not isinstance(patterns, list):
			raise ValueError("'replace_patterns' must be a JSON array")
		self.replace_patterns = [(str(p["search"]), str(p["replace"]), bool(p["match_case"])) 
							   for p in patterns]
		
		self.highlight_keywords()

	def save_config(self, path: str) -> None:
		data = {
			"colors": self.keyword_colors,
			"replace_patterns": [
				{"search": s, "replace": r, "match_case": m}
				for s, r, m in self.replace_patterns
			]
		}
		with open(path, "w", encoding="utf-8") as f:
			json.dump(data, f, ensure_ascii=False, indent=2)

	# ---------- keyword editing UI ----------
	def edit_keywords_dialog(self) -> None:
		dlg = tk.Toplevel(self.root)
		dlg.title("Edit Keywords")
		dlg.transient(self.root)
		dlg.grab_set()

		rows_frame = tk.Frame(dlg)
		rows_frame.pack(padx=8, pady=8, fill=tk.BOTH, expand=True)

		entries = []

		def add_row(key: str = "", color: str = "#000000"):
			row = tk.Frame(rows_frame)
			row.pack(fill=tk.X, pady=2)
			kvar = tk.StringVar(value=key)
			cvar = tk.StringVar(value=color)
			kentry = tk.Entry(row, textvariable=kvar, width=20)
			centry = tk.Entry(row, textvariable=cvar, width=12)
			def pick_color():
				col = colorchooser.askcolor(cvar.get(), parent=dlg)
				if col and col[1]:
					cvar.set(col[1])
			pick_btn = tk.Button(row, text="…", width=2, command=pick_color)
			del_btn = tk.Button(row, text="-", width=2, command=lambda: (row.destroy(), entries.remove((kvar, cvar))))
			kentry.pack(side=tk.LEFT, padx=(0,6))
			centry.pack(side=tk.LEFT)
			pick_btn.pack(side=tk.LEFT, padx=4)
			del_btn.pack(side=tk.LEFT, padx=4)
			entries.append((kvar, cvar))

		# populate existing
		for k, v in self.keyword_colors.items():
			add_row(k, v)

		add_btn = tk.Button(dlg, text="Add", command=lambda: add_row())
		add_btn.pack(pady=(0,6))

		def on_ok():
			new_map: Dict[str, str] = {}
			for kvar, cvar in entries:
				key = kvar.get().strip()
				col = cvar.get().strip()
				if not key:
					continue
				# basic validation for color
				if not col.startswith("#"):
					messagebox.showerror("Edit Keywords", f"Invalid color for {key}: {col}")
					return
				new_map[key] = col
			self.keyword_colors = new_map
			self.highlight_keywords()
			dlg.destroy()

		btn_frame = tk.Frame(dlg)
		btn_frame.pack(fill=tk.X, pady=(0,8))
		ok_btn = tk.Button(btn_frame, text="OK", width=10, command=on_ok)
		cancel_btn = tk.Button(btn_frame, text="Cancel", width=10, command=dlg.destroy)
		ok_btn.pack(side=tk.RIGHT, padx=4)
		cancel_btn.pack(side=tk.RIGHT)

	# ---------- replace patterns editing ----------
	def edit_replace_patterns_dialog(self) -> None:
		dlg = tk.Toplevel(self.root)
		dlg.title("Edit Replace Patterns")
		dlg.transient(self.root)
		dlg.grab_set()

		rows_frame = tk.Frame(dlg)
		rows_frame.pack(padx=8, pady=8, fill=tk.BOTH, expand=True)

		entries = []

		def add_row(search: str = "", replace: str = "", match_case: bool = False):
			row = tk.Frame(rows_frame)
			row.pack(fill=tk.X, pady=2)
			search_var = tk.StringVar(value=search)
			replace_var = tk.StringVar(value=replace)
			case_var = tk.BooleanVar(value=match_case)
			
			search_entry = tk.Entry(row, textvariable=search_var, width=20)
			replace_entry = tk.Entry(row, textvariable=replace_var, width=20)
			case_check = tk.Checkbutton(row, text="Aa", variable=case_var)
			del_btn = tk.Button(row, text="-", width=2, 
							   command=lambda: (row.destroy(), entries.remove((search_var, replace_var, case_var))))
			
			search_entry.pack(side=tk.LEFT, padx=(0,6))
			replace_entry.pack(side=tk.LEFT, padx=(0,6))
			case_check.pack(side=tk.LEFT)
			del_btn.pack(side=tk.LEFT, padx=4)
			entries.append((search_var, replace_var, case_var))

		# header
		header = tk.Frame(rows_frame)
		header.pack(fill=tk.X, pady=(0,4))
		tk.Label(header, text="Find", width=20).pack(side=tk.LEFT, padx=(0,6))
		tk.Label(header, text="Replace", width=20).pack(side=tk.LEFT, padx=(0,6))
		tk.Label(header, text="Case").pack(side=tk.LEFT)

		# populate existing
		for search, replace, match_case in self.replace_patterns:
			add_row(search, replace, match_case)

		add_btn = tk.Button(dlg, text="Add Pattern", command=lambda: add_row())
		add_btn.pack(pady=(0,6))

		def on_ok():
			patterns = []
			for svar, rvar, cvar in entries:
				search = svar.get().strip()
				replace = rvar.get().strip()
				if not search:
					continue
				patterns.append((search, replace, cvar.get()))
			self.replace_patterns = patterns
			dlg.destroy()

		btn_frame = tk.Frame(dlg)
		btn_frame.pack(fill=tk.X, pady=(0,8))
		ok_btn = tk.Button(btn_frame, text="OK", width=10, command=on_ok)
		cancel_btn = tk.Button(btn_frame, text="Cancel", width=10, command=dlg.destroy)
		ok_btn.pack(side=tk.RIGHT, padx=4)
		cancel_btn.pack(side=tk.RIGHT)

	def apply_replace_patterns(self) -> None:
		content = self.text.get("1.0", tk.END)
		modified = False

		for search, replace, match_case in self.replace_patterns:
			if match_case:
				new_content = content.replace(search, replace)
			else:
				new_content = re.sub(re.escape(search), replace, content, flags=re.IGNORECASE)
			
			if new_content != content:
				modified = True
				content = new_content

		if modified:
			self.text.delete("1.0", tk.END)
			self.text.insert("1.0", content)
			self.highlight_keywords()
			return True
		return False

	# ---------- replace dialog ----------
	def replace_dialog(self) -> None:
		dlg = tk.Toplevel(self.root)
		dlg.title("Replace Text")
		dlg.transient(self.root)
		dlg.grab_set()
		dlg.geometry("300x150")

		# Search frame
		search_frame = tk.Frame(dlg)
		search_frame.pack(fill=tk.X, padx=8, pady=(8,4))
		tk.Label(search_frame, text="Find:").pack(side=tk.LEFT)
		search_var = tk.StringVar()
		search_entry = tk.Entry(search_frame, textvariable=search_var)
		search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4,0))

		# Replace frame
		replace_frame = tk.Frame(dlg)
		replace_frame.pack(fill=tk.X, padx=8, pady=4)
		tk.Label(replace_frame, text="Replace:").pack(side=tk.LEFT)
		replace_var = tk.StringVar()
		replace_entry = tk.Entry(replace_frame, textvariable=replace_var)
		replace_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4,0))

		# Options frame
		options_frame = tk.Frame(dlg)
		options_frame.pack(fill=tk.X, padx=8, pady=4)
		match_case = tk.BooleanVar(value=False)
		tk.Checkbutton(options_frame, text="Match case", variable=match_case).pack(side=tk.LEFT)

		def do_replace() -> None:
			search_text = search_var.get()
			replace_text = replace_var.get()
			if not search_text:
				messagebox.showwarning("Replace", "Please enter text to find")
				return

			content = self.text.get("1.0", tk.END)
			if match_case.get():
				new_content = content.replace(search_text, replace_text)
			else:
				new_content = re.sub(re.escape(search_text), replace_text, content, flags=re.IGNORECASE)

			if new_content != content:
				self.text.delete("1.0", tk.END)
				self.text.insert("1.0", new_content)
				self.highlight_keywords()
				messagebox.showinfo("Replace", "Replacement completed")
			else:
				messagebox.showinfo("Replace", "No matches found")

		# Buttons frame
		btn_frame = tk.Frame(dlg)
		btn_frame.pack(fill=tk.X, pady=(8,8), padx=8)
		replace_btn = tk.Button(btn_frame, text="Replace All", width=10, command=do_replace)
		cancel_btn = tk.Button(btn_frame, text="Cancel", width=10, command=dlg.destroy)
		replace_btn.pack(side=tk.RIGHT, padx=(4,0))
		cancel_btn.pack(side=tk.RIGHT)

	# ---------- highlighting ----------
	def clear_highlight_tags(self) -> None:
		for tag in list(self.text.tag_names()):
			self.text.tag_delete(tag)

	def highlight_keywords(self) -> None:
		# remove previous tags
		self.clear_highlight_tags()
		content = self.text.get("1.0", tk.END)
		if not content:
			return

		for key, color in self.keyword_colors.items():
			try:
				# create tag
				tag_name = f"kw_{key}"
				self.text.tag_configure(tag_name, background=color)
				# find occurrences using Python regex (word-boundary, ignore case)
				pattern = re.compile(r"\b" + re.escape(key) + r"\b", flags=re.IGNORECASE)
				for m in pattern.finditer(content):
					start_idx = f"1.0+{m.start()}c"
					end_idx = f"1.0+{m.end()}c"
					self.text.tag_add(tag_name, start_idx, end_idx)
			except Exception:
				# ignore tag errors
				continue



def main() -> None:
	if TkinterDnD:
		root = TkinterDnD.Tk()
	else:
		root = tk.Tk()
	app = LogViewerApp(root)
	root.geometry("900x600")
	root.mainloop()


if __name__ == "__main__":
	main()
