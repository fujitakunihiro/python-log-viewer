import re
import unittest

from log_viewer import _find_keyword_matches, _group_log_entries


def rule(pattern, file_pattern=".*"):
    return {
        "file_pat_re": re.compile(file_pattern, re.I),
        "regex": re.compile(pattern, re.I | re.DOTALL),
    }


class MultilineFilterTests(unittest.TestCase):
    def setUp(self):
        self.lines = [
            "[100013.500000] [INFO] System On Halting...",
            "               xxxx",
            "               yyyy",
            "               zzzz",
            "[100020.000000] [INFO] Normal operation",
        ]
        self.sources = ["sample.log"] * len(self.lines)

    def test_groups_indented_lines_as_one_entry(self):
        self.assertEqual(_group_log_entries(self.lines, self.sources), [(0, 4), (4, 5)])

    def test_header_match_selects_complete_entry(self):
        self.assertEqual(
            _find_keyword_matches(self.lines, self.sources, [rule("System On Halting")])[0],
            {0: 0, 1: 0, 2: 0, 3: 0},
        )

    def test_continuation_match_selects_complete_entry(self):
        self.assertEqual(
            _find_keyword_matches(self.lines, self.sources, [rule("yyyy")])[0],
            {0: 0, 1: 0, 2: 0, 3: 0},
        )

    def test_pattern_can_span_continuation_lines(self):
        self.assertEqual(
            _find_keyword_matches(self.lines, self.sources, [rule(r"Halting.*xxxx.*yyyy.*zzzz")])[0],
            {0: 0, 1: 0, 2: 0, 3: 0},
        )

    def test_does_not_match_across_entries(self):
        self.assertEqual(_find_keyword_matches(self.lines, self.sources, [rule(r"zzzz.*Normal")])[0], {})

    def test_only_entry_start_is_marked_for_comment(self):
        matches, comment_lines = _find_keyword_matches(self.lines, self.sources, [rule("yyyy")])
        self.assertEqual(matches, {0: 0, 1: 0, 2: 0, 3: 0})
        self.assertEqual(comment_lines, {0: 0})

    def test_single_line_entry_colors_only_itself(self):
        lines = ["[1] WARN a", "[2] DEBUG b", "[3] DEBUG c"]
        self.assertEqual(_find_keyword_matches(lines, ["a.log"] * 3, [rule("WARN")])[0], {0: 0})

    def test_does_not_group_across_merged_sources(self):
        self.assertEqual(
            _group_log_entries(["[1] header", "  continuation"], ["a.log", "b.log"]),
            [(0, 1), (1, 2)],
        )


class ReadOnlyTextTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from log_viewer import ReadOnlyText

        try:
            self.root = tk.Tk()
        except tk.TclError as e:
            self.skipTest(f"Tk unavailable: {e}")
        self.root.withdraw()
        self.text = ReadOnlyText(self.root)
        self.text.pack()
        self.text.insert("1.0", "hello\nworld")

    def tearDown(self):
        if hasattr(self, "root"):
            self.root.destroy()

    def test_programmatic_edits_are_allowed(self):
        self.text.delete("1.0", "end")
        self.text.insert("1.0", "abc")
        self.text.replace("1.0", "1.1", "X")
        self.assertEqual(self.text.get("1.0", "end-1c"), "Xbc")

    def test_user_edits_are_blocked(self):
        self.root.clipboard_clear()
        self.root.clipboard_append("PASTE")
        self.text.mark_set("insert", "1.0")
        self.text.event_generate("<<Paste>>")
        self.text.tag_add("sel", "1.0", "1.5")
        self.text.event_generate("<<Cut>>")
        # Tk のバインディングと同じく、ウィジェットコマンド経由の編集は捨てられる
        self.root.tk.call(self.text._w, "insert", "end", "typed")
        self.root.tk.call(self.text._w, "delete", "1.0", "end")
        self.assertEqual(self.text.get("1.0", "end-1c"), "hello\nworld")

    def test_selection_and_copy_still_work(self):
        self.text.tag_add("sel", "1.0", "1.5")
        self.text.event_generate("<<Copy>>")
        self.assertEqual(self.root.clipboard_get(), "hello")

    def test_caught_tcl_error_does_not_stop_mainloop(self):
        # 選択なしでの Ctrl+C（tk_textCopy）は catch 内で Tcl エラーになる
        def step():
            self.text.event_generate("<<Copy>>")
            with self.assertRaises(Exception):
                self.text.index("sel.first")
            self.root.after(50, self.root.quit)

        self.root.after(10, step)
        self.root.mainloop()  # 例外が再送出されないこと

    def test_destroy_removes_proxy_command(self):
        path = self.text._w
        self.text.destroy()
        self.assertEqual(self.root.tk.call("info", "commands", path), "")


class DisplayPipelineTests(unittest.TestCase):
    """解析キャッシュと表示行の決定。"""

    def setUp(self):
        import tkinter as tk
        import log_viewer as lv

        self.lv = lv
        try:
            self.root = tk.Tk()
        except tk.TclError as e:
            self.skipTest(f"Tk unavailable: {e}")
        self.root.withdraw()
        self.app = lv.LogViewerApp.__new__(lv.LogViewerApp)
        self.app.root = self.root
        self.app.keywords_config = [
            {"pattern": "ERROR", "color": "#ffcccc", "comment": "err", "enabled": True}
        ]
        self.app.sections_config = []
        self.app.replace_patterns_config = []
        self.app.vsync_config = dict(lv.DEFAULT_CONFIG["vsync_auto_insert"])
        self.app.use_keyword_filter = False
        self.app.show_vsync_lines = True
        self.app.advance_mode = False
        content = "\n".join([
            "[1.000] V_START",
            "[1.001] info",
            "[1.002] V_START",
            "[1.003] ERROR boom",
            "[1.004] V_START",
            "[1.005] V_START",
        ])
        self.tab = lv.LogTab(self.root, self.app, "a.log", content, source_files_list=["a.log"])

    def tearDown(self):
        if hasattr(self, "root"):
            self.root.destroy()

    def test_analysis_is_cached_until_config_or_content_changes(self):
        first = self.app._get_analysis(self.tab)
        self.assertIs(self.app._get_analysis(self.tab), first)
        self.app.keywords_config[0]["color"] = "#000000"
        second = self.app._get_analysis(self.tab)
        self.assertIsNot(second, first)
        self.tab.original_content = self.tab.original_content + "\n[1.006] x"
        self.assertIsNot(self.app._get_analysis(self.tab), second)

    def test_filter_shows_adjacent_vsync_lines(self):
        self.app.use_keyword_filter = True
        visible = self.app._compute_visibility(self.app._get_analysis(self.tab), ["a.log"])
        self.assertEqual(visible, [False, False, True, True, True, False])

    def test_render_writes_text_and_colors(self):
        self.app.use_keyword_filter = True
        self.app.apply_display_update(self.tab)
        self.assertEqual(self.tab.text.get("1.0", "end-1c"), "[1.002] V_START\n[1.003] ERROR boom\n[1.004] V_START")
        self.assertEqual([str(x) for x in self.tab.text.tag_ranges("kw_ffcccc")], ["2.0", "2.18"])
        self.assertEqual(self.tab.comment_text.get("2.0", "2.end"), "err")


if __name__ == "__main__":
    unittest.main()
