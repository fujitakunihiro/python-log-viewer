import re
import unittest

from log_viewer import _find_keyword_matches, _group_log_entries


def rule(pattern, extra=0, file_pattern=".*"):
    return {
        "file_pat_re": re.compile(file_pattern, re.I),
        "regex": re.compile(pattern, re.I | re.DOTALL),
        "extra": extra,
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

    def test_header_match_selects_complete_entry_without_extra_lines(self):
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

    def test_does_not_group_across_merged_sources(self):
        self.assertEqual(
            _group_log_entries(["[1] header", "  continuation"], ["a.log", "b.log"]),
            [(0, 1), (1, 2)],
        )


if __name__ == "__main__":
    unittest.main()
