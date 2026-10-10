"""GUI launcher helpers (no window open)."""

from __future__ import annotations

import unittest

from shell import gui


class GuiHelperTests(unittest.TestCase):
    def test_with_local_libs_noop_when_missing(self) -> None:
        env = gui._with_local_libs({"FOO": "1"})
        self.assertEqual(env["FOO"], "1")

    def test_playwright_chrome_optional(self) -> None:
        # May be None in CI without playwright browsers — must not raise.
        path = gui._playwright_chrome()
        if path is not None:
            self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
