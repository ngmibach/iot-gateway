from __future__ import annotations

import unittest
from pathlib import Path


class IDSBundleLineEndingTests(unittest.TestCase):
    def test_gateway_ids_text_assets_use_lf(self) -> None:
        root = Path(__file__).parents[1]
        binary_suffixes = {".joblib", ".pyc"}
        invalid: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() in binary_suffixes:
                continue
            if b"\r\n" in path.read_bytes():
                invalid.append(str(path.relative_to(root)))
        self.assertEqual(invalid, [], f"CRLF in gateway IDS assets: {invalid}")


if __name__ == "__main__":
    unittest.main()
