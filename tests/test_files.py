from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from mcp_ci.files import atomic_write_text


class AtomicWriteTests(unittest.TestCase):
    def test_atomic_write_creates_parent_and_replaces_complete_text(self) -> None:
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "report.json"

            atomic_write_text(destination, "new report\n")

            self.assertEqual(destination.read_text(encoding="utf-8"), "new report\n")
            self.assertEqual(
                list(destination.parent.glob(f".{destination.name}.*.tmp")), []
            )

    def test_failed_replace_preserves_destination_and_cleans_temporary_file(self) -> None:
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            destination.write_text("reviewed report\n", encoding="utf-8")

            with patch(
                "mcp_ci.files.os.replace", side_effect=OSError("replace failed")
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    atomic_write_text(destination, "partial replacement\n")

            self.assertEqual(
                destination.read_text(encoding="utf-8"), "reviewed report\n"
            )
            self.assertEqual(
                list(destination.parent.glob(f".{destination.name}.*.tmp")), []
            )


if __name__ == "__main__":
    unittest.main()
