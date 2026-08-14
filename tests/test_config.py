from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from repo_doctor_ai.config import Config, ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_defaults_are_bounded(self) -> None:
        config = Config()
        self.assertLessEqual(config.max_file_bytes, 64 * 1024 * 1024)
        self.assertIn("secrets", config.enabled_categories)

    def test_unknown_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unknown"):
            Config.from_dict({"config_version": "1.0", "surprise": True})

    def test_duplicate_categories_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "duplicates"):
            Config.from_dict({"enabled_categories": ["tests", "tests"]})

    def test_parent_exclude_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "safe relative"):
            Config.from_dict({"exclude": ["../outside"]})

    def test_timeout_outside_bounds_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "timeout_seconds"):
            Config.from_dict({"timeout_seconds": 0})

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"config_version":"1.0","config_version":"1.0"}', encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "duplicate JSON key"):
                load_config(path)

    def test_round_trip(self) -> None:
        original = Config()
        self.assertEqual(Config.from_dict(original.as_dict()), original)


if __name__ == "__main__":
    unittest.main()

