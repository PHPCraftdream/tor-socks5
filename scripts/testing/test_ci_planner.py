#!/usr/bin/env python3
"""Изолированные проверки маршрутизации без git и cargo.

Сами проверки лежат в planner_tests/ (support.py — общий каркас); этот файл
остаётся точкой входа для CI: `python -I scripts/testing/test_ci_planner.py`.
"""
import os
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent / "planner_tests"


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Проверки планировщика разрешены только в CI")
    sys.path.insert(0, str(TESTS))
    suite = unittest.defaultTestLoader.discover(str(TESTS), pattern="test_*.py", top_level_dir=str(TESTS))
    sys.exit(0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1)
