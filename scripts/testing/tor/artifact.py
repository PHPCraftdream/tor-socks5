#!/usr/bin/env python3
"""Fail-closed Cargo artifact and libtest receipts for isolated Tor CI."""
import json
import os
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
REAL_TEST = "real_private_stream::owned_three_hop_round_trip"
LINE_LIMIT = 4 * 1024 * 1024
TOTAL_LIMIT = 128 * 1024 * 1024
MECHANISM_RESULT = re.compile(
    r"test result: ok\. 17 passed; 0 failed; 1 ignored; "
    r"0 measured; 0 filtered out; finished in [^\r\n]+"
)


def lines(stream):
    total = 0
    while True:
        line = stream.readline(LINE_LIMIT + 1)
        if not line:
            return
        total += len(line)
        if len(line) > LINE_LIMIT or total > TOTAL_LIMIT:
            raise ValueError("Tor test input exceeds its size limit")
        yield line.decode("utf-8")


def owned_path(value, expected):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("Cargo artifact owner must be an absolute path")
    if Path(value).resolve() != expected.resolve():
        raise ValueError("Cargo artifact has the wrong source owner")


def executable(value):
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("Invalid owned_stream executable path")
    path = Path(value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or not os.access(path, os.X_OK)
        or path.resolve(strict=True) != path
    ):
        raise ValueError("Expected an absolute canonical executable file")
    return value


def select(stream, root=ROOT):
    found = []
    finished = 0
    for line in lines(stream):
        message = json.loads(line)
        if not isinstance(message, dict):
            raise ValueError("Cargo message must be an object")
        reason = message.get("reason")
        if reason == "build-finished":
            if message.get("success") is not True:
                raise ValueError("Cargo build did not succeed")
            finished += 1
        if reason != "compiler-artifact":
            continue
        target = message.get("target")
        if not isinstance(target, dict):
            raise ValueError("Malformed Cargo target")
        if target.get("name") != "owned_stream":
            continue
        profile = message.get("profile")
        if (
            target.get("kind") != ["test"]
            or target.get("crate_types") != ["bin"]
            or not isinstance(profile, dict)
            or profile.get("test") is not True
        ):
            raise ValueError("owned_stream is not an integration-test executable")
        owned_path(
            message.get("manifest_path"),
            root / "packages/arti-wrapper/Cargo.toml",
        )
        owned_path(
            target.get("src_path"),
            root / "packages/arti-wrapper/tests/owned_stream.rs",
        )
        found.append(executable(message.get("executable")))
    if finished != 1 or len(found) != 1:
        raise ValueError("Expected one successful build and one owned_stream artifact")
    return found[0]


def ignored(stream):
    actual = [line.strip() for line in lines(stream) if line.strip()]
    expected = [REAL_TEST + ": test", "1 test, 0 benchmarks"]
    if actual != expected:
        raise ValueError("Expected exactly the owned three-hop ignored test")


def mechanisms(stream, output):
    summaries = []
    for line in lines(stream):
        output.write(line)
        stripped = line.rstrip("\r\n")
        if stripped.startswith("test result:"):
            summaries.append(stripped)
    if len(summaries) != 1 or MECHANISM_RESULT.fullmatch(summaries[0]) is None:
        raise ValueError("Expected all 17 mechanisms, one ignored test, and no filtering")
    output.write("Tor owned stream Rust mechanism controls passed: 17\n")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "select":
        with open(sys.argv[2], "rb") as stream:
            print(select(stream))
    elif sys.argv[1:] == ["ignored"]:
        ignored(sys.stdin.buffer)
    elif sys.argv[1:] == ["mechanisms"]:
        mechanisms(sys.stdin.buffer, sys.stdout)
    else:
        raise ValueError("Expected select FILE, ignored, or mechanisms")


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        print("Tor stream CI input rejected: " + str(error), file=sys.stderr)
        raise SystemExit(1)
