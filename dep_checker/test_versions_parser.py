#!/usr/bin/env python3
"""Tests for version parsing from Node's dependency headers"""

import tempfile
from pathlib import Path

import versions_parser


def test_c_ares_version_with_aligned_define() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        header = Path(temp_dir) / "deps" / "cares" / "include" / "ares_version.h"
        header.parent.mkdir(parents=True)
        # c-ares aligns its defines with several spaces.
        header.write_text('#define ARES_VERSION_MAJOR 1\n#define ARES_VERSION_STR   "1.34.9"\n')
        assert versions_parser.get_c_ares_version(Path(temp_dir)) == "1.34.9"


if __name__ == "__main__":
    test_c_ares_version_with_aligned_define()
    print("versions_parser tests passed")
