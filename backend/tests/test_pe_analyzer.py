"""Needs the `pefile` package. Skipped automatically if it is not installed."""
import os
import struct

import pytest

pytest.importorskip("pefile")

from pe_analyzer import analyze_pe  # noqa: E402


def build_minimal_pe(section_name=b".text", section_data=None, characteristics=0x60000020):
    """Build the smallest PE32 file pefile will accept: one section, no imports."""
    raw = (section_data if section_data is not None else b"\x90" * 64).ljust(512, b"\x00")

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew -> PE signature right after the DOS header

    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0x5F000000, 0, 0, 224, 0x0102)

    optional = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "IIII" + "HH" + "I" * 5 + "I",
        0x10B, 14, 0,
        512, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0,
        0, 0x2000, 0x200, 0,
        3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0,
        16,
    ) + bytes(16 * 8)  # 16 empty data-directory entries

    section = struct.pack(
        "<8sIIIIIIHHI",
        section_name.ljust(8, b"\x00"), len(raw), 0x1000, 512, 0x200, 0, 0, 0, 0, characteristics,
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + section
    return headers.ljust(0x200, b"\x00") + raw


def test_parses_minimal_pe():
    info = analyze_pe(build_minimal_pe())
    assert "error" not in info
    assert info["sections"][0]["name"] == ".text"
    assert info["sections"][0]["executable"] is True
    assert info["imports"] == []
    assert info["import_function_count"] == 0


def test_reports_high_entropy_section():
    info = analyze_pe(build_minimal_pe(section_data=bytes(range(256)) * 2))
    assert info["sections"][0]["entropy"] == 8.0


def test_reports_section_name_and_flags():
    info = analyze_pe(build_minimal_pe(section_name=b"UPX0", characteristics=0xE0000080))
    section = info["sections"][0]
    assert section["name"] == "UPX0"
    assert section["writable"] is True
    assert section["executable"] is True


def test_garbage_returns_error_instead_of_raising():
    assert "error" in analyze_pe(b"MZ" + b"\x90" * 100)
