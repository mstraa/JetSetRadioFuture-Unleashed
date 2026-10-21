"""
Seed list for the functions the discovery pass misses in JSRF.

The release build links two tables port/recomp_manual.c expects,
g_recomp_seeded (functions only reached from vtables and state-handler tables
in the data sections) and g_recomp_holes (functions reached by direct calls
the detector never started), and a dozen functions it wraps as sub_X_gen.
None of that is produced by the public pipeline, so a build from it fails to
link. This finds those entry points from the XBE and the last pass's output
and writes them as a --seed-functions file for tools.disasm, so the next pass
lifts them as ordinary functions; it also writes empty tables for the two
symbols, which are then not needed for lookup.

Only addresses that fall in a gap -- inside no detected function -- are
seeded from the stubs and the data scan, so none of them can cut a function
short (see tools.disasm --seed-functions). The sub_X_gen addresses are seeded
whatever they fall in: the release has them as functions of their own.

    python3 -m tools.jsrf_seeds XBE --gen-dir port/recomp/gen
"""

import argparse
import bisect
import json
import os
import re
import struct
import sys

from tools.abi_analysis.xbe_min import XbeFile
from tools.disasm.loader import DATA_SECTION_NAMES

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

PROLOGUES = (b"\x55\x8B\xEC", b"\x83\xEC", b"\x81\xEC", b"\x6A\xFF\x68",
             b"\x64\xA1\x00\x00\x00\x00")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xbe")
    ap.add_argument("--gen-dir", default=os.path.join(ROOT, "port", "recomp", "gen"))
    ap.add_argument("--functions", default=os.path.join(ROOT, "tools", "disasm", "output", "functions.json"))
    ap.add_argument("--manual", default=os.path.join(ROOT, "port", "recomp_manual.c"))
    ap.add_argument("--out", default=os.path.join(ROOT, "tools", "jsrf_seeds", "output", "seeds.json"))
    a = ap.parse_args()

    xbe = XbeFile(a.xbe)
    # What tools.disasm takes for code without --text-only (loader.py):
    # the release lifts the library sections (D3D, DSOUND, XPP, ...) too.
    code = [s for s in xbe.sections
            if (s.flags & 0x4) and s.raw_size > 0 and s.name not in DATA_SECTION_NAMES]
    datas = [s for s in xbe.sections if s.name in DATA_SECTION_NAMES and s.raw_size >= 4]

    def in_code(va):
        return any(s.contains_va(va) for s in code)

    funcs = json.load(open(a.functions))
    starts = sorted(int(f["start"], 16) for f in funcs)
    ranges = sorted((int(f["start"], 16), int(f["end"], 16)) for f in funcs)
    rs = [r[0] for r in ranges]
    known = set(starts)

    def in_function(va):
        i = bisect.bisect_right(rs, va) - 1
        return i >= 0 and ranges[i][0] <= va < ranges[i][1]

    def code_at(va, n=8):
        b = xbe.read_bytes_at_va(va, n)
        return b or b""

    def plausible(va):
        b = code_at(va)
        return len(b) >= 2 and b[0] not in (0x00, 0xCC, 0x90) and b[:2] != b"\x00\x00"

    old = set()
    if os.path.exists(a.out):
        old = {int(e["start"], 16) for e in json.load(open(a.out))}

    seeds = {}

    # 1. what recomp_manual.c wraps as sub_X_gen
    src = open(a.manual, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r"^extern void sub_([0-9A-Fa-f]{8})_gen\(void\);", src, re.M):
        va = int(m.group(1), 16)
        if va not in known and in_code(va):
            seeds[va] = "wrapped"

    # 2. direct-call targets left as stubs that sit in a gap
    #
    # And those inside a function, when they start one of its instructions:
    # a tail jump into the middle of another function (a shared epilogue or
    # body). The stub does nothing, so the jump silently did nothing: JSRF's
    # sub_000DA710, 9 KB of code in the release, was an empty stub here.
    # Seeding it cuts the function it is in there; the first
    # part falls through into it as a tail call, and a jump back across the
    # cut becomes a stub the next pass seeds in turn.
    def insn_start(va):
        i = bisect.bisect_right(rs, va) - 1
        lo, hi = ranges[i]
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        for ins in md.disasm(code_at(lo, hi - lo), lo):
            if ins.address >= va:
                return ins.address == va
        return False

    stub = os.path.join(a.gen_dir, "recomp_stubs_unresolved.c")
    if os.path.exists(stub):
        for m in re.finditer(r"/\* 0x([0-9A-Fa-f]{8}):", open(stub).read()):
            va = int(m.group(1), 16)
            if not in_code(va) or va in known or not plausible(va):
                continue
            if not in_function(va):
                seeds.setdefault(va, "hole")
            elif insn_start(va):
                seeds.setdefault(va, "tail")

    # 3. pointers into code from the data sections that start nothing yet
    for s in datas:
        data = xbe.data[s.raw_address:s.raw_address + s.raw_size]
        ptrs = [struct.unpack_from("<I", data, o)[0] for o in range(0, len(data) - 3, 4)]
        for i, va in enumerate(ptrs):
            if not in_code(va) or va in known or in_function(va) or not plausible(va):
                continue
            run = (i > 0 and in_code(ptrs[i - 1])) or (i + 1 < len(ptrs) and in_code(ptrs[i + 1]))
            if run or code_at(va).startswith(PROLOGUES):
                seeds.setdefault(va, "data")

    allseeds = sorted(set(seeds) | old)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump([{"start": f"0x{v:08X}", "why": seeds.get(v, "earlier pass")} for v in allseeds],
              open(a.out, "w"), indent=1)

    # The generated dispatch table maps a wrapped function's address to its
    # body, sub_X_gen, so an indirect call skipped the wrapper (the spin
    # thread, 0x0013B180, ran the guest's busy loop and held the lock for
    # ever). recomp_lookup_manual() asks g_recomp_holes before that table:
    # list every wrapper there.
    from tools.recomp.manual_scan import scan as scan_manual
    skip, wrap, _ = scan_manual(a.manual)
    wrapped = sorted(wrap & skip)
    tables = os.path.join(a.gen_dir, "recomp_jsrf_tables.c")
    os.makedirs(a.gen_dir, exist_ok=True)
    with open(tables, "w") as f:
        f.write("/* Written by tools.jsrf_seeds. The seeded functions are lifted as\n"
                " * ordinary functions here, so g_recomp_seeded stays empty; g_recomp_holes\n"
                " * routes indirect calls to the hand-written wrappers in recomp_manual.c\n"
                " * rather than to the sub_X_gen bodies the dispatch table names. */\n"
                "#include <stdint.h>\n"
                "typedef void (*jsrf_fn_t)(void);\n")
        for v in wrapped:
            f.write(f"extern void sub_{v:08X}(void);\n")
        f.write("const struct { uint32_t va; jsrf_fn_t fn; } g_recomp_seeded[1] = { { 0, 0 } };\n"
                "const unsigned g_recomp_seeded_count = 0;\n"
                f"const struct {{ uint32_t va; jsrf_fn_t fn; }} g_recomp_holes[{max(1, len(wrapped))}] = {{\n")
        f.write("".join(f"    {{ 0x{v:08X}u, sub_{v:08X} }},\n" for v in wrapped) or "    { 0, 0 },\n")
        f.write(f"}};\nconst unsigned g_recomp_holes_count = {len(wrapped)};\n")

    new = sorted(set(seeds) - old)
    by = {}
    for v in new:
        by[seeds[v]] = by.get(seeds[v], 0) + 1
    print(f"jsrf_seeds: {len(new)} new ({', '.join(f'{k} {n}' for k, n in sorted(by.items())) or 'none'}),"
          f" {len(allseeds)} in all -> {a.out}")
    print(f"NEW={len(new)}")


if __name__ == "__main__":
    main()
