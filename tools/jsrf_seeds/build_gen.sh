#!/bin/sh
# Generate port/recomp/gen from your default.xbe, seeding the functions the
# discovery pass misses until a pass finds nothing new (at most 5 passes).
#   tools/jsrf_seeds/build_gen.sh "/path/to/default.xbe"
set -e
XBE="$1"
[ -f "$XBE" ] || { echo "usage: $0 /path/to/default.xbe"; exit 1; }
cd "$(dirname "$0")/../.."
PY=${PYTHON:-python3}
SEEDS=tools/jsrf_seeds/output/seeds.json
ANALYSIS="$(dirname "$XBE")/$(basename "$XBE" .xbe)_analysis.json"
rm -f "$SEEDS"
# What the last run measured: every indirect call the game made, written as
# icall_targets.dump into the game folder when it quits. Targets that were
# not functions yet are seeded too (tools/recomp/icall_feedback.py), and the
# database keeps them from run to run, so each run lets the next build lift
# further into the game.
ICALL_SEEDS=tools/jsrf_seeds/output/icall_seeds.json
DUMP="$(dirname "$XBE")/icall_targets.dump"
mkdir -p tools/jsrf_seeds/output
if [ -f "$DUMP" ]; then
    $PY -m tools.recomp.icall_feedback merge "$DUMP"
    $PY -m tools.recomp.icall_feedback seeds --xbe "$XBE" --out "$ICALL_SEEDS"
fi
[ -f "$ANALYSIS" ] || $PY -m tools.xbe_parser "$XBE" --json "$ANALYSIS"
pass=1
while :; do
    echo "=== pass $pass ==="
    # Every code section, not only .text: the release lifts D3D's and the
    # other libraries' functions too, and the game calls them indirectly.
    set -- --force
    [ -f "$SEEDS" ] && set -- "$@" --seed-functions "$SEEDS"
    [ -f "$ICALL_SEEDS" ] && set -- "$@" --seed-functions "$ICALL_SEEDS"
    $PY -m tools.disasm "$XBE" "$@"
    $PY -m tools.func_id "$XBE"
    $PY -m tools.abi_analysis "$XBE"
    rm -rf port/recomp/gen
    $PY -m tools.recomp "$XBE" --all --split 1000 \
        --exclude-manual port/recomp_manual.c --gen-dir port/recomp/gen
    new=$($PY -m tools.jsrf_seeds "$XBE" | tee /dev/stderr | sed -n 's/^NEW=//p')
    [ "$new" = 0 ] && break
    pass=$((pass + 1))
    [ $pass -le 5 ] || { echo "still finding new functions after 5 passes; building anyway"; break; }
done
echo "done: port/recomp/gen is ready. Now: cmake -S port -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"
