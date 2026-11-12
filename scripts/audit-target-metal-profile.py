#!/usr/bin/env python3
"""Extract the A10X Metal device profile from the user's own 21H461 root and check it twice.

Method A executes the target's Metal.framework, IOGPU and AGXMetalA10 code from the root's
dyld shared cache in emulation on an AGXA10XDevice instance (MTLAddDevice's sequence, then
every MTLDevice/MTLDeviceSPI query). Method B1 runs the same queries through this Mac's own
Metal.framework for a device that returns the A10X driver answers; method B2 decodes the
driver getters with LLVM's disassembler. The result is WebMetal's
profile/ipados-17.7.11-21H461-a10x.toml: --write regenerates it, --check fails if the file
differs from a fresh extraction. A disagreement between the methods fails both modes.
"""
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'profile/ipados-17.7.11-21H461-a10x.toml'

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True, help='unpacked 21H461 root filesystem (only read)')
parser.add_argument('--webmetal', type=Path, default=ROOT / 'drivers/WebMetal', help='WebMetal checkout')
parser.add_argument('--python-modules', type=Path, required=True, help='directory providing the unicorn package')
parser.add_argument('--llvm-bin', type=Path, required=True, help='LLVM bin directory providing llvm-mc')
parser.add_argument('--build-dir', type=Path, required=True, help='directory for the host probe binary and input')
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--write', action='store_true', help='write the profile')
mode.add_argument('--check', action='store_true', help='compare the profile with a fresh extraction')
args = parser.parse_args()

root, build_dir = args.root.resolve(), args.build_dir.resolve()
if build_dir == root or root in build_dir.parents:
    sys.exit('The build directory must be outside the target root.')
cache = root / 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64'
if not cache.is_file():
    sys.exit(f'No dyld shared cache at {cache}')
sys.path[:0] = [str(args.python_modules.resolve()), str((args.webmetal / 'profile').resolve())]
from webmetal_profile import build, render  # noqa: E402

start = time.monotonic()
profile = build.collect(cache, build_dir, args.llvm_bin,
                        log=lambda line: print(f'[{time.monotonic() - start:6.1f}s] {line}', flush=True))
writer = render.render(profile)
text = writer.text()
target = args.webmetal / PROFILE
counts = writer.counts
summary = (f'{counts["values"]} values: {counts["two_method"]} confirmed by a second method, '
           f'{counts["single_method"]} single-method with the reason on their line')
if args.write:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    print(f'PASS: wrote {target}; {summary}')
else:
    current = target.read_text() if target.exists() else ''
    if current != text:
        fresh = build_dir / 'ipados-17.7.11-21H461-a10x.toml'
        fresh.write_text(text)
        sys.exit(f'FAIL: {target} differs from a fresh extraction (written to {fresh})')
    print(f'PASS: {target} matches a fresh extraction; {summary}')
