#!/usr/bin/env python3
"""Build WebMetal's guest plugin (drivers/WebMetal/guest) and check it on this Mac.

Outputs, under --out (default build/web-metal-plugin):

  ios/WebMetal.bundle          the plugin for iPadOS 17 (arm64-apple-ios17.0), ad-hoc signed with 4 KiB pages; it is
                               installed as /System/Library/Extensions/WebMetal.bundle and loaded by Metal.framework
                               for the WebMetal accelerator service
  macos/libWebMetalHostShim.dylib
                               the macOS test shim: the same classes, built against this Mac's Metal.framework layouts
                               (recorded by host/WebMetalLayoutProbe.mm), registering a device with MTLAddDevice and
                               running the host executor in its own process (host/executor, built with cargo over the
                               native WebGPU implementation --webgpu-native names); it is also a provider for the
                               reference harness (tests/reference, --device provider:PATH)
  macos/libWebMetalHostShim-21H461.dylib
                               the shim built with the 21H461 layouts the iOS bundle requires, to show that the guard
                               refuses this Mac's Metal.framework
  macos/WebMetalSPICheck       the checks of the system-client SPI (guest/SPI/host/WebMetalSPICheck.mm) on the shim
  macos/WebMetalGuardCheck     the checks of the base-class guard (host/WebMetalGuardCheck.mm) on classes defined from
                               the 21H461 layouts
  macos/WebMetalHostCheck      the host checks (host/WebMetalHostCheck.mm) and expectations.json, their reading of
                               the device profile

Unless --no-check is given, the checks run: registration and the profile comparison twice, with the two sentinel
values the device profile's extraction gives the kernel-supplied maxBufferLength; strict mode (WEBMETAL_STRICT=1) at
the first LOUD stub; the refusal of the 21H461-layout shim; the system-client SPI checks; and the guard checks.
--reference also builds the reference harness and runs it on the shim's device. The plugin's surface against the
target is audited by audit-target-web-metal-surface.py --check --plugin <out>/ios/WebMetal.bundle/WebMetal.
"""
import argparse
import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'profile/ipados-17.7.11-21H461-a10x.toml'
SENTINELS = (0x5e5e1000, 0x7b7b002000)  # the device profile's kernel-input sentinels (profile/webmetal_profile/target.py)

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--webmetal', type=Path, default=ROOT / 'drivers/WebMetal', help='WebMetal checkout')
parser.add_argument('--out', type=Path, default=ROOT / 'build/web-metal-plugin', help='output directory')
parser.add_argument('--no-check', action='store_true', help='build only')
parser.add_argument('--reference', action='store_true', help='also run the reference harness on the shim device')
parser.add_argument('--webgpu-native', default=os.environ.get('WEBGPU_NATIVE'),
                    help="the shim executor's WebGPU implementation: dawn or wgpu-native (default: $WEBGPU_NATIVE)")
parser.add_argument('--webgpu-native-dir', type=Path, default=os.environ.get('WEBGPU_NATIVE_DIR'),
                    help='its install root, with include/webgpu/webgpu.h and lib/ (default: $WEBGPU_NATIVE_DIR)')
args = parser.parse_args()

webmetal = args.webmetal.resolve()
guest = webmetal / 'guest'
out = args.out.resolve()
FLAGS = ['-std=c++17', '-fobjc-arc', '-fobjc-arc-exceptions', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
         '-Wno-unused-parameter']
# Every package's sources under guest/, without the generated ones (listed below), the layouts the iOS bundle alone
# links, and the macOS test vehicles under host/.
PLUGIN = sorted(p for p in guest.rglob('*.mm') if p.parent.name not in ('Generated', 'Private') and
                'host' not in p.relative_to(guest).parts and p.name != 'WebMetalLayoutTarget.mm')
GENERATED = [guest / 'Generated/WebMetalProfileGetters.mm']
FRAMEWORKS = ['-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOKit', '-framework', 'IOSurface',
              '-framework', 'Security']


def run(command, **kwargs):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), check=True, **kwargs)


def sdk(name):
    return subprocess.check_output(['xcrun', '--sdk', name, '--show-sdk-path'], text=True).strip()


def compile_ios():
    bundle = out / 'ios/WebMetal.bundle'
    shutil.rmtree(bundle, ignore_errors=True)
    bundle.mkdir(parents=True)
    executable = bundle / 'WebMetal'
    run(['xcrun', 'clang++', '-target', 'arm64-apple-ios17.0', '-isysroot', sdk('iphoneos'), *FLAGS, '-bundle',
         *PLUGIN, guest / 'Plugin/WebMetalLayoutTarget.mm', *GENERATED, *FRAMEWORKS, '-o', executable])
    # The debug symbols stay beside the bundle, out of its signed contents.
    symbols = out / 'ios/WebMetal.dSYM'
    shutil.rmtree(symbols, ignore_errors=True)
    if (bundle / 'WebMetal.dSYM').exists():
        shutil.move(bundle / 'WebMetal.dSYM', symbols)
    shutil.copyfile(guest / 'Plugin/Info.plist', bundle / 'Info.plist')
    info = plistlib.loads((bundle / 'Info.plist').read_bytes())
    if info['CFBundleExecutable'] != executable.name or info['NSPrincipalClass'] != 'WebMetalDevice':
        sys.exit('FAIL: guest/Plugin/Info.plist does not name the WebMetal executable and WebMetalDevice')
    header = executable.read_bytes()[:16]
    if header[:8] != bytes.fromhex('cffaedfe0c000001') or int.from_bytes(header[8:12], 'little') & 0xffffff != 0:
        sys.exit('FAIL: the bundle executable is not an arm64 Mach-O')
    run(['codesign', '--force', '--sign', '-', '--pagesize', '4096', '--identifier', info['CFBundleIdentifier'], bundle])
    run(['codesign', '--verify', '--strict', bundle])
    detail = subprocess.run(['codesign', '--display', '--verbose=4', bundle], capture_output=True, text=True,
                            check=True).stderr
    if not re.search(r'^Page size=4096$', detail, re.M):
        sys.exit('FAIL: the signature does not use 4 KiB pages')
    cdhash = re.search(r'^CDHash=([0-9a-f]{40})$', detail, re.M).group(1)
    print(f'built {bundle} (CDHash {cdhash})')


def compile_macos():
    macos = out / 'macos'
    shutil.rmtree(macos, ignore_errors=True)
    macos.mkdir(parents=True)
    host = ['xcrun', 'clang++', '-target', 'arm64-apple-macos14.0', '-isysroot', sdk('macosx'), *FLAGS]
    probe = macos / 'WebMetalLayoutProbe'
    # The probe looks selectors up as the guard does.
    run([*host, guest / 'Plugin/host/WebMetalLayoutProbe.mm', guest / 'Plugin/WebMetalGuard.mm', '-framework',
         'Foundation', '-framework', 'Metal', '-o', probe])
    layout = macos / 'WebMetalLayoutHost.mm'
    run([probe, layout])
    shim = guest / 'Plugin/host/WebMetalHostShim.mm'
    executor = build_executor()
    for name, layouts in (('libWebMetalHostShim.dylib', layout),
                          ('libWebMetalHostShim-21H461.dylib', guest / 'Plugin/WebMetalLayoutTarget.mm')):
        run([*host, '-dynamiclib', '-I', guest / 'Plugin', *PLUGIN, layouts, *GENERATED, shim, *executor, *FRAMEWORKS,
             '-install_name', '@rpath/' + name, '-o', macos / name])
    run([*host, guest / 'Plugin/host/WebMetalHostCheck.mm', '-framework', 'Foundation', '-framework', 'Metal',
         '-o', macos / 'WebMetalHostCheck'])
    if (guest / 'SPI/host/WebMetalSPICheck.mm').exists():
        run([*host, guest / 'SPI/host/WebMetalSPICheck.mm', '-framework', 'Foundation', '-framework', 'Metal',
             '-o', macos / 'WebMetalSPICheck'])
    if (guest / 'Plugin/host/WebMetalGuardCheck.mm').exists():
        run([*host, guest / 'Plugin/host/WebMetalGuardCheck.mm', guest / 'Plugin/WebMetalGuard.mm', '-framework',
             'Foundation', '-o', macos / 'WebMetalGuardCheck'])
    (macos / 'expectations.json').write_text(json.dumps(expectations(), indent=1) + '\n')
    print(f'built {macos}')


def build_executor():
    """The shim's host executor (guest/Plugin/host/executor), a static library, and what linking it needs."""
    if args.webgpu_native not in ('dawn', 'wgpu-native') or not args.webgpu_native_dir:
        sys.exit('FAIL: the shim runs the host executor: give --webgpu-native dawn|wgpu-native and --webgpu-native-dir')
    root = args.webgpu_native_dir.resolve()
    target = out / 'cargo'
    env = dict(os.environ, WEBGPU_NATIVE=args.webgpu_native, WEBGPU_NATIVE_DIR=str(root), CARGO_TARGET_DIR=str(target))
    run(['cargo', 'build', '--release', '--locked', '--manifest-path', guest / 'Plugin/host/executor/Cargo.toml'],
        env=env)
    link = [target / 'release/libwebmetal_shim_executor.a', '-lc++']
    if args.webgpu_native == 'dawn':
        # rustc bundles Dawn's static library into the executor's; the frameworks are those of Dawn's exported CMake
        # target (host/build.rs).
        link += ['-framework', 'CoreFoundation', '-framework', 'QuartzCore', '-framework', 'Cocoa']
    else:
        link += ['-L', root / 'lib', '-lwgpu_native', '-Wl,-rpath,' + str(root / 'lib')]
    return link


def expectations():
    """The device profile's values the host checks compare, with the profile's verdict on this Mac's framework."""
    text = (webmetal / PROFILE).read_text()
    profile = tomllib.loads(text)
    comments, section = {}, None
    for line in text.splitlines():
        header = re.match(r'^\[(.+?)\]', line)
        if header:
            section = header.group(1)
        entry = re.match(r'^("[^"]+"|[^ =\[]+) = .*?  # (.*)$', line)
        if entry and section:
            comments[(section, entry.group(1).strip('"'))] = entry.group(2)

    def b1(section, key):
        return 'B1 agrees' in comments[(section, key)]

    limits = []
    for name, value in profile['limits'].items():
        offset = int(re.match(r'\+(0x[0-9a-f]+);', comments[('limits', name)]).group(1), 16)
        limits.append({'name': name, 'offset': offset, 'value': value})
    for name in profile.get('limits_runtime', {}):
        offset = int(re.match(r'\+(0x[0-9a-f]+);', comments[('limits_runtime', name)]).group(1), 16)
        limits.append({'name': name, 'offset': offset, 'runtime': True})
    getters = [{'selector': selector, 'value': value, 'b1': b1(section, selector)}
               for section in ('getters', 'driver_getters') for selector, value in profile[section].items()]
    queries = []
    for selector, table in profile['queries'].items():
        for argument, value in table.items():
            entry = {'selector': selector, 'argument': int(argument), 'value': value,
                     'b1': b1(f'queries."{selector}"', argument)}
            if selector == 'minimumTextureBufferAlignmentForPixelFormat:':
                # The A10X's getter is a tail call to Metal.framework's minimumLinearTextureAlignmentForPixelFormat:
                # (WebMetalDevice.mm); on this Mac that answer is the host framework's, comparable where the profile's
                # second method found it to agree.
                via = 'minimumLinearTextureAlignmentForPixelFormat:'
                entry['via'] = via
                entry['b1'] = argument in profile['queries'][via] and b1(f'queries."{via}"', argument)
            queries.append(entry)
    return {'profile': PROFILE, 'limits': limits, 'getters': getters, 'queries': queries}


def check():
    macos = out / 'macos'
    tool, shim = macos / 'WebMetalHostCheck', macos / 'libWebMetalHostShim.dylib'
    for sentinel in SENTINELS:
        run([tool, 'register', shim, macos / 'expectations.json', hex(sentinel)])
    strict = subprocess.run([tool, 'strict', shim], capture_output=True, text=True,
                            env={'WEBMETAL_STRICT': '1', 'PATH': '/usr/bin:/bin'})
    line = 'WebMetal: -[WebMetalDevice newAccelerationStructureWithSize:]: not implemented'
    if strict.returncode != -signal.SIGABRT or line not in strict.stderr or 'WEBMETAL_STRICT' not in strict.stderr:
        sys.exit(f'FAIL: strict mode did not abort at the first LOUD stub (status {strict.returncode}):\n{strict.stdout}{strict.stderr}')
    print(f'PASS: under WEBMETAL_STRICT=1 the first LOUD stub reports and aborts: {line}')
    run([tool, 'refuse', macos / 'libWebMetalHostShim-21H461.dylib'])
    if (macos / 'WebMetalSPICheck').exists():
        run([macos / 'WebMetalSPICheck', shim])
    if (macos / 'WebMetalGuardCheck').exists():
        run([macos / 'WebMetalGuardCheck'])


def reference():
    """The reference harness's device cases, each in its own process, on the shim's device (provider path)."""
    harness = webmetal / 'tests/reference'
    build = out / 'wmref'
    run([sys.executable, harness / 'build.py', '--out', build])
    shim = out / 'macos/libWebMetalHostShim.dylib'
    cases = [line.split('\t')[0] for line in subprocess.check_output([build / 'wmref', 'list'], text=True).splitlines()
             if line.startswith('device.')]
    outcomes = {}
    for case in cases:
        result = subprocess.run([build / 'wmref', 'case', '--case', case, '--device', f'provider:{shim}'],
                                capture_output=True, text=True)
        end = json.loads(result.stdout.strip().splitlines()[-1]) if result.stdout.strip() else {}
        status, message = end.get('status'), end.get('message', '')
        loud = status == 'harness-error' and message.startswith('uncaught WebMetalNotImplemented: ')
        if end.get('kind') != 'end' or not (status in ('ok', 'unsupported') or loud):
            sys.exit(f'FAIL: reference case {case} on the shim device ended with {result.returncode}: '
                     f'{result.stdout}{result.stderr}')
        outcomes[case] = 'LOUD ' + message.split(': ', 2)[1] if loud else status
        print(f'{case:32} {outcomes[case]}')
    print(f'PASS: the reference harness runs its {len(cases)} device cases on the device through its provider path: '
          f'{sum(v == "ok" for v in outcomes.values())} ok, {sum(v == "unsupported" for v in outcomes.values())} '
          f'unsupported, {sum(v.startswith("LOUD") for v in outcomes.values())} stopped at a LOUD stub')


out.mkdir(parents=True, exist_ok=True)
compile_ios()
compile_macos()
if not args.no_check:
    check()
if args.reference:
    reference()
print('PASS: WebMetal guest plugin built' + ('' if args.no_check else ' and checked'))
