#!/usr/bin/env python3
"""Derive WebMetal's guest plugin surface from the user's own 21H461 root and audit the built plugin against it.

The guest plugin (drivers/WebMetal/guest) replaces the A10X's Metal driver bundle. For every Metal object class of
that driver (the AGXMetalA10 classes that adopt an MTL protocol) this script classifies every selector its objects
answer or its protocols declare, from the Objective-C metadata of the target's dyld shared cache (read-only):

  driver     the method is implemented by the driver layers the plugin replaces (AGXMetalA10, IOGPU.framework).
             The plugin class standing in for that driver class implements it, or it is a LOUD stub: reported as not
             implemented and failed, never answered.
  framework  a protocol method the driver class inherits from its Metal.framework base (_MTLDevice, _MTLResource...).
             The plugin class subclasses the same base and inherits the same code; it must not override it.
  absent     a protocol method no class of the chain implements (respondsToSelector: is NO on the device). The plugin
             must not implement it either.

--write regenerates guest/Generated and guest/SPI/clients in the WebMetal checkout:

  WebMetalTargetSurface.h    the driver selectors (with type encodings and LOUD reasons) of each driver class a plugin
                             class stands in for (guest/Plugin/roles.toml), and the layout of the Metal.framework base
                             classes guest/Private declares: superclass, instance size, instance variables, and every
                             classified selector's presence and type encoding. The plugin refuses to load when the
                             running Metal.framework differs. A driver class whose chain reaches the root class
                             without a Metal.framework base (AGXTextureLayout -> IOGPUMetalTextureLayout -> NSObject)
                             has NSObject as its base, which has no layout to guard.
  WebMetalProfileGetters.mm  the capability getters of the A10X: every driver selector the device profile
                             (profile/ipados-17.7.11-21H461-a10x.toml) answers with a value.
  surface.tsv                the classification of every selector of every driver class, with its status in the built
                             plugin: implemented, profile or loud for a driver selector of a class the plugin stands in
                             for (no-plugin-class otherwise), inherited for a framework one, not-answered for an absent
                             one. It needs --plugin, the built iOS executable; the loud rows are the backlog. A
                             plugin method whose code calls WMLoudMethod before any other call or branch fails every
                             call: it is loud, not implemented.
  SPI/clients/<client>.tsv   for each system client guest/SPI/clients.toml names (QuartzCore, CoreImage...), the rows
                             of surface.tsv whose selector the client's images reference (__objc_selrefs: every
                             selector they send, test with respondsToSelector: or send to super), with a note for each
                             loud row (the reason a hand-written LOUD method reports, or guest/SPI/notes.toml's) and
                             for each row of a driver class no plugin class stands in for (notes.toml's, per class). A
                             selector reference proves the client can send the message, not to which receiver, so
                             every driver class with the selector has a row. It needs --plugin.

guest/SPI/notes.toml holds the notes: [loud.<driver class>] gives, for a selector the plugin answers with a generated
LOUD stub, what is unknown or what the host cannot do exactly (the stub reports it, through WebMetalTargetSurface.h);
[unserved] gives, for a driver class no plugin class stands in for, why the plugin hands out no object of it.

--check regenerates in memory, fails if a committed file differs, and audits the built plugin: each plugin class has
the driver class's base and protocols, implements only driver selectors, with the target's type encodings, and every
other driver selector is a LOUD stub. It fails when a loud or unserved row of a client list has no note, or when
notes.toml has a note for a selector the plugin implements or for a class a plugin class stands in for. Categories in
the three images join their classes (IOGPU.framework adds one to _MTLSharedEvent); categories other images add are not
read, and the device profile records that none adds one to the device chain.
"""
import argparse
import re
import struct
import sys
import textwrap
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'profile/ipados-17.7.11-21H461-a10x.toml'
GENERATED = 'guest/Generated'
ROLES = 'guest/Plugin/roles.toml'
PRIVATE = 'guest/Private/MetalPrivate.h'
CLIENTS = 'guest/SPI/clients.toml'
NOTES = 'guest/SPI/notes.toml'
CLIENT_LISTS = 'guest/SPI/clients'
# The root class: the base of a driver class with no Metal.framework class in its chain.
ROOT_CLASS = 'NSObject'
DRIVER_IMAGES = ('AGX', 'IOGPU')
# Runtime-generated and lifecycle selectors: every class has its own, they are no part of the Metal surface.
LIFECYCLE = {'.cxx_construct', '.cxx_destruct', 'dealloc', 'init', 'initialize', 'load'}
# The profile describes AGXA10XDevice, the device class AGXPrincipalDevice creates for the A10X.
PROFILED_CLASS = 'AGXA10XDevice'

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--root', type=Path, required=True, help='unpacked 21H461 root file system (only read)')
parser.add_argument('--webmetal', type=Path, default=ROOT / 'drivers/WebMetal', help='WebMetal checkout')
parser.add_argument('--plugin', type=Path, help='built iOS executable (WebMetal.bundle/WebMetal) to audit')
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--write', action='store_true', help='write guest/Generated')
mode.add_argument('--check', action='store_true', help='compare guest/Generated to a fresh derivation and audit --plugin')
parser.add_argument('--backlog', action='store_true', help='print every LOUD selector of the plugin classes')
args = parser.parse_args()

webmetal = args.webmetal.resolve()
sys.path.insert(0, str(webmetal / 'wire/tools'))
sys.dont_write_bytecode = True  # nothing is written into the WebMetal checkout but guest/Generated
import target_surface  # noqa: E402  (WebMetal's shared-cache and Objective-C metadata reader)


def fail(message):
    raise SystemExit('FAIL: ' + message)


# Target ---------------------------------------------------------------------------------------------------------------

class Target:
    """The Metal driver stack of the 21H461 cache: Metal.framework, IOGPU.framework and AGXMetalA10."""

    IMAGES = ('Metal', 'IOGPU', 'AGX')

    def __init__(self, root):
        self.cache = target_surface.Cache(str(root / target_surface.CACHE_REL))
        self.objc = target_surface.ObjC(self.cache)
        self.uuid = self.cache.main[0x58:0x68].hex()
        images = self.cache.images()
        self.classes, self.order = {}, {key: [] for key in self.IMAGES}
        for key in self.IMAGES:
            sections = self.cache.sections(images[target_surface.IMAGES[key]])
            for va, size in self.objc.section(sections, '__objc_classlist'):
                for at in range(va, va + size, 8):
                    cls = self.read_class(self.cache.pointer(at), key)
                    self.classes[cls['name']] = cls
                    self.order[key].append(cls['name'])
        for key in self.IMAGES:
            sections = self.cache.sections(images[target_surface.IMAGES[key]])
            for name in ('__objc_catlist', '__objc_catlist2'):
                for va, size in self.objc.section(sections, name):
                    for at in range(va, va + size, 8):
                        self.read_category(self.cache.pointer(at), key)
        self.protocols = {}
        for path in sorted(images):
            sections = self.cache.sections(images[path])
            for va, size in self.objc.section(sections, '__objc_protolist'):
                for at in range(va, va + size, 8):
                    address = self.cache.pointer(at)
                    name = self.objc.protocol_name(address)
                    if not name.startswith('MTL') or (name in self.protocols and self.protocols[name][0] == 'Metal'):
                        continue
                    if name not in self.protocols or path == target_surface.IMAGES['Metal']:
                        self.protocols[name] = ('Metal' if path == target_surface.IMAGES['Metal'] else path,
                                                self.objc.protocol(address))
        self.protocols = {name: definition for name, (_, definition) in self.protocols.items()}

    def read_class(self, address, image):
        """objc4 class_t and class_ro_t (objc-runtime-new.h) of a shared-cache class and its metaclass."""
        c = self.cache
        ro = self.objc.data(address)
        _, instance_start, instance_size = struct.unpack('<3I', c.read(ro, 12))
        superclass = c.pointer(address + 8)
        meta = self.objc.data(c.pointer(address))
        ivars = []
        ivar_list = c.pointer(ro + 48)
        if ivar_list:
            entsize, count = struct.unpack('<II', c.read(ivar_list, 8))
            for i in range(count):
                entry = ivar_list + 8 + entsize * i
                offset_at = c.pointer(entry)
                offset, = struct.unpack('<i', c.read(offset_at, 4)) if offset_at else (None,)
                ivars.append({'name': c.cstring(c.pointer(entry + 8)), 'type': c.cstring(c.pointer(entry + 16)),
                              'offset': offset})
        return {'name': c.cstring(c.pointer(ro + 24)), 'image': image, 'address': address,
                'super': self.objc.class_name(superclass) if superclass else None,
                'instance_start': instance_start, 'instance_size': instance_size, 'ivars': ivars,
                'methods': [(n, t, image) for n, t in self.objc.methods(c.pointer(ro + 32))],
                'class_methods': [(n, t, image) for n, t in self.objc.methods(c.pointer(meta + 32))],
                'protocols': [self.objc.protocol_name(p) for p in self.objc.protocol_list(c.pointer(ro + 40))]}

    def read_category(self, address, image):
        """objc4 category_t: its methods join the class's, ahead of the class's own (attachCategories)."""
        c = self.cache
        cls_address = c.pointer(address + 8)
        if not cls_address:
            return
        name = self.objc.class_name(cls_address)
        if name not in self.classes:
            return
        target = self.classes[name]
        target['methods'][:0] = [(n, t, image) for n, t in self.objc.methods(c.pointer(address + 16))]
        target['class_methods'][:0] = [(n, t, image) for n, t in self.objc.methods(c.pointer(address + 24))]
        target['protocols'] += [self.objc.protocol_name(p) for p in self.objc.protocol_list(c.pointer(address + 32))]

    def chain(self, name):
        out = []
        while name in self.classes:
            out.append(self.classes[name])
            name = self.classes[name]['super']
        return out, name

    def closure(self, names):
        out, stack = set(), list(names)
        while stack:
            name = stack.pop()
            if name in out:
                continue
            out.add(name)
            if name in self.protocols:
                stack += self.protocols[name]['protocols']
        return out

    def role(self, name):
        """Classification of every selector of driver class `name`."""
        chain, root = self.chain(name)
        adopted = set()
        for link in chain:
            adopted |= set(link['protocols'])
        protocols = sorted(p for p in self.closure(adopted) if p in self.protocols)
        framework = [link for link in chain if link['image'] not in DRIVER_IMAGES]
        base = framework[0]['name'] if framework else root
        resolved = {}
        for kind, field in (('instance', 'methods'), ('class', 'class_methods')):
            for link in chain:
                for selector, types, image in link[field]:
                    resolved.setdefault((kind, selector), (link['name'], image, types))
        declared = {}
        for protocol in protocols:
            for method in self.protocols[protocol]['methods']:
                kind = 'class' if method['kind'].endswith('class') else 'instance'
                declared.setdefault((kind, method['name']), set()).add(protocol)
        rows = {}
        for key, (owner, image, types) in resolved.items():
            if key[1] in LIFECYCLE:
                continue
            if image in DRIVER_IMAGES:
                rows[key] = {'category': 'driver', 'owner': owner, 'layer': image.lower(), 'types': types}
            elif key in declared:
                rows[key] = {'category': 'framework', 'owner': owner, 'layer': 'framework', 'types': types}
        for key in declared:
            if key not in resolved and key[1] not in LIFECYCLE:
                types = next(m['types'] for p in sorted(declared[key]) for m in self.protocols[p]['methods']
                             if m['name'] == key[1] and m['kind'].endswith('class') == (key[0] == 'class'))
                rows[key] = {'category': 'absent', 'owner': None, 'layer': 'none', 'types': types}
        for key, row in rows.items():
            row['protocols'] = sorted(declared.get(key, ()))
        return {'name': name, 'chain': [link['name'] for link in chain], 'base': base, 'protocols': protocols,
                'rows': rows}

    def roles(self):
        out = []
        for name in self.order['AGX']:
            role = self.role(name)
            if any(p.startswith('MTL') for p in role['protocols']):
                out.append(role)
        return out

    def base_layout(self, name, selectors):
        """Superclass, size, instance variables and the presence and encoding of each (kind, selector) on a base."""
        if name not in self.classes or self.classes[name]['image'] != 'Metal':
            fail(f'{name} is not a Metal.framework class on 21H461')
        cls = self.classes[name]
        chain, _ = self.chain(name)
        present = {}
        for kind, field in (('instance', 'methods'), ('class', 'class_methods')):
            for link in chain:
                # Categories the driver images add are not there when the plugin, not the driver, is loaded.
                for selector, types, image in link[field]:
                    if image == 'Metal':
                        present.setdefault((kind, selector), types)
        return {'name': name, 'super': cls['super'], 'size': cls['instance_size'], 'ivars': cls['ivars'],
                'selectors': [(kind, sel, present.get((kind, sel))) for kind, sel in sorted(selectors)]}


# Device profile -------------------------------------------------------------------------------------------------------

def profile_comments(text):
    """{(section, key): comment} for every `key = value  # comment` line of the profile, and {(section, None): the
    comment lines above the section's header}."""
    out, section, block = {}, None, []
    for line in text.splitlines():
        if line.startswith('# '):
            block.append(line[2:])
            continue
        header = re.match(r'^\[(.+?)\]', line)
        if header:
            section = header.group(1)
            out[(section, None)] = ' '.join(block)
            block = []
            continue
        block = []
        entry = re.match(r'^("[^"]+"|[^ =]+) = .*?  # (.*)$', line)
        if entry and section:
            out[(section, entry.group(1).strip('"'))] = entry.group(2)
    return out


CTYPES = {'B': 'BOOL', 'C': 'uint8_t', 'c': 'int8_t', 'S': 'uint16_t', 's': 'int16_t', 'I': 'uint32_t', 'i': 'int32_t',
          'Q': 'NSUInteger', 'q': 'NSInteger', 'L': 'uint64_t', 'l': 'int64_t', 'f': 'float', 'd': 'double',
          '{?=QQQ}': 'MTLSize', '{?=QQ}': 'MTLSizeAndAlign'}


BITFIELDS = re.compile(r'^\{(\w+)=((?:b\d+)+)\}$')


def bitfield_struct(encoding):
    """A struct of bit-fields, `{Name=b1b1b1b29}`: (name, widths), or None."""
    m = BITFIELDS.match(encoding)
    return (m.group(1), [int(w) for w in re.findall(r'\d+', m.group(2))]) if m else None


def ctype_of(encoding):
    if encoding in CTYPES:
        return CTYPES[encoding]
    bits = bitfield_struct(encoding)
    return f'struct {bits[0]}' if bits and sum(bits[1]) <= 64 else None


def signature(types):
    ret, arguments = target_surface.method_arguments(types)
    ctypes = [ctype_of(t) for t in [ret] + arguments]
    if any(c is None for c in ctypes):
        return None
    return ctypes[0], ctypes[1:]


def literal(ctype, value):
    if ctype.startswith('struct '):
        if isinstance(value, bool) or not isinstance(value, int):
            fail(f'profile value {value!r} of {ctype} is not the integer of its bits')
        return f'WMBits<{ctype}>({value}ull)'
    if ctype == 'BOOL':
        if not isinstance(value, bool):
            fail(f'profile value {value!r} is not a boolean')
        return 'YES' if value else 'NO'
    if ctype in ('float', 'double'):
        text = repr(float(value))
        return text + ('f' if ctype == 'float' else '')
    if ctype == 'MTLSize':
        if not (isinstance(value, list) and len(value) == 3):
            fail(f'profile value {value!r} is not a size')
        return 'MTLSizeMake(%s)' % ', '.join(f'{int(v)}ull' for v in value)
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f'profile value {value!r} is not an integer')
    if ctype in ('NSUInteger', 'uint64_t'):
        return f'{value}ull'
    if ctype in ('NSInteger', 'int64_t'):
        return f'{value}ll'
    return f'{value}u' if ctype.startswith('uint') else f'{value}'


def selector_parts(selector, names):
    """`a:b:` with parameter names -> `a:(T)x b:(T)y`."""
    pieces = selector.split(':')[:-1]
    return ' '.join(f'{piece}:({ctype}){name}' for piece, (ctype, name) in zip(pieces, names))


class ProfileGetters:
    """Methods answering driver selectors from the A10X device profile."""

    def __init__(self, profile_text, device_role, properties):
        self.profile = tomllib.loads(profile_text)
        self.comments = profile_comments(profile_text)
        self.rows = device_role['rows']
        self.methods = {}   # selector -> (source, provenance)
        self.skipped = []   # profiled queries with validation failures, left to hand-written code
        self.reasons = {}   # selector -> LOUD detail for driver selectors the profile records as device state
        for section in ('getters', 'driver_getters'):
            for selector, value in sorted(self.profile.get(section, {}).items()):
                row = self.rows.get(('instance', selector))
                if not row or row['category'] != 'driver':
                    continue
                self.getter(section, selector, value, row)
        for selector, table in sorted(self.profile.get('queries', {}).items()):
            row = self.rows.get(('instance', selector))
            if row and row['category'] == 'driver':
                self.query(selector, table, row)
        self.heap()
        for selector in self.profile.get('runtime', {}):
            row = self.rows.get(('instance', selector))
            if row and row['category'] == 'driver':
                self.reasons[selector] = 'device state the 21H461 driver reads from the kernel or the process; ' + \
                    self.comments[('runtime', selector)].split(': ', 1)[-1]
        for (kind, selector), row in self.rows.items():
            if kind != 'instance' or row['category'] != 'driver' or selector in self.methods or selector in self.reasons:
                continue
            if selector in properties:
                self.reasons[selector] = 'a device property the device profile records no value for'
        for selector in self.profile.get('unimplemented', {}):
            row = self.rows.get(('instance', selector))
            if row and row['category'] != 'absent':
                fail(f'the profile lists {selector} as unimplemented but the target classifies it {row["category"]}')

    def getter(self, section, selector, value, row):
        sig = signature(row['types'])
        if not sig or sig[1]:
            fail(f'{section}.{selector}: encoding {row["types"]} is not a zero-argument scalar getter')
        ctype = sig[0]
        provenance = self.comments[(section, selector)]
        self.methods[selector] = (f'- ({ctype}){selector}\n{{\n    return {literal(ctype, value)};\n}}\n', provenance)

    def query(self, selector, table, row):
        """An integer-argument query evaluated over a finite domain; other arguments are LOUD."""
        sig = signature(row['types'])
        if not sig or len(sig[1]) != 1 or sig[1][0] not in ('NSUInteger', 'NSInteger', 'uint32_t', 'int32_t'):
            fail(f'queries.{selector}: encoding {row["types"]} is not a one-integer-argument query')
        ctype, (argtype,) = sig
        if self.profile.get('query_failures', {}).get(selector):
            # Metal.framework reports validation failures for some arguments: the plugin implements the query by hand
            # through the same framework path, or it stays LOUD.
            self.skipped.append(selector)
            return
        lines = [f'- ({ctype}){selector_parts(selector, [(argtype, "argument")])}', '{', '    switch (argument) {']
        for key in sorted(table, key=int):
            comment = self.comments.get((f'queries."{selector}"', key), '').split(';')[0]
            lines.append(f'    case {int(key)}: return {literal(ctype, table[key])};  // {comment}'.rstrip())
        lines += ['    }',
                  '    WMLoudArgument(self, _cmd, (uint64_t)argument,',
                  f'                   "the device profile evaluates this query only for the arguments {min(map(int, table))} to '
                  f'{max(map(int, table))}");', '}', '']
        domain = sorted(map(int, table))
        if domain != list(range(domain[0], domain[-1] + 1)):
            fail(f'queries.{selector}: the profiled domain is not contiguous')
        section = 'queries."%s"' % selector
        self.methods[selector] = ('\n'.join(lines), f'{self.comments[(section, None)]} Arguments {domain[0]} to {domain[-1]}.')

    def heap(self):
        selector = 'heapBufferSizeAndAlignWithLength:options:'
        heap = self.profile.get('heap', {})
        row = self.rows.get(('instance', selector))
        if not row or row['category'] != 'driver' or not heap:
            return
        if set(heap) != {'buffer_size_is_length', 'buffer_alignment'} or heap['buffer_size_is_length'] is not True:
            fail(f'[heap] does not state a length-preserving size with one alignment: {heap}')
        if signature(row['types']) != ('MTLSizeAndAlign', ['NSUInteger', 'NSUInteger']):
            fail(f'{selector}: unexpected encoding {row["types"]}')
        provenance = self.comments[('heap', None)] + ' ' + self.comments[('heap', 'buffer_size_is_length')]
        body = (f'- (MTLSizeAndAlign)heapBufferSizeAndAlignWithLength:(NSUInteger)length options:(MTLResourceOptions)options\n'
                f'{{\n    return MTLSizeAndAlign{{length, {literal("NSUInteger", heap["buffer_alignment"])}}};\n}}\n')
        self.methods[selector] = (body, provenance)


# Generated files ------------------------------------------------------------------------------------------------------

HEADER = ('// Generated by UniXNU scripts/audit-target-web-metal-surface.py from the 21H461 dyld shared cache\n'
          '// (UUID {uuid}). Do not edit: run the script with --write.\n')


def c_string(text):
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def c_name(name):
    return re.sub(r'\W', '_', name)


def surface_header(target, mapped, bases, getters, notes):
    out = [HEADER.format(uuid=target.uuid), '#pragma once', '', '#include "../Plugin/WebMetalSurface.h"', '',
           'namespace webmetal::target {', '',
           f'inline constexpr char kCacheUUID[] = {c_string(target.uuid)};', '']
    for role in mapped:
        rows = [(k, s, r) for (k, s), r in sorted(role['rows'].items()) if r['category'] == 'driver']
        out.append(f'// Driver-layer selectors of {" -> ".join(role["chain"])}.')
        out.append(f'inline constexpr DriverSelector k{c_name(role["name"])}Driver[] = {{')
        for kind, selector, row in rows:
            detail = getters.reasons.get(selector, '') if role['name'] == PROFILED_CLASS and kind == 'instance' else ''
            detail = '; '.join(d for d in (detail, notes.stub(role['name'], kind, selector)) if d)
            out.append(f'    {{SelectorKind::{kind.capitalize()}, {c_string(selector)}, {c_string(row["types"])}, '
                       f'{c_string(row["layer"])}, {c_string(detail)}}},')
        out += ['};', '']
    out.append('inline constexpr Role kRoles[] = {')
    for role in mapped:
        n = sum(1 for r in role['rows'].values() if r['category'] == 'driver')
        out.append(f'    {{{c_string(role["plugin"])}, {c_string(role["name"])}, {c_string(role["base"])}, '
                   f'k{c_name(role["name"])}Driver, {n}}},')
    out += ['};', '']
    for base in bases:
        out.append(f'inline constexpr BaseIvar k{c_name(base["name"])}Ivars[] = {{')
        for ivar in base['ivars']:
            out.append(f'    {{{c_string(ivar["name"])}, {ivar["offset"]}, {c_string(ivar["type"])}}},')
        if not base['ivars']:
            out.append('    {nullptr, 0, nullptr},  // none; the count below is 0')
        out += ['};', f'inline constexpr BaseSelector k{c_name(base["name"])}Selectors[] = {{']
        for kind, selector, types in base['selectors']:
            out.append(f'    {{SelectorKind::{kind.capitalize()}, {c_string(selector)}, '
                       f'{c_string(types) if types else "nullptr"}}},')
        if not base['selectors']:
            out.append('    {SelectorKind::Instance, nullptr, nullptr},  // none; the count below is 0')
        out += ['};', '']
    out.append('// Metal.framework base classes on 21H461, as guest/Private declares them.')
    out.append('inline constexpr BaseLayout kBases[] = {')
    for base in bases:
        out.append(f'    {{{c_string(base["name"])}, {c_string(base["super"])}, {base["size"]}, '
                   f'k{c_name(base["name"])}Ivars, {len(base["ivars"])}, k{c_name(base["name"])}Selectors, '
                   f'{len(base["selectors"])}}},')
    out += ['};', '', '}  // namespace webmetal::target', '']
    return '\n'.join(out)


def getters_source(target, mapped, getters):
    devices = [role['plugin'] for role in mapped if role['name'] == PROFILED_CLASS]
    out = [HEADER.format(uuid=target.uuid).rstrip(), '// Capability getters of the A10X: the driver selectors whose answer the device profile',
           f'// ({PROFILE}) records. The comment above each method is the profile\'s provenance.', '',
           '#import "../Plugin/WebMetalDevice.h"', '#import "../Plugin/WebMetalReport.h"', '',
           '// The class adopts the protocols that declare these methods; this category, not the class, implements them.',
           '#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"', '']
    structs = {}
    for (kind, selector), row in sorted(getters.rows.items()):
        if selector in getters.methods:
            for encoding in [target_surface.method_arguments(row['types'])[0]] + target_surface.method_arguments(row['types'])[1]:
                bits = bitfield_struct(encoding)
                if bits:
                    structs[bits[0]] = bits[1]
    if structs:
        out += ['#include <cstring>', '', '// Bit-field structures of the 21H461 method encodings.']
        for name, widths in sorted(structs.items()):
            word = 'uint32_t' if sum(widths) <= 32 else 'uint64_t'
            fields = ' '.join(f'{word} f{i} : {w};' for i, w in enumerate(widths))
            out.append(f'struct {name} {{ {fields} }};')
        out += ['', '// The structure whose bits, read as a little-endian integer, are `bits`, as the profile records it.',
                'template <typename T> static T WMBits(unsigned long long bits)', '{',
                '    T value;', '    static_assert(sizeof value <= sizeof bits, "bit-field structure wider than its value");',
                '    memcpy(&value, &bits, sizeof value);', '    return value;', '}', '']
    for plugin in devices:
        out += [f'@implementation {plugin} (WebMetalProfile)', '']
        for selector in sorted(getters.methods):
            source, provenance = getters.methods[selector]
            out += ['// ' + line for line in textwrap.wrap(provenance, 117)]
            out.append(source)
        out += ['@end', '']
    return '\n'.join(out)


def row_state(role, kind, selector, row, plugin_status):
    if row['category'] != 'driver':
        return 'inherited' if row['category'] == 'framework' else 'not-answered'
    if 'plugin' not in role:
        return 'no-plugin-class'
    return plugin_status.get(role['name'], {}).get((kind, selector), 'loud')


def surface_tsv(target, roles, plugin_status):
    lines = [HEADER.format(uuid=target.uuid).replace('//', '#').rstrip(),
             '# driver-class\tkind\tselector\tprotocols\tlayer\tclassification\tplugin-class\tplugin-status']
    for role in roles:
        for (kind, selector), row in sorted(role['rows'].items()):
            lines.append('\t'.join([role['name'], kind, selector, ','.join(row['protocols']) or '-', row['layer'],
                                    row['category'], role.get('plugin', '-'),
                                    row_state(role, kind, selector, row, plugin_status)]))
    return '\n'.join(lines) + '\n'


# System clients -------------------------------------------------------------------------------------------------------

def note_key(kind, selector):
    return ('+' if kind == 'class' else '') + selector


class Notes:
    """guest/SPI/notes.toml: why a driver selector is a LOUD stub, and why no plugin class serves a driver class."""

    def __init__(self, text, roles, mapped):
        data = tomllib.loads(text) if text is not None else {}
        unknown = set(data) - {'loud', 'unserved'}
        if unknown:
            fail(f'{NOTES}: unknown tables {sorted(unknown)}')
        self.loud = data.get('loud', {})
        self.unserved = data.get('unserved', {})
        names = {role['name']: role for role in roles}
        plugins = {role['name'] for role in mapped}
        for cls, table in sorted(self.loud.items()):
            if cls not in plugins:
                fail(f'{NOTES}: [loud.{cls}] names no driver class a plugin class stands in for')
            for key in table:
                kind = 'class' if key.startswith('+') else 'instance'
                row = names[cls]['rows'].get((kind, key.lstrip('+')))
                if not row or row['category'] != 'driver':
                    fail(f'{NOTES}: [loud.{cls}] {key} is not a driver selector of {cls}')
        for cls in sorted(self.unserved):
            if cls not in names or cls in plugins:
                fail(f'{NOTES}: [unserved] {cls} is not a Metal driver class without a plugin class')

    def stub(self, cls, kind, selector):
        return self.loud.get(cls, {}).get(note_key(kind, selector), '')


def client_selectors(target, images):
    """The selectors an image's __objc_selrefs reference: every message it sends, tests or sends to super."""
    paths = target.cache.images()
    out = set()
    for path in images:
        if path not in paths:
            fail(f'{CLIENTS}: {path} is not an image of the 21H461 cache')
        sections = target.cache.sections(paths[path])
        for va, size in target.objc.section(sections, '__objc_selrefs'):
            for at in range(va, va + size, 8):
                pointer = target.cache.pointer(at)
                if pointer:
                    out.add(target.cache.cstring(pointer))
    return out


def client_rows(target, roles, client, plugin_status, reasons, notes):
    """[(selector, driver class, kind, row, state, note, plugin class)] of one client, sorted by selector."""
    selectors = client_selectors(target, client['images'])
    out = []
    for role in roles:
        for (kind, selector), row in role['rows'].items():
            if selector not in selectors or selector in LIFECYCLE:
                continue
            state = row_state(role, kind, selector, row, plugin_status)
            if state == 'loud':
                note = reasons.get((role['name'], kind, selector), notes.stub(role['name'], kind, selector))
            elif state == 'no-plugin-class':
                note = notes.unserved.get(role['name'], '')
            else:
                note = ''
            out.append((selector, role['name'], kind, row, state, note, role.get('plugin', '-')))
    return sorted(out, key=lambda r: (r[0], r[1], r[2]))


def client_tsv(target, client, rows):
    lines = [HEADER.format(uuid=target.uuid).replace('//', '#').rstrip(),
             f'# The rows of surface.tsv whose selector {client["name"]} references ({", ".join(client["images"])}).',
             '# selector\tdriver-class\tkind\tprotocols\tlayer\tclassification\tplugin-class\tplugin-status\tnote']
    for selector, cls, kind, row, state, note, plugin in rows:
        lines.append('\t'.join([selector, cls, kind, ','.join(row['protocols']) or '-', row['layer'], row['category'],
                                plugin, state, note or '-']))
    return '\n'.join(lines) + '\n'


def check_notes(notes, mapped, plugin_status, reasons, clients, errors):
    for name, rows in clients.items():
        for selector, cls, kind, _, state, note, _ in rows:
            if state in ('loud', 'no-plugin-class') and not note:
                what = 'the driver class' if state == 'no-plugin-class' else 'the LOUD selector'
                errors.append(f'{CLIENT_LISTS}/{name}.tsv: {what} {cls} {note_key(kind, selector)} has no note '
                              f'in {NOTES}')
    for role in mapped:
        for key in notes.loud.get(role['name'], {}):
            kind, selector = ('class', key[1:]) if key.startswith('+') else ('instance', key)
            state = plugin_status.get(role['name'], {}).get((kind, selector), 'loud')
            if state != 'loud' or (role['name'], kind, selector) in reasons:
                errors.append(f'{NOTES}: [loud.{role["name"]}] {key}: {role["plugin"]} implements it '
                              f'({"a LOUD method with its own detail" if state == "loud" else state})')


# Built plugin ---------------------------------------------------------------------------------------------------------

class PluginImage:
    """The Objective-C classes of a thin arm64 Mach-O image linked with chained fixups (mach-o/fixup-chains.h)."""

    def __init__(self, path):
        data = path.read_bytes()
        magic, cputype, _, filetype, ncmds, _, _, _ = struct.unpack_from('<8I', data, 0)
        if magic != 0xfeedfacf or cputype != 0x0100000c:
            fail(f'{path} is not a thin arm64 Mach-O')
        self.data, self.segments, self.sections, self.platform = data, [], {}, None
        fixups, self.symtab = None, None
        at = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', data, at)
            if cmd == 0x19:  # LC_SEGMENT_64
                name = data[at + 8:at + 24].split(b'\0')[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', data, at + 24)
                self.segments.append((name, vmaddr, vmsize, fileoff, filesize))
                nsects, = struct.unpack_from('<I', data, at + 64)
                for k in range(nsects):
                    s = at + 72 + 80 * k
                    sect = data[s:s + 16].split(b'\0')[0].decode()
                    addr, sz = struct.unpack_from('<2Q', data, s + 32)
                    self.sections[(name, sect)] = (addr, sz)
            elif cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
                fixups = struct.unpack_from('<II', data, at + 8)
            elif cmd == 0x32:  # LC_BUILD_VERSION
                self.platform, self.minos = struct.unpack_from('<II', data, at + 8)
            elif cmd == 0x2:  # LC_SYMTAB: symoff, nsyms, stroff, strsize
                self.symtab = struct.unpack_from('<4I', data, at + 8)
            at += size
        self.fixups = {}
        if fixups:
            self.read_fixups(*fixups)

    def offset(self, va):
        for _, vmaddr, vmsize, fileoff, filesize in self.segments:
            if vmaddr <= va < vmaddr + min(vmsize, filesize):
                return fileoff + va - vmaddr
        fail(f'unmapped plugin address 0x{va:x}')

    def read_fixups(self, dataoff, datasize):
        d = self.data
        _, starts, imports, symbols, count, imports_format, _ = struct.unpack_from('<7I', d, dataoff)
        names = []
        for i in range(count):
            if imports_format == 1:
                raw, = struct.unpack_from('<I', d, dataoff + imports + 4 * i)
                name_offset = raw >> 9
            elif imports_format == 2:
                raw, _ = struct.unpack_from('<Ii', d, dataoff + imports + 8 * i)
                name_offset = raw >> 9
            else:
                fail(f'chained import format {imports_format}')
            start = dataoff + symbols + name_offset
            names.append(d[start:d.index(b'\0', start)].decode())
        segments, = struct.unpack_from('<I', d, dataoff + starts)
        for seg in range(segments):
            info, = struct.unpack_from('<I', d, dataoff + starts + 4 + 4 * seg)
            if not info:
                continue
            base = dataoff + starts + info
            _, page_size, pointer_format, segment_offset, _, page_count = struct.unpack_from('<IHHQIH', d, base)
            if pointer_format not in (2, 6):  # DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET
                fail(f'chained pointer format {pointer_format}')
            # DYLD_CHAINED_PTR_64 rebases hold the target address, DYLD_CHAINED_PTR_64_OFFSET its offset from the image.
            image_base = next(s[1] for s in self.segments if s[0] == '__TEXT') if pointer_format == 6 else 0
            for page in range(page_count):
                start, = struct.unpack_from('<H', d, base + 22 + 2 * page)
                if start == 0xffff:
                    continue
                at = segment_offset + page * page_size + start
                while True:
                    raw, = struct.unpack_from('<Q', d, at)
                    if raw >> 63:
                        self.fixups[at] = ('bind', names[raw & 0xffffff])
                    else:
                        self.fixups[at] = ('rebase', ((raw & 0xfffffffff) + image_base) | ((raw >> 36) & 0xff) << 56)
                    step = (raw >> 51) & 0xfff
                    if not step:
                        break
                    at += 4 * step

    def pointer(self, va):
        """The pointer stored at va: an address, or for a bind the imported symbol's name."""
        if self.offset(va) in self.fixups:
            return self.fixups[self.offset(va)][1]
        raw, = struct.unpack_from('<Q', self.data, self.offset(va))
        return raw

    def cstring(self, va):
        at = self.offset(va)
        return self.data[at:self.data.index(b'\0', at)].decode()

    def methods(self, va):
        """(selector, type encoding, implementation address) of each method of a method list."""
        if not va:
            return []
        flags, count = struct.unpack_from('<II', self.data, self.offset(va))
        out = []
        for i in range(count):
            if flags & 0x80000000:  # relative method list: selector reference, types, implementation offsets
                entry = va + 8 + 12 * i
                name, types, imp = struct.unpack_from('<3i', self.data, self.offset(entry))
                out.append((self.cstring(self.pointer(entry + name)), self.cstring(entry + 4 + types), entry + 8 + imp))
            else:
                entry = va + 8 + (flags & 0xfffc) * i
                out.append((self.cstring(self.pointer(entry)), self.cstring(self.pointer(entry + 8)),
                            self.pointer(entry + 16)))
        return out

    def symbol(self, name):
        """The address of a defined symbol of the image's symbol table (nlist_64), or None."""
        if not self.symtab:
            return None
        symoff, nsyms, stroff, _ = self.symtab
        for i in range(nsyms):
            strx, ntype, _, _, value = struct.unpack_from('<IBBHQ', self.data, symoff + 16 * i)
            if ntype & 0x0e == 0x0e and self.data[stroff + strx:self.data.index(b'\0', stroff + strx)] == name.encode():
                return value
        return None

    def loud_method(self, imp, loud):
        """Whether the arm64 code at imp calls `loud` (WMLoudMethod, which never returns) before any other call or any
        branch, so that every call of the method fails; with the detail it passes (x2, built by adrp and add or by adr),
        or '' when the code computes it otherwise. None for any other method."""
        x2 = None
        for k in range(256):
            pc = imp + 4 * k
            w, = struct.unpack_from('<I', self.data, self.offset(pc))
            if w & 0xfc000000 == 0x94000000:  # BL
                target = pc + 4 * (((w & 0x3ffffff) ^ 0x2000000) - 0x2000000)
                if target != loud:
                    return None
                try:
                    return self.cstring(x2) if x2 is not None else ''
                except (ValueError, SystemExit):
                    return ''
            if (w & 0x7c000000 == 0x14000000 or w & 0xff000010 == 0x54000000 or w & 0x7e000000 in (0x34000000, 0x36000000)
                    or w & 0xfe000000 == 0xd6000000):  # B, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET and their forms
                return None
            if w & 0x9f00001f == 0x90000002:  # ADRP x2
                imm = ((w >> 29) & 3) | ((w >> 5) & 0x7ffff) << 2
                x2 = (pc & ~0xfff) + (((imm ^ 0x100000) - 0x100000) << 12)
            elif w & 0x9f00001f == 0x10000002:  # ADR x2
                imm = ((w >> 29) & 3) | ((w >> 5) & 0x7ffff) << 2
                x2 = pc + ((imm ^ 0x100000) - 0x100000)
            elif w & 0xffc003ff == 0x91000042 and x2 is not None:  # ADD x2, x2, #imm12
                x2 += (w >> 10) & 0xfff
            elif w & 0x1f == 2:  # another instruction whose destination may be x2
                x2 = None
        return None

    def protocols(self, va):
        if not va:
            return []
        count, = struct.unpack_from('<Q', self.data, self.offset(va))
        return [self.cstring(self.pointer(self.pointer(va + 8 + 8 * i) + 8)) for i in range(count)]

    def classes(self):
        out = {}
        for key in (('__DATA_CONST', '__objc_classlist'), ('__DATA', '__objc_classlist')):
            if key not in self.sections:
                continue
            va, size = self.sections[key]
            for at in range(va, va + size, 8):
                cls = self.pointer(at)
                superclass = self.pointer(cls + 8)
                ro = self.pointer(cls + 32) & 0x00007ffffffffff8
                meta_ro = self.pointer(self.pointer(cls) + 32) & 0x00007ffffffffff8
                name = self.cstring(self.pointer(ro + 24))
                out[name] = {'super': superclass.removeprefix('_OBJC_CLASS_$_') if isinstance(superclass, str)
                             else self.cstring(self.pointer(self.pointer(superclass + 32) + 24)),
                             'methods': self.methods(self.pointer(ro + 32)),
                             'class_methods': self.methods(self.pointer(meta_ro + 32)),
                             'protocols': self.protocols(self.pointer(ro + 40))}
        for key in (('__DATA_CONST', '__objc_catlist'), ('__DATA', '__objc_catlist')):
            if key not in self.sections:
                continue
            va, size = self.sections[key]
            for at in range(va, va + size, 8):
                cat = self.pointer(at)
                cls = self.pointer(cat + 8)
                if isinstance(cls, str):
                    continue
                name = self.cstring(self.pointer(self.pointer(cls + 32) + 24))
                if name in out:
                    out[name]['methods'] += self.methods(self.pointer(cat + 16))
                    out[name]['class_methods'] += self.methods(self.pointer(cat + 24))
                    out[name]['protocols'] += self.protocols(self.pointer(cat + 32))
        return out


def audit_plugin(path, target, mapped, getters, errors, reasons):
    """The status of each driver selector a plugin class implements: profile, implemented, or loud for a method that
    fails every call (its detail goes to `reasons`, by driver class, kind and selector)."""
    image = PluginImage(path)
    if image.platform != 2:  # PLATFORM_IOS
        errors.append(f'{path}: platform {image.platform}, expected iOS (2)')
    loud = image.symbol('_WMLoudMethod')
    if loud is None:
        errors.append(f'{path}: no symbol _WMLoudMethod (guest/Plugin/WebMetalReport.h) in its symbol table')
    classes = image.classes()
    statuses = {}
    for role in mapped:
        plugin = role['plugin']
        cls = classes.get(plugin)
        if not cls:
            errors.append(f'{plugin} (for {role["name"]}) is not in {path}')
            continue
        if cls['super'] != role['base']:
            errors.append(f'{plugin}: superclass {cls["super"]}, the 21H461 driver class {role["name"]} is a {role["base"]}')
        mtl = {p for p in target.closure(cls['protocols']) if p.startswith('MTL')}
        want = {p for p in role['protocols'] if p.startswith('MTL')}
        if mtl != want:
            errors.append(f'{plugin}: adopts {sorted(mtl)}, {role["name"]} adopts {sorted(want)}')
        status = statuses.setdefault(role['name'], {})
        for kind, field in (('instance', 'methods'), ('class', 'class_methods')):
            seen = set()
            for selector, types, imp in cls[field]:
                if (kind, selector) in seen:
                    errors.append(f'{plugin}: {selector} is implemented twice')
                seen.add((kind, selector))
                if selector in LIFECYCLE:
                    continue
                row = role['rows'].get((kind, selector))
                where = f'{"+" if kind == "class" else "-"}[{plugin} {selector}]'
                if not row:
                    errors.append(f'{where}: neither the 21H461 driver layers of {role["name"]} implement it nor does a '
                                  'protocol it adopts declare it')
                elif row['category'] == 'framework':
                    errors.append(f'{where}: {role["name"]} inherits it from {row["owner"]} (Metal.framework); '
                                  'the plugin must inherit it too')
                elif row['category'] == 'absent':
                    errors.append(f'{where}: no layer of the 21H461 driver implements it (respondsToSelector: is NO)')
                elif types != row['types']:
                    errors.append(f'{where}: type encoding {types}, 21H461 {row["owner"]} has {row["types"]}')
                else:
                    profiled = role['name'] == PROFILED_CLASS and kind == 'instance' and selector in getters.methods
                    detail = image.loud_method(imp, loud) if loud is not None and not profiled else None
                    if detail is not None:
                        status[(kind, selector)] = 'loud'
                        reasons[(role['name'], kind, selector)] = detail
                    else:
                        status[(kind, selector)] = 'profile' if profiled else 'implemented'
        if role['name'] == PROFILED_CLASS:
            for selector in getters.methods:
                if status.get(('instance', selector)) != 'profile':
                    errors.append(f'-[{plugin} {selector}]: the generated profile getter is missing from {path}')
    return statuses


# Main -----------------------------------------------------------------------------------------------------------------

def property_getters(protocol):
    """Getter selectors of a protocol's declared properties (objc4 property attribute strings: G names a getter)."""
    out = set()
    for name, attributes in protocol['properties']:
        getter = next((a[1:] for a in attributes.split(',') if a.startswith('G')), name)
        out.add(getter)
    return out


def private_bases(text):
    """@interface declarations of guest/Private/MetalPrivate.h: {class: superclass}."""
    return {m.group(1): m.group(2) for m in re.finditer(r'^@interface (_MTL\w+) : (\w+)\b', text, re.M)}


def main():
    root = args.root.resolve()
    target = Target(root)
    if target.uuid != target_surface.CACHE_UUID:
        fail(f'cache UUID {target.uuid} is not 21H461')
    roles = target.roles()
    by_name = {role['name']: role for role in roles}
    mapping = tomllib.loads((webmetal / ROLES).read_text()).get('class', [])
    mapped = []
    for entry in mapping:
        role = by_name.get(entry['target'])
        if not role:
            fail(f'{ROLES}: {entry["target"]} is not a Metal driver class of AGXMetalA10 on 21H461')
        role['plugin'] = entry['name']
        mapped.append(role)
    declared = private_bases((webmetal / PRIVATE).read_text())
    for name, superclass in sorted(declared.items()):
        if name not in target.classes:
            fail(f'{PRIVATE}: {name} is not a class of Metal.framework on 21H461')
        if target.classes[name]['super'] != superclass:
            fail(f'{PRIVATE}: {name} is declared a {superclass}, on 21H461 it is a {target.classes[name]["super"]}')
    for role in mapped:
        if role['base'] not in declared and role['base'] != ROOT_CLASS:
            fail(f'{PRIVATE} does not declare {role["base"]}, the base of {role["name"]}')
    selectors = {name: set() for name in declared}
    for role in mapped:
        if role['base'] in selectors:
            selectors[role['base']] |= set(role['rows'])
    bases = [target.base_layout(name, selectors[name]) for name in sorted(declared)]
    profile_text = (webmetal / PROFILE).read_text()
    device = by_name[PROFILED_CLASS]
    properties = {getter for protocol in device['protocols'] for getter in property_getters(target.protocols[protocol])}
    getters = ProfileGetters(profile_text, device, properties)
    notes_path = webmetal / NOTES
    notes = Notes(notes_path.read_text() if notes_path.exists() else None, roles, mapped)
    clients = tomllib.loads((webmetal / CLIENTS).read_text()).get('client', []) if (webmetal / CLIENTS).exists() else []

    outputs = {
        'WebMetalTargetSurface.h': surface_header(target, mapped, bases, getters, notes),
        'WebMetalProfileGetters.mm': getters_source(target, mapped, getters),
    }
    lists, client_lists = {}, {}
    errors, statuses, reasons = [], {}, {}
    if args.plugin:
        statuses = audit_plugin(args.plugin, target, mapped, getters, errors, reasons)
        outputs['surface.tsv'] = surface_tsv(target, roles, statuses)
        for client in clients:
            client_lists[client['name']] = client_rows(target, roles, client, statuses, reasons, notes)
            lists[client['name'] + '.tsv'] = client_tsv(target, client, client_lists[client['name']])
        check_notes(notes, mapped, statuses, reasons, client_lists, errors)
    elif args.check:
        fail('--check needs --plugin (the built iOS executable)')

    for folder, files in ((GENERATED, outputs), (CLIENT_LISTS, lists)):
        directory = webmetal / folder
        if args.write:
            directory.mkdir(parents=True, exist_ok=True)
            for name, text in files.items():
                (directory / name).write_text(text)
        else:
            for name, text in files.items():
                path = directory / name
                if not path.exists() or path.read_text() != text:
                    errors.append(f'{folder}/{name} differs from a fresh derivation; run with --write')
        if folder == CLIENT_LISTS and args.plugin and directory.exists():
            for path in sorted(directory.glob('*.tsv')):
                if path.name not in files:
                    errors.append(f'{folder}/{path.name} is the list of no client {CLIENTS} names')

    for role in mapped:
        rows = role['rows']
        count = {c: sum(1 for r in rows.values() if r['category'] == c) for c in ('driver', 'framework', 'absent')}
        status = statuses.get(role['name'], {})
        implemented = sum(1 for s in status.values() if s == 'implemented')
        profiled = sum(1 for s in status.values() if s == 'profile')
        loud = [key for key, row in sorted(rows.items())
                if row['category'] == 'driver' and status.get(key, 'loud') == 'loud']
        print(f'{role["plugin"]} for {" -> ".join(role["chain"])}: {count["driver"]} driver selectors '
              f'({implemented} implemented, {profiled} from the profile, {len(loud)} LOUD), {count["framework"]} '
              f'inherited from Metal.framework, {count["absent"]} absent')
        if args.backlog:
            for kind, selector in loud:
                print(f'    LOUD {"+" if kind == "class" else "-"}{selector}')
    others = [role for role in roles if 'plugin' not in role]
    print(f'{len(roles)} Metal driver classes on 21H461; {len(mapped)} with a plugin class; '
          f'{sum(sum(1 for r in role["rows"].values() if r["category"] == "driver") for role in others)} '
          f'driver selectors of the other {len(others)} are not served by any plugin class yet')
    print(f'{len(getters.methods)} capability getters from the device profile; {len(bases)} base classes guarded')
    for name, rows in client_lists.items():
        states = {}
        for row in rows:
            state = row[4]
            states[state] = states.get(state, 0) + 1
        order = ('implemented', 'profile', 'inherited', 'not-answered', 'loud', 'no-plugin-class')
        print(f'{name}: {len({r[0] for r in rows})} selectors, {len(rows)} driver-class rows: ' +
              ', '.join(f'{states.get(state, 0)} {state}' for state in order))
    for selector in getters.skipped:
        print(f'not generated: {selector} (Metal.framework reports validation failures for some arguments)')
    for message in errors:
        print('error: ' + message)
    if errors:
        sys.exit(1)
    print('PASS: ' + ('wrote ' + ', '.join(sorted(outputs) + sorted(lists)) if args.write else
                      'guest/Generated and guest/SPI/clients are current and the plugin matches the 21H461 surface'))


main()
