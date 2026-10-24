#!/usr/bin/env python3
"""Inventory supplied UE artifacts without executing or unpacking them (Python 3.9+)."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET


KINDS = {
    '.exe': 'module', '.dll': 'module', '.pdb': 'symbols',
    '.pak': 'pak_candidate', '.utoc': 'iostore_toc_candidate',
    '.ucas': 'iostore_data_candidate', '.uasset': 'asset_candidate',
    '.umap': 'map_candidate', '.uexp': 'package_export_candidate',
    '.ubulk': 'bulk_data_candidate', '.dmp': 'dump', '.mdmp': 'dump',
    '.utrace': 'trace', '.usmap': 'mapping_candidate', '.log': 'log',
    '.uproject': 'project_descriptor', '.uplugin': 'plugin_descriptor',
    '.modules': 'module_manifest', '.target': 'target_manifest',
}
BUILD_FIELDS = ('MajorVersion', 'MinorVersion', 'PatchVersion', 'Changelist',
                'CompatibleChangelist', 'BranchName')
CRASH_FIELDS = ('EngineVersion', 'BuildVersion', 'BuildConfiguration',
                'PlatformName', 'CrashGUID', 'CrashType')


def is_link(info):
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, 'st_file_attributes', 0) & 0x400  # Windows reparse point
    )


def issue(report, code, path, message, partial=True):
    report['diagnostics'].append({'code': code, 'path': str(path), 'message': message})
    if partial:
        report['status'] = 'partial'


def decode_metadata(raw):
    if raw.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        return raw.decode('utf-32')
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16')
    if raw.startswith(b'<\x00'):
        return raw.decode('utf-16-le')
    if raw.startswith(b'\x00<'):
        return raw.decode('utf-16-be')
    return raw.decode('utf-8-sig')


def scalar_fields(data, names, report, path):
    values = {}
    for key in names:
        if key not in data:
            continue
        value = data[key]
        if type(value) not in (int, str) or (isinstance(value, str) and len(value) > 4096):
            issue(report, 'invalid_metadata_field', path, f'Unsupported value for {key}')
        else:
            values[key] = value
    return values


def read_metadata(path, artifact, report, limit):
    kind = artifact['kind']
    if kind not in ('build_version', 'project_descriptor', 'crash_context'):
        return
    try:
        # Read with a bound even if the file grows after the preceding stat.
        with path.open('rb') as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            issue(report, 'metadata_size_limit', path, f'Metadata exceeds {limit} bytes')
            return
        text = decode_metadata(raw)
        if kind == 'crash_context':
            if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.I):
                issue(report, 'xml_declaration_rejected', path, 'DTD and entity declarations are not accepted')
                return
            tree = ET.fromstring(text)
            local_tag = lambda tag: tag.rsplit('}', 1)[-1]
            runtime = tree if local_tag(tree.tag) == 'RuntimeProperties' else next(
                (node for node in tree if local_tag(node.tag) == 'RuntimeProperties'), None
            )
            if runtime is None:
                issue(report, 'missing_runtime_properties', path, 'No RuntimeProperties in crash context')
                return
            data = {local_tag(node.tag): (node.text or '').strip() for node in runtime
                    if local_tag(node.tag) in CRASH_FIELDS}
            artifact['metadata'] = scalar_fields(data, CRASH_FIELDS, report, path)
            raw_version = artifact['metadata'].get('EngineVersion', '')
            match = re.match(r'^(\d+\.\d+\.\d+)(?:[-+].*)?$', raw_version)
            if match:
                report['engine_version_hints'].append({
                    'path': artifact['path'], 'field': 'EngineVersion',
                    'version': match.group(1), 'raw': raw_version,
                })
        else:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError('Metadata root must be an object')
            fields = BUILD_FIELDS if kind == 'build_version' else ('EngineAssociation',)
            artifact['metadata'] = scalar_fields(data, fields, report, path)
            if kind == 'project_descriptor':
                artifact['interpretation'] = 'EngineAssociation is a declaration, not a verified engine version'
                return
            version_parts = [data.get(key) for key in BUILD_FIELDS[:3]]
            if all(type(value) is int and value >= 0 for value in version_parts):
                report['engine_version_hints'].append({
                    'path': artifact['path'], 'field': 'MajorVersion/MinorVersion/PatchVersion',
                    'version': '.'.join(map(str, version_parts)),
                })
            else:
                issue(report, 'invalid_build_version', path, 'Major, minor and patch must be nonnegative integers')
    except (OSError, ValueError, UnicodeError, ET.ParseError, RecursionError) as exc:
        # Parser exception text can contain source content. Do not echo it.
        issue(report, 'metadata_read_failed', path, type(exc).__name__)


def inspect(path, max_files=2000, max_depth=8, max_entries=10000, max_metadata_bytes=1048576):
    root = Path(os.path.abspath(os.path.expanduser(str(path))))
    report = {
        'schema_version': 1, 'root': str(root), 'status': 'ok',
        'limits': {'max_files': max_files, 'max_depth': max_depth,
                   'max_entries': max_entries, 'max_metadata_bytes': max_metadata_bytes},
        'scan': {'entries_seen': 0, 'files_seen': 0, 'directories_scanned': 0,
                 'linked_entries_skipped': 0, 'complete': True},
        'artifacts': [], 'engine_version_hints': [], 'engine_version_conflict': False,
        'diagnostics': [],
    }
    try:
        for ancestor in (root, *root.parents):
            if is_link(ancestor.lstat()):
                raise ValueError('Root or a parent is a symbolic link or reparse point')
        root_info = root.lstat()
        if not (stat.S_ISREG(root_info.st_mode) or stat.S_ISDIR(root_info.st_mode)):
            raise ValueError('Input must be a regular file or directory')
    except (OSError, ValueError) as exc:
        issue(report, 'invalid_input', root, str(exc))
        report['status'] = 'error'
        report['scan']['complete'] = False
        return report

    def add_file(item, info):
        if report['scan']['files_seen'] >= max_files:
            issue(report, 'file_limit', item, 'File limit reached; inventory is incomplete')
            report['scan']['complete'] = False
            return False
        report['scan']['files_seen'] += 1
        name = item.name.lower()
        kind = ('build_version' if name == 'build.version' else
                'crash_context' if name == 'crashcontext.runtime-xml' else
                KINDS.get(item.suffix.lower()))
        if kind is not None or item == root:
            artifact = {'path': str(item), 'kind': kind or 'other', 'size_bytes': info.st_size}
            report['artifacts'].append(artifact)
            read_metadata(item, artifact, report, max_metadata_bytes)
        return True

    if stat.S_ISREG(root_info.st_mode):
        add_file(root, root_info)
    else:
        stack = [(root, 0)]
        stop = False
        while stack and not stop:
            directory, depth = stack.pop()
            try:
                # Recheck queued directories before traversing them.
                if is_link(directory.lstat()):
                    report['scan']['linked_entries_skipped'] += 1
                    report['scan']['complete'] = False
                    issue(report, 'link_skipped', directory, 'Link or reparse point was not followed')
                    continue
                report['scan']['directories_scanned'] += 1
                names = []
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if report['scan']['entries_seen'] >= max_entries:
                            issue(report, 'entry_limit', directory, 'Directory entry limit reached')
                            report['scan']['complete'] = False
                            stop = True
                            break
                        report['scan']['entries_seen'] += 1
                        names.append(entry.name)
                for name in sorted(names, key=lambda value: (value.casefold(), value)):
                    item = directory / name
                    try:
                        info = item.lstat()
                        if is_link(info):
                            report['scan']['linked_entries_skipped'] += 1
                            report['scan']['complete'] = False
                            issue(report, 'link_skipped', item, 'Link or reparse point was not followed')
                        elif stat.S_ISDIR(info.st_mode):
                            if depth < max_depth:
                                stack.append((item, depth + 1))
                            else:
                                report['scan']['complete'] = False
                                issue(report, 'depth_limit', item, 'Directory depth limit reached')
                        elif stat.S_ISREG(info.st_mode) and not add_file(item, info):
                            stop = True
                            break
                    except OSError as exc:
                        report['scan']['complete'] = False
                        issue(report, 'stat_failed', item, type(exc).__name__)
            except OSError as exc:
                report['scan']['complete'] = False
                issue(report, 'directory_read_failed', directory, type(exc).__name__)

    report['artifacts'].sort(key=lambda item: item['path'].casefold())
    report['engine_version_conflict'] = len({hint['version'] for hint in report['engine_version_hints']}) > 1
    if report['engine_version_conflict']:
        issue(report, 'version_sources_differ', root,
              'Version sources differ; associate each source with the target build before deciding', partial=False)
    for artifact in report['artifacts']:
        if artifact['kind'] == 'iostore_toc_candidate':
            toc = Path(artifact['path'])
            artifact['related_data_candidates'] = [other['path'] for other in report['artifacts']
                if other['kind'] == 'iostore_data_candidate'
                and Path(other['path']).parent == toc.parent
                and (Path(other['path']).stem.casefold() == toc.stem.casefold()
                     or Path(other['path']).stem.casefold().startswith(toc.stem.casefold() + '_'))]
            artifact['container_validation'] = 'not_performed'
            artifact['pairing_note'] = 'Filename candidates only; verify partitions and layout with matching tools'
    return report


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must be nonnegative')
    return number


class JsonParser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({'schema_version': 1, 'status': 'error',
                          'diagnostics': [{'code': 'invalid_arguments', 'message': message}]}))
        raise SystemExit(2)


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = JsonParser(description=__doc__, epilog='Exit codes: 0 complete, 1 partial, 2 invalid input. No output files are written.')
    parser.add_argument('path', help='Supplied local file or directory')
    parser.add_argument('--max-files', type=positive, default=2000)
    parser.add_argument('--max-depth', type=nonnegative, default=8)
    parser.add_argument('--max-entries', type=positive, default=10000)
    parser.add_argument('--max-metadata-bytes', type=positive, default=1048576)
    report = inspect(**vars(parser.parse_args()))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return {'ok': 0, 'partial': 1, 'error': 2}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
