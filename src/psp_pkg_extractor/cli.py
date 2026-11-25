"""Command-line interface."""
import argparse
import sys
from typing import Optional

from .errors import PkgError
from .extractor import extract_pkg, inspect_pkg


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='Extract locally supplied retail PSP PKG files offline.')
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='Validate and list package contents')
    inspect.add_argument('package')
    extract = commands.add_parser('extract', help='Extract package files into a staged directory')
    extract.add_argument('package')
    extract.add_argument('--output', required=True)
    extract.add_argument('--force', action='store_true', help='Replace existing regular files')
    extract.add_argument('--baseline', action='store_true', help='Extract only ISO/CSO, CONTENT.DAT, and PSP-KEY.EDAT')
    args = parser.parse_args(argv)
    try:
        result = None
        if args.command == 'extract':
            result = extract_pkg(args.package, args.output, force=args.force, baseline=args.baseline)
            info = result.info
        else:
            info = inspect_pkg(args.package)
        print(f'Content ID: {info.content_id}')
        print(f'Package type: {info.package_type}')
        print(f'Title ID: {info.title_id or "unavailable"}')
        print(f'Item count: {info.item_count}')
        for item in info.items:
            path = result.output / item.path if result else item.path
            print(f'{"directory" if item.is_directory else str(item.size) + " bytes"}\t{path}\t{item.payload_type}')
        if result:
            print(f'Total extracted bytes: {result.total_bytes}')
            print(f'Output: {result.output}')
        else:
            print(f'Total file bytes: {info.total_bytes}')
        return 0
    except (PkgError, OSError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('error: interrupted', file=sys.stderr)
        return 130
