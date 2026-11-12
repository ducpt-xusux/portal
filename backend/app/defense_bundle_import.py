"""Operator entry point for pinned defense tar intake. Dry-run unless --publish."""
import argparse
import json
from pathlib import Path

from .defense_bundle import (
    DefenseBundleError, DefenseRegistry, build_registry, digest, publish_registry, summarize_registry,
)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise DefenseBundleError('DEFENSE_ARGUMENTS_INVALID')


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--pins', required=True, type=Path)
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--output', type=Path)
    try:
        args = parser.parse_args(argv)
        if args.publish != (args.output is not None):
            raise DefenseBundleError('DEFENSE_EXPLICIT_PUBLISH_REQUIRED')
        prepared = build_registry(args.source_root, args.pins)
        if args.publish:
            status = publish_registry(prepared, args.output)
            registry, registry_sha = DefenseRegistry(args.output).read()
        else:
            status = 'DRY_RUN_VALID'
            registry = prepared.registry
            registry_sha = digest(registry.model_dump_json().encode())
        print(json.dumps({'status': status, 'summary': summarize_registry(registry, registry_sha).model_dump(mode='json')},
                         ensure_ascii=True))
        return 0
    except DefenseBundleError as error:
        print(json.dumps({'status': 'REJECTED', 'error_code': error.code}))
        return 2
    except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
        print(json.dumps({'status': 'REJECTED', 'error_code': 'DEFENSE_INTAKE_UNAVAILABLE'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
