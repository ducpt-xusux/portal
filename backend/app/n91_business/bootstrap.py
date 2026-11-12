"""Run manually: python -m app.n91_business.bootstrap --help. Never auto-run."""
import argparse
from getpass import getpass
from pathlib import Path
from .config import BusinessConfig
from .service import BusinessService, BusinessError
from .models import Role


def main():
    parser = argparse.ArgumentParser(description='Operator-only setup of a dedicated Portal business DB.')
    parser.add_argument('--database', required=True, type=Path)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--username', help='Create the first Portal account')
    operation.add_argument('--migrate-only', action='store_true', help='Upgrade an existing Portal database')
    parser.add_argument('--role', action='append', choices=[r.value for r in Role])
    parser.add_argument('--portal-admin', action='store_true', help='Explicit separate Portal user-management permission')
    parser.add_argument('--context', choices=['PORTAL', 'TEST'], required=True)
    args = parser.parse_args()
    service = BusinessService(BusinessConfig(database_path=args.database, context=args.context))
    if args.migrate_only:
        if args.role or args.portal_admin:
            parser.error('--migrate-only does not accept account options')
        try:
            service.migrate()
        except BusinessError as exc:
            parser.exit(2, exc.code + '\n')
        print('Portal Business database schema is current.')
        return
    if not args.role:
        parser.error('--role is required with --username')
    password = getpass('New Portal password (12–128 characters): ')
    if password != getpass('Confirm password: '):
        parser.exit(2, 'Password confirmation differs.\n')
    try:
        service.initialize()
        service.bootstrap(args.username, password, args.role, portal_admin=args.portal_admin)
    except BusinessError as exc:
        parser.exit(2, exc.code + '\n')
    finally:
        password = None
    print('Portal account created. No credentials or tokens printed. Source systems unchanged.')


if __name__ == '__main__':
    main()
