import argparse
import json
import base64
from core.database import Database
from core.security import EncryptionManager
from core.configs import ConfigManager
from core.migration import migrate_filesystem_to_db
from core.backup import BackupManager


def main():
    parser = argparse.ArgumentParser(prog='seq')
    sub = parser.add_subparsers(dest='cmd')

    sub.add_parser('list')
    get = sub.add_parser('get')
    get.add_argument('category')
    get.add_argument('provider')
    get.add_argument('config')

    setp = sub.add_parser('set')
    setp.add_argument('category')
    setp.add_argument('provider')
    setp.add_argument('config')
    setp.add_argument('--value')

    sub.add_parser('export')
    sub.add_parser('import')
    sub.add_parser('migrate')
    sub.add_parser('backup-create')
    restore = sub.add_parser('backup-restore')
    restore.add_argument('path')
    rotate = sub.add_parser('rotate-master')
    rotate.add_argument('old')
    rotate.add_argument('new')

    args = parser.parse_args()
    db = Database()
    enc = EncryptionManager(None)
    cfg = ConfigManager(db, enc)
    backup = BackupManager(enc, db)

    if args.cmd == 'list':
        print(json.dumps(db.list_all(), indent=2))
    elif args.cmd == 'migrate':
        n = migrate_filesystem_to_db(db, cfg)
        print(f'Migrated {n} entries')
    elif args.cmd == 'backup-create':
        p = backup.create_backup()
        print('Created', p)
    elif args.cmd == 'backup-restore':
        backup.restore_backup(args.path)
        print('Restored', args.path)
    elif args.cmd == 'rotate-master':
        enc.rotate_master_password(args.old, args.new, db, cfg)
        print('Rotation complete')
    else:
        parser.print_help()


if __name__ == '__main__':
    main()