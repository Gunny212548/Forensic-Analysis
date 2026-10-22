"""Create, update, list or remove login accounts (FR-1).

There is no sign-up page on purpose - an administrator decides who may read
customer logs. Run it inside the container so it writes the same AUTH_DIR
(the accounts store, apart from customer data - config.py):

    docker exec -it forensic-analyzer-forensic-analyzer-1 \\
        python tools/create_user.py add someone@example.com --name "Somchai" --role analyst
    docker exec forensic-analyzer-forensic-analyzer-1 python tools/create_user.py list
    docker exec forensic-analyzer-forensic-analyzer-1 python tools/create_user.py remove someone@example.com
    docker exec forensic-analyzer-forensic-analyzer-1 python tools/create_user.py role someone@example.com manager

`add` on an existing email updates its name/role and resets its password.
The password is prompted for; pass --password-stdin to pipe it in instead.
Removing an account ends its sessions at once (see app/services/auth.py).
Roles: admin, manager, analyst (app/services/authz.py, IAI-14). Every change
goes through auth.py like the Users page does - checked the same way (the last
administrator stays one) and written to the hash-chained account audit log,
with the actor `cli:<operating-system user>`.
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import auth, authz  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="create an account, or update one and reset its password")
    add.add_argument("email")
    add.add_argument("--name", default="")
    add.add_argument("--role", default=auth.DEFAULT_ROLE, choices=authz.ROLES)
    add.add_argument("--password-stdin", action="store_true")
    sub.add_parser("list")
    rm = sub.add_parser("remove")
    rm.add_argument("email")
    ro = sub.add_parser("role", help="change an account's role, keeping its password")
    ro.add_argument("email")
    ro.add_argument("role", choices=authz.ROLES)
    args = ap.parse_args()

    users = auth.load_users()

    if args.cmd == "list":
        for u in users.values():
            print(f"{u['email']:<40} {u.get('role', ''):<10} {u.get('name', '')}")
        print(f"{len(users)} account(s)")
        return 0

    email = auth.normalize_email(args.email)
    actor = f"cli:{getpass.getuser()}"
    if args.cmd == "remove":
        try:
            auth.remove_account(actor, email)
        except (LookupError, auth.AccountError) as exc:
            print(exc, file=sys.stderr)
            return 1
        print(f"removed {email}")
        return 0
    if args.cmd == "role":
        try:
            auth.update_account(actor, email, role=args.role)
        except (LookupError, auth.AccountError) as exc:
            print(exc, file=sys.stderr)
            return 1
        print(f"{email} is now {args.role}")
        return 0

    if "@" not in email:
        print("email must contain @", file=sys.stderr)
        return 1
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("password: ")
        if getpass.getpass("again: ") != password:
            print("passwords differ", file=sys.stderr)
            return 1
    existing = email in users
    try:
        if existing:
            auth.update_account(actor, email, name=args.name or None, role=args.role)
            auth.reset_password(actor, email, password)
        else:
            auth.create_account(actor, email, args.name or email, args.role, password)
    except auth.AccountError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"{'updated' if existing else 'created'} {email} ({args.role})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
