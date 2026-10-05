"""Create, update, list or remove login accounts (FR-1).

There is no sign-up page on purpose - an administrator decides who may read
customer logs. Run it inside the container so it writes the same DATA_DIR:

    docker exec -it forensic-analyzer-forensic-analyzer-1 \\
        python tools/create_user.py add someone@example.com --name "Somchai" --role analyst
    docker exec forensic-analyzer-forensic-analyzer-1 python tools/create_user.py list
    docker exec forensic-analyzer-forensic-analyzer-1 python tools/create_user.py remove someone@example.com

`add` on an existing email updates its name/role and resets its password.
The password is prompted for; pass --password-stdin to pipe it in instead.
Removing an account ends its sessions at once (see app/services/auth.py).
"""

import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import auth  # noqa: E402

MIN_PASSWORD = 10


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="create an account, or update one and reset its password")
    add.add_argument("email")
    add.add_argument("--name", default="")
    add.add_argument("--role", default=auth.DEFAULT_ROLE)
    add.add_argument("--password-stdin", action="store_true")
    sub.add_parser("list")
    rm = sub.add_parser("remove")
    rm.add_argument("email")
    args = ap.parse_args()

    users = auth.load_users()

    if args.cmd == "list":
        for u in users.values():
            print(f"{u['email']:<40} {u.get('role', ''):<10} {u.get('name', '')}")
        print(f"{len(users)} account(s)")
        return 0

    email = auth.normalize_email(args.email)
    if args.cmd == "remove":
        if users.pop(email, None) is None:
            print(f"no account {email}", file=sys.stderr)
            return 1
        auth.save_users(users)
        print(f"removed {email}")
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
    if len(password) < MIN_PASSWORD:
        print(f"password must be at least {MIN_PASSWORD} characters", file=sys.stderr)
        return 1

    existing = users.get(email, {})
    users[email] = {
        "email": email,
        "name": args.name or existing.get("name") or email,
        "role": args.role,
        "password": auth.hash_password(password),
        "created": existing.get("created") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    auth.save_users(users)
    print(f"{'updated' if existing else 'created'} {email} ({args.role})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
