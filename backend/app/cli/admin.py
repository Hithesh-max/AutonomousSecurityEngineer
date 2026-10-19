import argparse
import getpass
from app.config.database import SessionLocal
from app.models.user import User
from app.core import security

def set_password(username: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            print(f"Error: User '{username}' not found.")
            return

        new_password = getpass.getpass(f"New Password for {username}: ")
        confirm_password = getpass.getpass("Confirm Password: ")
        
        if new_password != confirm_password:
            print("Error: Passwords do not match.")
            return

        user.hashed_password = security.get_password_hash(new_password)
        user.is_active = True
        user.token_version += 1
        db.commit()
        print(f"Success: Password for '{username}' updated. Old tokens are invalidated.")
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Administrative commands for ASE")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pwd_parser = subparsers.add_parser("set-password", help="Set the password for a user account (e.g., legacy_admin)")
    pwd_parser.add_argument("username", help="The username to update")

    args = parser.parse_args()

    if args.command == "set-password":
        set_password(args.username)
