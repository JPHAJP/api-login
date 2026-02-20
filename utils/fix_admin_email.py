import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def fix_admin_email(old_email, new_email):
    load_dotenv()
    try:
        from database import SessionLocal
        from models import User
    except ImportError:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from database import SessionLocal
        from models import User

    db = SessionLocal()
    user = db.query(User).filter(User.email == old_email).first()
    
    if user:
        print(f"Found user with email: {user.email}")
        user.email = new_email
        db.commit()
        print(f"✅ Updated email to: {new_email}")
    else:
        print(f"❌ User {old_email} not found")
        # Check if already fixed
        user_new = db.query(User).filter(User.email == new_email).first()
        if user_new:
            print(f"⚠️  User {new_email} already exists (maybe already fixed?)")
    
    db.close()

if __name__ == "__main__":
    fix_admin_email("admin@CDS.com", "admin@cds.com")
