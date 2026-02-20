import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def check_user(email):
    load_dotenv()
    try:
        from database import SessionLocal
        from models import User
    except ImportError:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from database import SessionLocal
        from models import User

    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    
    if user:
        print(f"✅ User found: {user.email}")
        print(f"   Role: {user.role}")
        print(f"   Is Authorized: {user.is_authorized}")
        print(f"   Auth Status: {user.authorization_status}")
    else:
        print(f"❌ User {email} not found")
    
    db.close()

if __name__ == "__main__":
    check_user("admin@CDS.com")
