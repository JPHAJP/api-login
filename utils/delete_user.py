import os
import sys
from dotenv import load_dotenv

# Add current directory to path of the script to find sibling modules if needed, 
# though we are running from root usually.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def delete_user(email):
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
        db.delete(user)
        db.commit()
        print(f"✅ Deleted user: {email}")
    else:
        print(f"⚠️ User {email} not found.")

    db.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        delete_user(sys.argv[1])
    else:
        print("Usage: python delete_user.py <email>")
