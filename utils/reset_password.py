import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def reset_password(email, new_password):
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
        print(f"Found user: {user.email}")
        user.set_password(new_password)
        db.commit()
        print(f"✅ Password updated for {email}")
    else:
        print(f"❌ User {email} not found")
    
    db.close()

if __name__ == "__main__":
    if len(sys.argv) > 2:
        reset_password(sys.argv[1], sys.argv[2])
    else:
        # Default for the task
        reset_password("admin@CDS.com", "LaloncheraCDS-132372")
