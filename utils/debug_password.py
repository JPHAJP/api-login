import os
import sys
import bcrypt
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def debug_password(email, password):
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
    
    if not user:
        print(f"❌ User {email} not found")
        return

    print(f"👤 User: {user.email}")
    print(f"🔑 Stored Hash: {user.password_hash}")
    print(f"📏 Hash Length: {len(user.password_hash)}")
    
    # Check prefixes
    prefixes = ['$2a$', '$2b$', '$2y$']
    has_prefix = any(user.password_hash.startswith(p) for p in prefixes)
    print(f"✅ Has valid prefix: {has_prefix}")

    # Check verification
    result = user.check_password(password)
    print(f"🧪 check_password('{password}') -> {result}")

    if not result:
        print("\n🔍 Manual verification attempt:")
        try:
            password_bytes = password.encode('utf-8')
            hash_bytes = user.password_hash.encode('utf-8')
            manual_check = bcrypt.checkpw(password_bytes, hash_bytes)
            print(f"   bcrypt.checkpw -> {manual_check}")
        except Exception as e:
            print(f"   ❌ Error during manual check: {e}")

    db.close()

if __name__ == "__main__":
    debug_password("admin@cds.com", "LaloncheraCDS-132372")
