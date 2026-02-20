import os
import sys
from dotenv import load_dotenv

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

def create_admin():
    load_dotenv()
    
    try:
        from database import SessionLocal
        from models import User
    except ImportError:
        # Fallback for relative imports if running from utils/
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from database import SessionLocal
        from models import User

    db = SessionLocal()
    
    email = "admin@CDS.com"
    password = "LaloncheraCDS-132372" # Strong-ish default for dev
    
    # Check if exists
    user = db.query(User).filter(User.email == email).first()
    
    if user:
        print(f"User {email} already exists.")
        if user.role != 'admin':
            user.role = 'admin'
            user.is_authorized = True
            user.authorization_status = 'authorized'
            db.commit()
            print(f"Updated {email} to admin.")
        else:
            print(f"{email} is already an admin.")
    else:
        new_user = User(
            email=email,
            nombre_completo="Admin",
            apellidos="User",
            direccion="System",
            edad=30,
            telefono="1234567890",
            role='admin',
            is_authorized=True,
            authorization_status='authorized'
        )
        new_user.set_password(password)
        db.add(new_user)
        db.commit()
        print(f"Created admin user: {email}")
        print(f"Password: {password}")

    db.close()

if __name__ == "__main__":
    create_admin()
