from app import app, db
from models import User

with app.app_context():
    admin = User(
        email="admin@example.com",
        nombre_completo="Admin",
        apellidos="Principal",
        direccion="Oficina Central",
        edad=30,
        telefono="+525512345678",
        role="admin",
        is_authorized=True
    )
    admin.set_password("admin_secure_password_123")
    db.session.add(admin)
    db.session.commit()
    print("Administrador creado exitosamente")