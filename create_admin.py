#!/usr/bin/env python3
"""
Script para crear un usuario administrador en la API v2
"""

import os
import sys
from getpass import getpass

# Agregar el directorio actual al path para importar los módulos
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User

def create_admin():
    """Crear un usuario administrador"""
    
    with app.app_context():
        print("🔧 Creación de Usuario Administrador")
        print("=" * 40)
        
        # Solicitar datos del administrador
        email = input("Email del administrador: ").strip()
        
        if not email:
            print("❌ El email es requerido")
            return False
        
        # Verificar si ya existe
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"❌ Ya existe un usuario con el email: {email}")
            return False
        
        password = getpass("Contraseña: ")
        if len(password) < 6:
            print("❌ La contraseña debe tener al menos 6 caracteres")
            return False
        
        password_confirm = getpass("Confirmar contraseña: ")
        if password != password_confirm:
            print("❌ Las contraseñas no coinciden")
            return False
        
        nombre = input("Nombre completo: ").strip()
        if not nombre:
            print("❌ El nombre es requerido")
            return False
        
        apellidos = input("Apellidos: ").strip()
        if not apellidos:
            print("❌ Los apellidos son requeridos") 
            return False
        
        print("\n✅ Creando administrador...")
        
        try:
            # Crear usuario administrador
            admin = User(
                email=email,
                nombre_completo=nombre,
                apellidos=apellidos,
                direccion="Oficina Central",
                edad=25,
                telefono="0000000000",
                role='admin',
                is_authorized=True  # Los admins siempre están autorizados
            )
            admin.set_password(password)
            
            db.session.add(admin)
            db.session.commit()
            
            print(f"🎉 Administrador creado exitosamente!")
            print(f"   Email: {email}")
            print(f"   Nombre: {nombre} {apellidos}")
            print(f"   Rol: admin")
            print(f"   ID: {admin.id}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error al crear administrador: {e}")
            db.session.rollback()
            return False

if __name__ == "__main__":
    if create_admin():
        print("\n✅ ¡Listo! Ahora puedes hacer login con las credenciales del administrador.")
    else:
        print("\n❌ No se pudo crear el administrador.")
        sys.exit(1)