#!/usr/bin/env python3
"""
Script para crear un usuario administrador
Carga automáticamente variables de entorno desde .env
"""

import os
import sys
from getpass import getpass
from dotenv import load_dotenv

# Agregar el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Función principal"""
    print("🚀 Creador de Administrador (Auto .env)")
    print("=" * 45)
    
    # Cargar variables de entorno desde .env
    print("📁 Cargando configuración desde .env...")
    load_dotenv()
    
    # Verificar DATABASE_URL
    db_url = os.getenv('DATABASE_URL')
    if not db_url:
        print("❌ DATABASE_URL no encontrado en .env")
        print("💡 Verifica que tengas un archivo .env con DATABASE_URL")
        return False
    
    # Detectar tipo de BD
    if db_url.startswith('postgresql://') or db_url.startswith('postgres://'):
        db_type = "PostgreSQL"
        safe_url = db_url.split('@')[0].split(':')[:-1]
        safe_url = ':'.join(safe_url) + ':***@' + db_url.split('@')[1]
    elif db_url.startswith('sqlite:'):
        db_type = "SQLite"
        safe_url = db_url
    else:
        db_type = "Otro"
        safe_url = db_url[:30] + "..."
    
    print(f"✅ BD detectada: {db_type}")
    print(f"   Conexión: {safe_url}")
    
    # Importar módulos después de cargar .env
    try:
        from database import SessionLocal, create_tables
        from models import User
    except Exception as e:
        print(f"❌ Error importando: {e}")
        return False
    
    # Probar conexión
    try:
        print("🔍 Probando conexión...")
        from sqlalchemy import text
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        print("✅ Conexión exitosa")
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return False
    
    # Crear tablas
    try:
        print("🔧 Verificando tablas...")
        create_tables()
        print("✅ Tablas OK")
    except Exception as e:
        print(f"❌ Error con tablas: {e}")
        return False
    
    # Crear admin
    db = SessionLocal()
    try:
        print("\n👤 Datos del Admin:")
        print("-" * 25)
        
        email = input("Email: ").strip()
        if not email:
            print("❌ Email requerido")
            return False
        
        # Verificar si existe
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"⚠️  Usuario existe: {existing.role}")
            if existing.role == 'admin':
                print("✅ Ya es admin")
                return True
            else:
                convert = input("¿Convertir a admin? (s/N): ").lower() == 's'
                if convert:
                    existing.role = 'admin'
                    existing.is_authorized = True
                    existing.authorization_status = 'authorized'
                    db.commit()
                    print("✅ Convertido a admin")
                    return True
                return False
        
        password = getpass("Contraseña (min 8 chars): ")
        if len(password) < 8:
            print("❌ Mínimo 8 caracteres")
            return False
        
        confirm = getpass("Confirmar contraseña: ")
        if password != confirm:
            print("❌ Las contraseñas no coinciden")
            print("💡 Asegúrate de escribir exactamente la misma contraseña")
            return False
        
        nombre = input("Nombre: ").strip()
        apellidos = input("Apellidos: ").strip()
        
        if not all([nombre, apellidos]):
            print("❌ Nombre y apellidos requeridos")
            return False
        
        print("\n⚙️  Creando...")
        
        admin = User(
            email=email,
            nombre_completo=nombre,
            apellidos=apellidos,
            direccion="Admin Office",
            edad=30,
            telefono="0000000000",
            role='admin',
            is_authorized=True,
            authorization_status='authorized'
        )
        admin.set_password(password)
        
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        print(f"🎉 ¡Admin creado!")
        print(f"   ID: {admin.id}")
        print(f"   Email: {email}")
        print(f"   Nombre: {nombre} {apellidos}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    if main():
        print("\n✅ Listo! Puedes hacer login ahora.")
    else:
        print("\n❌ Falló la creación.")
        sys.exit(1)