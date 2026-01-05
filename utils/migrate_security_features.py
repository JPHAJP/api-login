#!/usr/bin/env python3
"""
Script de migración para agregar las tablas y columnas de seguridad a la base de datos.

Este script:
1. Agrega columnas de seguridad a la tabla users (failed_login_attempts, etc.)
2. Crea la tabla security_logs
3. Mantiene los datos existentes intactos

Uso:
    python migrate_security_features.py
"""

import sys
import os

# Agregar el directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from database import get_db, engine as db_engine
from models import Base, User, SecurityLog
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./site.db')

def migrate_database():
    """Ejecuta las migraciones de base de datos."""
    
    print("=" * 80)
    print("🔧 MIGRACIÓN: Sistema de Logs de Seguridad")
    print("=" * 80)
    print()
    
    # Crear engine
    engine = create_engine(DATABASE_URL)
    
    print("📋 Verificando tablas existentes...")
    
    try:
        # Obtener sesión
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        
        # Verificar si las nuevas columnas ya existen
        print("\n📊 Verificando columnas de seguridad en tabla users...")
        
        # PostgreSQL
        if "postgresql" in DATABASE_URL:
            result = db.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='users' AND column_name IN ('failed_login_attempts', 'last_failed_login', 'account_locked_until')
            """))
            existing_columns = [row[0] for row in result]
            
            if len(existing_columns) == 0:
                print("  ℹ️  Columnas de seguridad no encontradas, agregando...")
                
                db.execute(text("""
                    ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0 NOT NULL,
                    ADD COLUMN IF NOT EXISTS last_failed_login TIMESTAMP,
                    ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP
                """))
                
                db.commit()
                print("  ✅ Columnas agregadas exitosamente")
            else:
                print(f"  ✅ Columnas ya existen: {', '.join(existing_columns)}")
        
        # SQLite
        elif "sqlite" in DATABASE_URL:
            result = db.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result]
            
            new_columns_needed = []
            if 'failed_login_attempts' not in columns:
                new_columns_needed.append('failed_login_attempts')
            if 'last_failed_login' not in columns:
                new_columns_needed.append('last_failed_login')
            if 'account_locked_until' not in columns:
                new_columns_needed.append('account_locked_until')
            
            if new_columns_needed:
                print(f"  ℹ️  Agregando columnas: {', '.join(new_columns_needed)}")
                
                if 'failed_login_attempts' in new_columns_needed:
                    db.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0 NOT NULL"))
                if 'last_failed_login' in new_columns_needed:
                    db.execute(text("ALTER TABLE users ADD COLUMN last_failed_login DATETIME"))
                if 'account_locked_until' in new_columns_needed:
                    db.execute(text("ALTER TABLE users ADD COLUMN account_locked_until DATETIME"))
                
                db.commit()
                print("  ✅ Columnas agregadas exitosamente")
            else:
                print("  ✅ Todas las columnas ya existen")
        
        # Crear tabla security_logs si no existe
        print("\n📊 Verificando tabla security_logs...")
        
        Base.metadata.create_all(bind=engine, tables=[SecurityLog.__table__])
        print("  ✅ Tabla security_logs verificada/creada")
        
        # Verificar que todo está OK
        print("\n🔍 Verificación final...")
        
        # Contar usuarios
        user_count = db.query(User).count()
        print(f"  📊 Usuarios en la base de datos: {user_count}")
        
        # Contar logs de seguridad
        security_log_count = db.query(SecurityLog).count()
        print(f"  📊 Logs de seguridad existentes: {security_log_count}")
        
        db.close()
        
        print()
        print("=" * 80)
        print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
        print("=" * 80)
        print()
        print("📝 Cambios aplicados:")
        print("  ✅ Columnas de seguridad agregadas a tabla users")
        print("  ✅ Tabla security_logs creada/verificada")
        print()
        print("🚀 El sistema está listo para usar las nuevas funcionalidades de seguridad")
        print()
        
        return 0
        
    except Exception as e:
        print()
        print("=" * 80)
        print("❌ ERROR EN LA MIGRACIÓN")
        print("=" * 80)
        print(f"Error: {e}")
        print()
        print("💡 Posibles soluciones:")
        print("  1. Verifica que la base de datos esté accesible")
        print("  2. Verifica que DATABASE_URL en .env sea correcto")
        print("  3. Asegúrate de tener permisos de escritura en la base de datos")
        print()
        
        import traceback
        traceback.print_exc()
        
        return 1


if __name__ == "__main__":
    sys.exit(migrate_database())
