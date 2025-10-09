#!/usr/bin/env python3
"""
Script de migración de la versión 1 a la versión 2 de la API
Este script migra los datos existentes al nuevo esquema de la v2
"""

import os
import sys
import sqlite3
from datetime import datetime
from pathlib import Path

def migrate_database():
    """Migra la base de datos de v1 a v2"""
    
    # Ruta de la base de datos
    db_path = "instance/site.db"
    backup_path = f"instance/site_v1_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    
    if not os.path.exists(db_path):
        print("No se encontró la base de datos. Creando nueva base de datos v2...")
        return True
    
    # Hacer backup de la base de datos actual
    print(f"Creando backup de la base de datos en: {backup_path}")
    os.system(f"cp {db_path} {backup_path}")
    
    # Conectar a la base de datos
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Verificar si ya existe la estructura v2
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'nombre_completo' in columns:
            print("La base de datos ya parece estar en formato v2.")
            return True
        
        print("Migrando base de datos de v1 a v2...")
        
        # Obtener usuarios existentes
        cursor.execute("""
            SELECT id, username, email, password_hash, role, created_at 
            FROM users
        """)
        existing_users = cursor.fetchall()
        
        print(f"Encontrados {len(existing_users)} usuarios para migrar")
        
        # Crear nueva tabla users_v2
        cursor.execute("""
            CREATE TABLE users_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                nombre_completo VARCHAR(100) NOT NULL,
                apellidos VARCHAR(100) NOT NULL,
                direccion VARCHAR(255) NOT NULL,
                edad INTEGER NOT NULL,
                telefono VARCHAR(20) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'voluntarios',
                is_authorized BOOLEAN NOT NULL DEFAULT 0,
                foto_identificacion_path VARCHAR(255),
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                authorized_at DATETIME,
                authorized_by_id INTEGER,
                FOREIGN KEY (authorized_by_id) REFERENCES users_v2 (id),
                CHECK (edad >= 18),
                CHECK (role IN ('admin', 'voluntarios', 'personal', 'servicio_social', 
                               'visitas', 'familiares', 'donantes', 'proveedores'))
            )
        """)
        
        # Migrar usuarios existentes
        for user in existing_users:
            user_id, username, email, password_hash, old_role, created_at = user
            
            # Mapear roles antiguos a nuevos
            if old_role == 'admin':
                new_role = 'admin'
                is_authorized = 1  # Los admins están siempre autorizados
            else:
                new_role = 'voluntarios'  # Por defecto los 'user' se convierten en 'voluntarios'
                is_authorized = 1  # Mantener usuarios existentes como autorizados
            
            # Insertar usuario con datos por defecto para campos nuevos
            cursor.execute("""
                INSERT INTO users_v2 (
                    id, email, password_hash, nombre_completo, apellidos, 
                    direccion, edad, telefono, role, is_authorized, 
                    created_at, authorized_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, email, password_hash,
                username,  # Usar username como nombre_completo temporalmente
                "Por definir",  # apellidos por defecto
                "Por definir",  # direccion por defecto
                18,  # edad por defecto
                "0000000000",  # telefono por defecto
                new_role, is_authorized, created_at,
                datetime.now().isoformat() if is_authorized else None
            ))
            
            print(f"Migrado usuario: {email} ({old_role} -> {new_role})")
        
        # Eliminar tabla antigua y renombrar la nueva
        cursor.execute("DROP TABLE users")
        cursor.execute("ALTER TABLE users_v2 RENAME TO users")
        
        # Crear índices
        cursor.execute("CREATE INDEX idx_users_email ON users(email)")
        cursor.execute("CREATE INDEX idx_users_role ON users(role)")
        cursor.execute("CREATE INDEX idx_users_is_authorized ON users(is_authorized)")
        cursor.execute("CREATE INDEX idx_users_created_at ON users(created_at)")
        
        # Actualizar tabla de migración de Alembic para marcar como migrada
        cursor.execute("DROP TABLE IF EXISTS alembic_version")
        cursor.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        cursor.execute("INSERT INTO alembic_version VALUES ('v2_migration_complete')")
        
        conn.commit()
        print("✅ Migración completada exitosamente!")
        
        print("\n⚠️  IMPORTANTE: Los usuarios migrados tienen datos por defecto:")
        print("   - apellidos: 'Por definir'")
        print("   - direccion: 'Por definir'") 
        print("   - telefono: '0000000000'")
        print("   - edad: 18")
        print("   - Todos los usuarios están marcados como autorizados")
        print("   - Los usuarios podrán actualizar su perfil después del login")
        
        return True
        
    except Exception as e:
        print(f"❌ Error durante la migración: {e}")
        conn.rollback()
        # Restaurar backup
        if os.path.exists(backup_path):
            print("Restaurando backup...")
            os.system(f"cp {backup_path} {db_path}")
        return False
        
    finally:
        conn.close()

def create_directories():
    """Crear directorios necesarios para la v2"""
    directories = [
        "data/identificaciones",
        "instance"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Directorio creado/verificado: {directory}")

if __name__ == "__main__":
    print("🔄 Iniciando migración de API Login v1 -> v2")
    print("=" * 50)
    
    # Crear directorios necesarios
    create_directories()
    
    # Migrar base de datos
    if migrate_database():
        print("\n🎉 Migración completada con éxito!")
        print("\nPróximos pasos:")
        print("1. Los usuarios existentes pueden hacer login con sus credenciales actuales")
        print("2. Recomendamos que actualicen su información de perfil")
        print("3. Solo administradores pueden autorizar nuevos usuarios")
        print("4. Los nuevos usuarios deben registrarse con información completa")
    else:
        print("\n❌ La migración falló. Revisa los logs de error.")
        sys.exit(1)