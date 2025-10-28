"""
Script de migración para agregar el campo foto_identificacion_drive_id
Ejecutar este script para actualizar la base de datos existente
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

# Configuración de la base de datos
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./api_login.db')

def migrate_add_drive_id_field():
    """Agregar el campo foto_identificacion_drive_id a la tabla users"""
    
    engine = create_engine(DATABASE_URL)
    
    try:
        with engine.connect() as connection:
            # Verificar si la columna ya existe
            if 'sqlite' in DATABASE_URL.lower():
                # Para SQLite
                result = connection.execute(text("PRAGMA table_info(users)"))
                columns = [row[1] for row in result.fetchall()]
                
                if 'foto_identificacion_drive_id' not in columns:
                    connection.execute(text(
                        "ALTER TABLE users ADD COLUMN foto_identificacion_drive_id VARCHAR(255)"
                    ))
                    connection.commit()
                    print("✅ Campo foto_identificacion_drive_id agregado exitosamente (SQLite)")
                else:
                    print("ℹ️ Campo foto_identificacion_drive_id ya existe")
                    
            else:
                # Para PostgreSQL
                # Verificar si la columna existe
                result = connection.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='users' AND column_name='foto_identificacion_drive_id'
                """))
                
                if not result.fetchone():
                    connection.execute(text(
                        "ALTER TABLE users ADD COLUMN foto_identificacion_drive_id VARCHAR(255)"
                    ))
                    connection.commit()
                    print("✅ Campo foto_identificacion_drive_id agregado exitosamente (PostgreSQL)")
                else:
                    print("ℹ️ Campo foto_identificacion_drive_id ya existe")
                    
    except Exception as e:
        print(f"❌ Error durante la migración: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("Iniciando migración de base de datos...")
    if migrate_add_drive_id_field():
        print("✅ Migración completada exitosamente")
    else:
        print("❌ Error en la migración")