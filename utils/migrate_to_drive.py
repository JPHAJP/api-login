"""
Script para migrar archivos locales existentes a Google Drive
Ejecutar después de configurar Google Drive para migrar imágenes ya existentes
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

from models import User
from utils.google_drive import upload_identification_image

load_dotenv()

# Configuración de la base de datos
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./api_login.db')

def migrate_local_files_to_drive():
    """Migrar archivos locales existentes a Google Drive"""
    
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = SessionLocal()
    
    try:
        # Obtener usuarios que tienen rutas locales pero no ID de Drive
        users_to_migrate = db.query(User).filter(
            User.foto_identificacion_path.isnot(None),
            User.foto_identificacion_drive_id.is_(None),
            ~User.foto_identificacion_path.startswith('drive://')
        ).all()
        
        print(f"Encontrados {len(users_to_migrate)} usuarios con archivos locales para migrar...")
        
        migrated_count = 0
        error_count = 0
        
        for user in users_to_migrate:
            print(f"\nMigrando usuario {user.id} - {user.email}")
            
            # Verificar que el archivo local existe
            if not os.path.exists(user.foto_identificacion_path):
                print(f"  ❌ Archivo no encontrado: {user.foto_identificacion_path}")
                error_count += 1
                continue
            
            try:
                # Leer archivo local
                with open(user.foto_identificacion_path, 'rb') as f:
                    content = f.read()
                
                # Determinar extensión
                filename = os.path.basename(user.foto_identificacion_path)
                if '.' in filename:
                    file_extension = filename.rsplit('.', 1)[1].lower()
                else:
                    file_extension = 'jpg'  # Por defecto
                
                # Subir a Google Drive
                drive_result = upload_identification_image(content, user.id, file_extension)
                
                if drive_result.get('success'):
                    # Actualizar base de datos
                    user.foto_identificacion_drive_id = drive_result.get('file_id')
                    # Marcar como migrado pero mantener referencia local
                    user.foto_identificacion_path = f"drive://{drive_result.get('file_id')}"
                    db.commit()
                    
                    print(f"  ✅ Migrado exitosamente - Drive ID: {drive_result.get('file_id')}")
                    migrated_count += 1
                    
                    # Opcional: eliminar archivo local después de migrar
                    # os.remove(original_path)  # Descomenta si quieres eliminar archivos locales
                    
                else:
                    print(f"  ❌ Error al subir a Drive: {drive_result.get('error')}")
                    error_count += 1
                    
            except Exception as e:
                print(f"  ❌ Error procesando archivo: {str(e)}")
                error_count += 1
                continue
        
        print(f"\n📊 Resumen de migración:")
        print(f"  ✅ Archivos migrados exitosamente: {migrated_count}")
        print(f"  ❌ Errores: {error_count}")
        print(f"  📁 Total procesado: {migrated_count + error_count}")
        
        return migrated_count, error_count
        
    except Exception as e:
        print(f"❌ Error durante la migración: {e}")
        return 0, 1
    finally:
        db.close()

def verify_migration():
    """Verificar el estado de la migración"""
    
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = SessionLocal()
    
    try:
        total_users = db.query(User).count()
        users_with_drive = db.query(User).filter(User.foto_identificacion_drive_id.isnot(None)).count()
        users_with_local = db.query(User).filter(
            User.foto_identificacion_path.isnot(None),
            ~User.foto_identificacion_path.startswith('drive://')
        ).count()
        users_without_image = db.query(User).filter(
            User.foto_identificacion_path.is_(None),
            User.foto_identificacion_drive_id.is_(None)
        ).count()
        
        print(f"📊 Estado actual de imágenes:")
        print(f"  👥 Total usuarios: {total_users}")
        print(f"  ☁️  Con imágenes en Google Drive: {users_with_drive}")
        print(f"  💾 Con imágenes locales: {users_with_local}")
        print(f"  ❌ Sin imágenes: {users_without_image}")
        
        if users_with_local > 0:
            print(f"\n⚠️  Hay {users_with_local} usuarios con archivos locales pendientes de migrar")
        else:
            print(f"\n✅ Todos los archivos están migrados a Google Drive")
            
    except Exception as e:
        print(f"❌ Error verificando migración: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'verify':
        print("Verificando estado de la migración...")
        verify_migration()
    else:
        print("Iniciando migración de archivos locales a Google Drive...")
        print("⚠️  Asegúrate de haber configurado las credenciales de Google Drive primero")
        
        response = input("¿Continuar? (s/N): ").lower()
        if response == 's' or response == 'sí':
            migrated, errors = migrate_local_files_to_drive()
            if errors == 0 and migrated > 0:
                print("\n🎉 ¡Migración completada exitosamente!")
            elif migrated > 0:
                print(f"\n⚠️  Migración parcialmente completada. Revisar {errors} errores.")
            else:
                print("\n❌ No se pudo migrar ningún archivo.")
        else:
            print("Migración cancelada.")
        
        print("\nPara verificar el estado, ejecuta: python utils/migrate_to_drive.py verify")