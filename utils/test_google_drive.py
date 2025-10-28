"""
Script de prueba para verificar la configuración de Google Drive
"""

import os
import sys
from datetime import datetime

# Agregar la ruta raíz al PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.google_drive import GoogleDriveManager, upload_identification_image, download_identification_image
from config import GOOGLE_DRIVE_ENABLED

def test_google_drive_connection():
    """Probar conexión básica con Google Drive"""
    print("🔧 Probando conexión con Google Drive...")
    
    if not GOOGLE_DRIVE_ENABLED:
        print("❌ Google Drive no está habilitado en la configuración")
        return False
    
    try:
        manager = GoogleDriveManager()
        service = manager._authenticate()
        
        if service:
            print("✅ Autenticación exitosa con Google Drive")
            return True
        else:
            print("❌ Error en la autenticación")
            return False
            
    except Exception as e:
        print(f"❌ Error conectando con Google Drive: {str(e)}")
        return False

def test_file_upload():
    """Probar subida de archivo de prueba"""
    print("\n📤 Probando subida de archivo...")
    
    # Crear contenido de prueba
    test_content = f"Este es un archivo de prueba creado el {datetime.now().isoformat()}".encode('utf-8')
    test_user_id = 99999  # ID de usuario ficticio para prueba
    test_extension = "txt"
    
    try:
        result = upload_identification_image(test_content, test_user_id, test_extension)
        
        if result.get('success'):
            print(f"✅ Archivo subido exitosamente")
            print(f"   - ID: {result.get('file_id')}")
            print(f"   - URL: {result.get('drive_url')}")
            print(f"   - Tamaño: {result.get('size')} bytes")
            return result.get('file_id')
        else:
            print(f"❌ Error subiendo archivo: {result.get('error')}")
            return None
            
    except Exception as e:
        print(f"❌ Error en test de subida: {str(e)}")
        return None

def test_file_download(file_id):
    """Probar descarga de archivo"""
    print(f"\n📥 Probando descarga de archivo {file_id}...")
    
    try:
        result = download_identification_image(file_id)
        
        if result.get('success'):
            content = result.get('content')
            metadata = result.get('metadata', {})
            
            print(f"✅ Archivo descargado exitosamente")
            print(f"   - Nombre: {metadata.get('name')}")
            print(f"   - Tamaño: {len(content)} bytes")
            print(f"   - Contenido: {content.decode('utf-8')[:50]}...")
            return True
        else:
            print(f"❌ Error descargando archivo: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error en test de descarga: {str(e)}")
        return False

def test_folder_creation():
    """Probar creación de carpeta"""
    print(f"\n📁 Probando creación de carpeta...")
    
    try:
        manager = GoogleDriveManager()
        folder_name = f"Test_API_Login_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        result = manager.create_folder(folder_name)
        
        if result.get('success'):
            print(f"✅ Carpeta creada exitosamente")
            print(f"   - ID: {result.get('folder_id')}")
            print(f"   - Nombre: {folder_name}")
            return result.get('folder_id')
        else:
            print(f"❌ Error creando carpeta: {result.get('error')}")
            return None
            
    except Exception as e:
        print(f"❌ Error en test de carpeta: {str(e)}")
        return None

def cleanup_test_files(file_id, folder_id):
    """Limpiar archivos de prueba"""
    print(f"\n🧹 Limpiando archivos de prueba...")
    
    try:
        manager = GoogleDriveManager()
        
        # Eliminar archivo de prueba
        if file_id:
            result = manager.delete_file(file_id)
            if result.get('success'):
                print(f"✅ Archivo de prueba eliminado")
            else:
                print(f"⚠️  No se pudo eliminar archivo: {result.get('error')}")
        
        # Eliminar carpeta de prueba
        if folder_id:
            result = manager.delete_file(folder_id)  # Las carpetas se eliminan igual que archivos
            if result.get('success'):
                print(f"✅ Carpeta de prueba eliminada")
            else:
                print(f"⚠️  No se pudo eliminar carpeta: {result.get('error')}")
                
    except Exception as e:
        print(f"⚠️  Error limpiando archivos: {str(e)}")

def run_all_tests():
    """Ejecutar todos los tests"""
    print("🔍 Iniciando tests de Google Drive...\n")
    
    # Test 1: Conexión
    if not test_google_drive_connection():
        print("\n❌ Error en la conexión. Verifica tu configuración.")
        return False
    
    # Test 2: Subida de archivo
    file_id = test_file_upload()
    if not file_id:
        print("\n❌ Error en la subida de archivos.")
        return False
    
    # Test 3: Descarga de archivo
    if not test_file_download(file_id):
        print("\n❌ Error en la descarga de archivos.")
        return False
    
    # Test 4: Creación de carpeta
    folder_id = test_folder_creation()
    
    # Limpieza
    cleanup_test_files(file_id, folder_id)
    
    print("\n🎉 ¡Todos los tests pasaron exitosamente!")
    print("✅ Google Drive está configurado correctamente y listo para usar.")
    return True

if __name__ == "__main__":
    print("Google Drive API - Tests de Configuración")
    print("=" * 50)
    
    # Verificar si Google Drive está habilitado
    if not GOOGLE_DRIVE_ENABLED:
        print("⚠️  Google Drive no está habilitado.")
        print("   Configura GOOGLE_DRIVE_ENABLED=true en tu archivo .env")
        sys.exit(1)
    
    # Ejecutar tests
    success = run_all_tests()
    
    if success:
        print("\n🚀 Google Drive está listo para usar en tu aplicación!")
        sys.exit(0)
    else:
        print("\n❌ Hay problemas con la configuración de Google Drive.")
        print("   Revisa la documentación en docs/GOOGLE_DRIVE_SETUP.md")
        sys.exit(1)