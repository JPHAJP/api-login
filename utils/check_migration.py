#!/usr/bin/env python3
"""
Script para verificar que la migración a FastAPI esté completa
"""

import os
import sys
from pathlib import Path

def check_file_exists(filename: str, required: bool = True) -> bool:
    """Verificar si un archivo existe"""
    path = Path(filename)
    exists = path.exists()
    status = "✅" if exists else ("❌" if required else "⚠️")
    req_text = " (requerido)" if required else " (opcional)"
    print(f"{status} {filename}{req_text}")
    return exists

def check_migration():
    """Verificar que la migración esté completa"""
    print("🔍 Verificando migración Flask → FastAPI...")
    print("=" * 50)
    
    # Archivos principales
    print("\n📁 Archivos principales:")
    required_files = [
        "main.py",           # Nueva aplicación FastAPI
        "models.py",         # Modelos actualizados
        "schemas.py",        # Modelos Pydantic
        "database.py",       # Configuración BD
        "config.py",         # Configuración
        "requirements.txt",  # Dependencias
    ]
    
    all_required_exist = True
    for file in required_files:
        if not check_file_exists(file):
            all_required_exist = False
    
    # Archivos opcionales/utilitarios
    print("\n📋 Scripts y utilidades:")
    optional_files = [
        "create_admin.py",
        "start_server.py",
        ".env.example",
        "README_FastAPI_v2.md"
    ]
    
    for file in optional_files:
        check_file_exists(file, required=False)
    
    # Archivo anterior
    print("\n🗂️ Archivo anterior:")
    old_file = "app.py"
    if check_file_exists(old_file, required=False):
        print("  ℹ️  Puedes renombrar o mover app.py como respaldo")
    
    # Directorio de uploads
    print("\n📂 Directorio de archivos:")
    upload_dir = "data/identificaciones"
    if Path(upload_dir).exists():
        print(f"✅ {upload_dir}")
    else:
        print(f"⚠️ {upload_dir} (se creará automáticamente)")
    
    # Variables de entorno
    print("\n🔧 Configuración:")
    env_file = ".env"
    if Path(env_file).exists():
        print(f"✅ {env_file}")
    else:
        print(f"⚠️ {env_file} (copia .env.example y configura)")
    
    # Resumen
    print("\n" + "=" * 50)
    if all_required_exist:
        print("🎉 ¡Migración completada exitosamente!")
        print("\n📋 Próximos pasos:")
        print("1. Instalar dependencias: pip install -r requirements.txt")
        print("2. Configurar .env (copia desde .env.example)")
        print("3. Crear admin: python create_admin.py")
        print("4. Iniciar servidor: python start_server.py")
        print("   o: uvicorn main:app --reload")
        print("5. Ver docs: http://localhost:8000/docs")
    else:
        print("❌ Faltan archivos requeridos para completar la migración")
        return False
    
    return True

if __name__ == "__main__":
    success = check_migration()
    sys.exit(0 if success else 1)