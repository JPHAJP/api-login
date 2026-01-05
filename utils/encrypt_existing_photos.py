#!/usr/bin/env python3
"""
Script de migración para encriptar las imágenes existentes en data/identificaciones.

Este script:
1. Lee todas las imágenes existentes en la carpeta data/identificaciones
2. Verifica si ya están encriptadas (intentando desencriptarlas)
3. Si no están encriptadas, las encripta usando la clave DATABASE_ENCRYPTION_KEY
4. Crea un backup de las imágenes originales antes de encriptarlas

IMPORTANTE: Ejecuta este script ANTES de poner en producción el nuevo código de encriptación.

Uso:
    python encrypt_existing_photos.py [--dry-run] [--backup-dir=ruta]

Opciones:
    --dry-run       Muestra qué archivos se encriptarían sin hacerlo realmente
    --backup-dir    Directorio donde guardar el backup (por defecto: data/identificaciones_backup)
"""

import os
import sys
import shutil
import argparse
from pathlib import Path
from datetime import datetime

# Agregar el directorio raíz al path para poder importar los módulos
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.file_encryption import encrypt_file_content, decrypt_file_content, get_encryption_key
from config import UPLOAD_FOLDER


def is_file_encrypted(file_path: str) -> bool:
    """
    Verifica si un archivo está encriptado intentando desencriptarlo.
    
    Args:
        file_path: Ruta del archivo a verificar
        
    Returns:
        bool: True si el archivo está encriptado, False en caso contrario
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Intentar desencriptar
        decrypt_file_content(content)
        return True
    except Exception:
        # Si falla la desencriptación, el archivo no está encriptado
        return False


def encrypt_photo(file_path: str, backup_dir: str = None, dry_run: bool = False) -> bool:
    """
    Encripta una fotografía.
    
    Args:
        file_path: Ruta del archivo a encriptar
        backup_dir: Directorio donde guardar el backup (opcional)
        dry_run: Si es True, solo simula la operación
        
    Returns:
        bool: True si la operación fue exitosa, False en caso contrario
    """
    try:
        # Verificar si ya está encriptado
        if is_file_encrypted(file_path):
            print(f"  ⏭️  Ya encriptado: {file_path}")
            return True
        
        if dry_run:
            print(f"  🔄 Se encriptaría: {file_path}")
            return True
        
        # Crear backup si se especificó
        if backup_dir:
            os.makedirs(backup_dir, exist_ok=True)
            backup_path = os.path.join(backup_dir, os.path.basename(file_path))
            shutil.copy2(file_path, backup_path)
            print(f"  💾 Backup creado: {backup_path}")
        
        # Leer el contenido original
        with open(file_path, 'rb') as f:
            original_content = f.read()
        
        # Encriptar el contenido
        encrypted_content = encrypt_file_content(original_content)
        
        # Sobrescribir el archivo con el contenido encriptado
        with open(file_path, 'wb') as f:
            f.write(encrypted_content)
        
        print(f"  ✅ Encriptado: {file_path}")
        return True
        
    except Exception as e:
        print(f"  ❌ Error al encriptar {file_path}: {str(e)}")
        return False


def main():
    """Función principal del script."""
    parser = argparse.ArgumentParser(
        description='Encripta las imágenes existentes en data/identificaciones'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Muestra qué archivos se encriptarían sin hacerlo realmente'
    )
    parser.add_argument(
        '--backup-dir',
        type=str,
        default=None,
        help='Directorio donde guardar el backup (por defecto: data/identificaciones_backup)'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='No crear backup de las imágenes originales (no recomendado)'
    )
    
    args = parser.parse_args()
    
    # Configurar directorio de backup
    backup_dir = None
    if not args.no_backup:
        if args.backup_dir:
            backup_dir = args.backup_dir
        else:
            backup_dir = f"{UPLOAD_FOLDER}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print("=" * 80)
    print("🔐 SCRIPT DE MIGRACIÓN - ENCRIPTACIÓN DE FOTOGRAFÍAS")
    print("=" * 80)
    print()
    
    # Verificar que existe la clave de encriptación
    try:
        get_encryption_key()
        print("✅ Clave de encriptación encontrada en .env")
    except ValueError as e:
        print(f"❌ Error: {e}")
        print("\nAsegúrate de que DATABASE_ENCRYPTION_KEY esté configurado en el archivo .env")
        return 1
    
    # Verificar que existe el directorio de uploads
    if not os.path.exists(UPLOAD_FOLDER):
        print(f"❌ Error: El directorio {UPLOAD_FOLDER} no existe")
        return 1
    
    print(f"📁 Directorio de fotografías: {UPLOAD_FOLDER}")
    
    if args.dry_run:
        print("🔍 Modo DRY-RUN activado (no se modificarán archivos)")
    
    if backup_dir:
        print(f"💾 Directorio de backup: {backup_dir}")
    else:
        print("⚠️  ADVERTENCIA: No se creará backup (--no-backup activado)")
    
    print()
    
    # Obtener lista de archivos de imagen
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    image_files = []
    
    for file in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, file)
        if os.path.isfile(file_path):
            ext = os.path.splitext(file)[1].lower()
            if ext in image_extensions:
                image_files.append(file_path)
    
    if not image_files:
        print("ℹ️  No se encontraron archivos de imagen para encriptar")
        return 0
    
    print(f"📊 Se encontraron {len(image_files)} archivo(s) de imagen")
    print()
    
    # Confirmar antes de proceder (si no es dry-run)
    if not args.dry_run:
        response = input("¿Deseas continuar con la encriptación? (s/N): ")
        if response.lower() not in ['s', 'si', 'sí', 'y', 'yes']:
            print("❌ Operación cancelada por el usuario")
            return 0
        print()
    
    # Procesar cada archivo
    successful = 0
    failed = 0
    already_encrypted = 0
    
    print("🔄 Procesando archivos...")
    print()
    
    for file_path in image_files:
        if is_file_encrypted(file_path):
            already_encrypted += 1
            print(f"  ⏭️  Ya encriptado: {file_path}")
        else:
            if encrypt_photo(file_path, backup_dir, args.dry_run):
                successful += 1
            else:
                failed += 1
    
    # Resumen
    print()
    print("=" * 80)
    print("📊 RESUMEN")
    print("=" * 80)
    print(f"Total de archivos procesados: {len(image_files)}")
    print(f"✅ Ya estaban encriptados: {already_encrypted}")
    print(f"✅ Encriptados exitosamente: {successful}")
    if failed > 0:
        print(f"❌ Errores: {failed}")
    
    if args.dry_run:
        print()
        print("ℹ️  Esta fue una ejecución de prueba (--dry-run)")
        print("   Ejecuta el script sin --dry-run para encriptar realmente los archivos")
    
    if backup_dir and successful > 0 and not args.dry_run:
        print()
        print(f"💾 Backup guardado en: {backup_dir}")
        print("   Puedes eliminar este directorio después de verificar que todo funciona correctamente")
    
    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
