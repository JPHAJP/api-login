#!/usr/bin/env python3
"""
Script de prueba para verificar el sistema de encriptación de fotografías.

Este script realiza pruebas básicas del módulo de encriptación para asegurar
que funciona correctamente antes de usarlo en producción.
"""

import os
import sys
import tempfile
from pathlib import Path

# Agregar el directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Cargar variables de entorno ANTES de importar los módulos
from dotenv import load_dotenv
load_dotenv()

from utils.file_encryption import (
    encrypt_file_content, decrypt_file_content, 
    encrypt_file, decrypt_file, get_encryption_key
)


def test_encryption_key():
    """Prueba 1: Verificar que la clave de encriptación está configurada"""
    print("Prueba 1: Verificar clave de encriptación...")
    try:
        key = get_encryption_key()
        assert key is not None
        assert len(key) > 0
        print("  ✅ Clave de encriptación encontrada y válida")
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def test_content_encryption():
    """Prueba 2: Encriptar y desencriptar contenido en memoria"""
    print("\nPrueba 2: Encriptación/Desencriptación de contenido en memoria...")
    try:
        # Datos de prueba
        original_data = "Este es un contenido de prueba para encriptar! 🔐".encode('utf-8')
        
        # Encriptar
        encrypted_data = encrypt_file_content(original_data)
        assert encrypted_data != original_data
        print("  ✅ Contenido encriptado correctamente")
        
        # Desencriptar
        decrypted_data = decrypt_file_content(encrypted_data)
        assert decrypted_data == original_data
        print("  ✅ Contenido desencriptado correctamente")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def test_file_encryption():
    """Prueba 3: Encriptar y desencriptar archivo completo"""
    print("\nPrueba 3: Encriptación/Desencriptación de archivo...")
    
    # Crear archivo temporal de prueba
    test_content = "Contenido de archivo de prueba con datos importantes! 📄".encode('utf-8')
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as temp_file:
        temp_file.write(test_content)
        temp_path = temp_file.name
    
    try:
        # Encriptar archivo
        encrypt_file(temp_path)
        print("  ✅ Archivo encriptado correctamente")
        
        # Verificar que el contenido está encriptado
        with open(temp_path, 'rb') as f:
            encrypted_content = f.read()
        assert encrypted_content != test_content
        print("  ✅ El archivo encriptado es diferente del original")
        
        # Desencriptar
        decrypted_content = decrypt_file(temp_path)
        assert decrypted_content == test_content
        print("  ✅ Archivo desencriptado correctamente")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    finally:
        # Limpiar
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_image_simulation():
    """Prueba 4: Simular encriptación de imagen (bytes grandes)"""
    print("\nPrueba 4: Simulación con datos de imagen (5KB)...")
    try:
        # Simular una imagen pequeña (5KB de datos aleatorios)
        import random
        image_data = bytes([random.randint(0, 255) for _ in range(5 * 1024)])
        
        # Encriptar
        encrypted = encrypt_file_content(image_data)
        print(f"  ✅ Imagen simulada encriptada (tamaño: {len(encrypted)} bytes)")
        
        # Desencriptar
        decrypted = decrypt_file_content(encrypted)
        assert decrypted == image_data
        print("  ✅ Imagen simulada desencriptada correctamente")
        
        # Verificar tamaño
        overhead = len(encrypted) - len(image_data)
        overhead_percent = (overhead / len(image_data)) * 100
        print(f"  ℹ️  Overhead de encriptación: {overhead} bytes ({overhead_percent:.2f}%)")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def test_invalid_decryption():
    """Prueba 5: Intentar desencriptar datos no válidos"""
    print("\nPrueba 5: Manejo de errores con datos inválidos...")
    try:
        invalid_data = b"Esto no es un dato encriptado valido"
        
        try:
            decrypt_file_content(invalid_data)
            print("  ❌ Se esperaba un error pero no ocurrió")
            return False
        except Exception:
            print("  ✅ Error manejado correctamente al intentar desencriptar datos inválidos")
            return True
            
    except Exception as e:
        print(f"  ❌ Error inesperado: {e}")
        return False


def main():
    """Ejecuta todas las pruebas"""
    print("=" * 80)
    print("🧪 PRUEBAS DEL SISTEMA DE ENCRIPTACIÓN DE FOTOGRAFÍAS")
    print("=" * 80)
    print()
    
    tests = [
        test_encryption_key,
        test_content_encryption,
        test_file_encryption,
        test_image_simulation,
        test_invalid_decryption
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print()
    print("=" * 80)
    print("📊 RESUMEN DE PRUEBAS")
    print("=" * 80)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Total de pruebas: {total}")
    print(f"✅ Exitosas: {passed}")
    print(f"❌ Fallidas: {total - passed}")
    
    if passed == total:
        print()
        print("🎉 ¡Todas las pruebas pasaron exitosamente!")
        print("   El sistema de encriptación está listo para usar.")
        return 0
    else:
        print()
        print("⚠️  Algunas pruebas fallaron. Revisa los errores antes de continuar.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
