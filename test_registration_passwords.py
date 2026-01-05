#!/usr/bin/env python3
"""
Test de Registro con Validación de Contraseñas
===============================================

Script para probar el registro de usuarios con diferentes contraseñas.
"""

import requests
import json
from io import BytesIO
from colorama import init, Fore, Style
from pathlib import Path

# Inicializar colorama
init(autoreset=True)

API_URL = "http://127.0.0.1:8000"
REGISTER_URL = f"{API_URL}/auth/register"

# Crear una imagen de prueba simple (1x1 pixel PNG)
# Este es un PNG válido de 1x1 pixel transparente
FAKE_IMAGE = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
    0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
])

# Casos de prueba
TEST_CASES = [
    {
        "description": "Contraseña débil (123456)",
        "password": "123456",
        "should_fail": True
    },
    {
        "description": "Contraseña común (password)",
        "password": "password",
        "should_fail": True
    },
    {
        "description": "Contraseña sin mayúscula",
        "password": "secur3p@ss!",
        "should_fail": True
    },
    {
        "description": "Contraseña sin número",
        "password": "SecurePass!",
        "should_fail": True
    },
    {
        "description": "Contraseña sin carácter especial",
        "password": "SecurePass123",
        "should_fail": True
    },
    {
        "description": "Contraseña muy corta",
        "password": "Sec1!",
        "should_fail": True
    },
    {
        "description": "Contraseña con palabra común (Admin123!)",
        "password": "Admin123!",
        "should_fail": True
    },
    {
        "description": "✅ Contraseña válida y segura",
        "password": "S3gur0T0t@l!",
        "should_fail": False
    }
]


def print_header():
    """Imprime el encabezado"""
    print("\n" + "="*80)
    print(f"{Fore.CYAN}🔐 TEST DE REGISTRO CON VALIDACIÓN DE CONTRASEÑAS{Style.RESET_ALL}")
    print("="*80 + "\n")


def test_registration(email: str, password: str, test_number: int):
    """
    Intenta registrar un usuario con la contraseña dada
    
    Args:
        email: Email del usuario
        password: Contraseña a probar
        test_number: Número del test
        
    Returns:
        tuple: (success: bool, response_data: dict)
    """
    # Datos del formulario
    data = {
        "email": email,
        "password": password,
        "nombre_completo": f"Test User {test_number}",
        "apellidos": "Test Apellidos",
        "direccion": "Test Address 123",
        "edad": "25",
        "telefono": "+1234567890",
        "role": "voluntarios"
    }
    
    # Archivo de imagen
    files = {
        "foto_identificacion": ("test_id.png", BytesIO(FAKE_IMAGE), "image/png")
    }
    
    try:
        response = requests.post(REGISTER_URL, data=data, files=files)
        return response.status_code, response.json()
    except Exception as e:
        return None, {"error": str(e)}


def run_tests():
    """Ejecuta todos los tests de registro"""
    print_header()
    
    # Usar timestamp para evitar conflictos
    import time
    timestamp = int(time.time())
    
    passed = 0
    failed = 0
    
    for i, test_case in enumerate(TEST_CASES, 1):
        email = f"test{timestamp}_{i}@example.com"
        password = test_case["password"]
        description = test_case["description"]
        should_fail = test_case["should_fail"]
        
        print(f"\n{Fore.CYAN}Test {i}/{len(TEST_CASES)}: {description}{Style.RESET_ALL}")
        print(f"Contraseña: '{password}'")
        print(f"Email: {email}")
        
        status_code, response_data = test_registration(email, password, i)
        
        # Evaluar resultado
        if status_code is None:
            print(f"{Fore.RED}✗ ERROR: {response_data.get('error')}{Style.RESET_ALL}")
            failed += 1
            continue
        
        is_success = status_code in [200, 201]
        test_passed = (is_success and not should_fail) or (not is_success and should_fail)
        
        if test_passed:
            print(f"{Fore.GREEN}✓ PASS{Style.RESET_ALL} - Comportamiento esperado")
            passed += 1
        else:
            print(f"{Fore.RED}✗ FAIL{Style.RESET_ALL} - Comportamiento inesperado")
            failed += 1
        
        print(f"Status: {status_code}")
        
        # Mostrar detalles de la respuesta
        if "detail" in response_data:
            if isinstance(response_data["detail"], list):
                print(f"{Fore.YELLOW}Errores de validación:{Style.RESET_ALL}")
                for error in response_data["detail"]:
                    if "msg" in error:
                        print(f"  • {error['msg']}")
                        if "ctx" in error:
                            print(f"    {error['ctx']}")
            else:
                print(f"{Fore.YELLOW}Detalle: {response_data['detail']}{Style.RESET_ALL}")
        elif "message" in response_data:
            print(f"{Fore.GREEN}Mensaje: {response_data['message']}{Style.RESET_ALL}")
        
        print("-" * 80)
    
    # Resumen
    print("\n" + "="*80)
    print(f"{Fore.CYAN}📊 RESUMEN{Style.RESET_ALL}")
    print(f"Total: {passed + failed}")
    print(f"{Fore.GREEN}✓ Pasados: {passed}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Fallados: {failed}{Style.RESET_ALL}")
    
    if failed == 0:
        print(f"\n{Fore.GREEN}🎉 ¡Todos los tests pasaron!{Style.RESET_ALL}\n")
        return 0
    else:
        print(f"\n{Fore.RED}❌ Algunos tests fallaron{Style.RESET_ALL}\n")
        return 1


def main():
    """Función principal"""
    # Verificar que el servidor esté corriendo
    try:
        response = requests.get(f"{API_URL}/health")
        if response.status_code != 200:
            print(f"{Fore.RED}❌ El servidor no está respondiendo correctamente{Style.RESET_ALL}")
            return 1
    except Exception as e:
        print(f"{Fore.RED}❌ No se puede conectar al servidor en {API_URL}{Style.RESET_ALL}")
        print(f"Error: {e}")
        print(f"\n{Fore.YELLOW}Asegúrate de que el servidor esté corriendo:{Style.RESET_ALL}")
        print(f"  uvicorn main:app --reload")
        return 1
    
    return run_tests()


if __name__ == "__main__":
    import sys
    sys.exit(main())
