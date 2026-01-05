#!/usr/bin/env python3
"""
Script de prueba para el endpoint de cambio de contraseña por administrador.

Este script demuestra cómo usar el nuevo endpoint POST /admin/users/{user_id}/change-password
"""

import requests
import json

# Configuración
BASE_URL = "http://localhost:8000"  # Ajusta según tu configuración
ADMIN_EMAIL = "admin@example.com"  # Email del admin
ADMIN_PASSWORD = "admin123"  # Contraseña del admin
TARGET_USER_ID = 2  # ID del usuario al que se le cambiará la contraseña
NEW_PASSWORD = "NuevaContraseña123!"  # Nueva contraseña para el usuario

def main():
    """Ejecuta el test del endpoint de cambio de contraseña."""
    
    print("=" * 80)
    print("🧪 PRUEBA: Cambio de contraseña por administrador")
    print("=" * 80)
    print()
    
    # Paso 1: Login como administrador
    print("Paso 1: Login como administrador...")
    login_data = {
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    }
    
    try:
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
        
        if response.status_code != 200:
            print(f"❌ Error al hacer login: {response.status_code}")
            print(f"   Respuesta: {response.text}")
            return 1
        
        tokens = response.json()
        access_token = tokens.get("access_token")
        print(f"✅ Login exitoso")
        print(f"   Token obtenido: {access_token[:20]}...")
        print()
        
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return 1
    
    # Paso 2: Cambiar contraseña del usuario
    print(f"Paso 2: Cambiar contraseña del usuario {TARGET_USER_ID}...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    change_password_data = {
        "new_password": NEW_PASSWORD
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/admin/users/{TARGET_USER_ID}/change-password",
            json=change_password_data,
            headers=headers
        )
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Contraseña cambiada exitosamente")
            print(f"   Mensaje: {result.get('message')}")
            print(f"   Usuario: {result.get('user_email')}")
            print(f"   Cambiado por: {result.get('changed_by')}")
            print(f"   Fecha: {result.get('changed_at')}")
            print()
            
        elif response.status_code == 403:
            print(f"❌ Acceso prohibido")
            print(f"   Detalles: {response.json().get('detail')}")
            print()
            
        elif response.status_code == 404:
            print(f"❌ Usuario no encontrado")
            print(f"   Detalles: {response.json().get('detail')}")
            print()
            
        elif response.status_code == 400:
            print(f"❌ Contraseña no válida")
            print(f"   Detalles: {response.json().get('detail')}")
            print()
            
        else:
            print(f"❌ Error inesperado")
            print(f"   Respuesta: {response.text}")
            print()
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return 1
    
    # Paso 3: Verificar que la nueva contraseña funciona (opcional)
    print(f"Paso 3: Verificar que la nueva contraseña funciona...")
    print(f"   (Puedes probar manualmente con el usuario {TARGET_USER_ID})")
    print()
    
    print("=" * 80)
    print("✅ Prueba completada")
    print("=" * 80)
    print()
    print("📝 NOTAS:")
    print("   - Solo administradores pueden cambiar contraseñas")
    print("   - No se puede cambiar la contraseña de otro administrador")
    print("   - La contraseña debe cumplir con los requisitos de seguridad")
    print()
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
