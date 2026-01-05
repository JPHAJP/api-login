#!/usr/bin/env python3
"""
Script de prueba para verificar el endpoint público de QR
"""

import requests
import json
from datetime import datetime

# Configuración
API_URL = "http://localhost:8000"

def test_health():
    """Probar endpoint de health"""
    print("🔍 Probando /health...")
    try:
        response = requests.get(f"{API_URL}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Health OK - Status: {data['status']}, Version: {data['version']}")
            return True
        else:
            print(f"   ❌ Health falló - Status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Error al conectar: {e}")
        return False

def test_qr_endpoint():
    """Probar endpoint público de QR"""
    print("\n🔍 Probando /public/qr/current (público)...")
    try:
        response = requests.get(f"{API_URL}/public/qr/current")
        
        if response.status_code == 200:
            data = response.json()
            
            # Verificar estructura de respuesta
            required_fields = ['qr_image', 'code', 'expires_at']
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                print(f"   ❌ Campos faltantes: {missing_fields}")
                return False
            
            # Información del QR
            print(f"   ✅ QR obtenido exitosamente")
            print(f"   📝 Código: {data['code'][:20]}...")
            print(f"   ⏰ Expira: {data['expires_at']}")
            print(f"   🖼️  Imagen base64: {len(data['qr_image'])} caracteres")
            
            # Verificar que la imagen es válida (comienza con datos de PNG)
            if data['qr_image'].startswith('iVBOR'):
                print(f"   ✅ Imagen QR válida (formato PNG)")
            else:
                print(f"   ⚠️  Formato de imagen QR inesperado")
            
            return True
        else:
            print(f"   ❌ Error - Status code: {response.status_code}")
            print(f"   📄 Respuesta: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error al conectar: {e}")
        return False

def test_qr_no_auth_required():
    """Verificar que no requiere autenticación"""
    print("\n🔍 Verificando que NO requiere autenticación...")
    try:
        # Intentar sin headers de autorización
        response = requests.get(f"{API_URL}/public/qr/current")
        
        if response.status_code == 200:
            print(f"   ✅ Endpoint público confirmado (no requiere auth)")
            return True
        elif response.status_code == 401 or response.status_code == 403:
            print(f"   ❌ Requiere autenticación (no es público)")
            return False
        else:
            print(f"   ⚠️  Status code inesperado: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_qr_refresh():
    """Probar que el QR se puede obtener múltiples veces"""
    print("\n🔍 Probando múltiples obtenciones del QR...")
    try:
        codes = []
        for i in range(3):
            response = requests.get(f"{API_URL}/public/qr/current")
            if response.status_code == 200:
                data = response.json()
                codes.append(data['code'])
            else:
                print(f"   ❌ Fallo en intento {i+1}")
                return False
        
        # El código debería ser el mismo (no expiró)
        if len(set(codes)) == 1:
            print(f"   ✅ QR consistente en múltiples llamadas")
            return True
        else:
            print(f"   ⚠️  Códigos diferentes obtenidos (puede ser normal si pasaron 5 min)")
            return True
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    """Ejecutar todas las pruebas"""
    print("=" * 60)
    print("🧪 PRUEBAS DEL ENDPOINT PÚBLICO DE QR")
    print("=" * 60)
    
    results = []
    
    # Test 1: Health check
    results.append(("Health Check", test_health()))
    
    # Test 2: Endpoint QR
    results.append(("Endpoint QR", test_qr_endpoint()))
    
    # Test 3: No requiere auth
    results.append(("Público (sin auth)", test_qr_no_auth_required()))
    
    # Test 4: Múltiples obtenciones
    results.append(("Múltiples llamadas", test_qr_refresh()))
    
    # Resumen
    print("\n" + "=" * 60)
    print("📊 RESUMEN DE PRUEBAS")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print("\n" + "=" * 60)
    print(f"Resultado: {passed}/{total} pruebas exitosas")
    
    if passed == total:
        print("🎉 ¡Todas las pruebas pasaron exitosamente!")
    else:
        print("⚠️  Algunas pruebas fallaron. Revisa el servidor.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
