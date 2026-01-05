#!/usr/bin/env python3
"""
Script para probar el Rate Limiting de la API
Ejecutar: python test_rate_limit.py
"""

import requests
import time
import sys

API_URL = "http://localhost:8000"

def test_rate_limit_public(num_requests=210):
    """Prueba el rate limit en un endpoint público"""
    print("=" * 70)
    print("🧪 PRUEBA DE RATE LIMITING - ENDPOINT PÚBLICO")
    print("=" * 70)
    print(f"\nEnviando {num_requests} solicitudes al endpoint /health...")
    print("(Límite: 200/minuto en desarrollo)")
    print()
    
    success_count = 0
    rate_limited_count = 0
    
    for i in range(1, num_requests + 1):
        try:
            response = requests.get(f"{API_URL}/health", timeout=2)
            
            if response.status_code == 200:
                success_count += 1
                print(f"✅ Solicitud {i}: OK (200)")
            elif response.status_code == 429:
                rate_limited_count += 1
                print(f"🛑 Solicitud {i}: Rate Limited (429)")
                data = response.json()
                print(f"   Mensaje: {data.get('detail', 'N/A')}")
                print(f"   Retry After: {response.headers.get('Retry-After', 'N/A')} segundos")
                break  # Detener al primer rate limit
            else:
                print(f"⚠️  Solicitud {i}: Status {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"⏱️  Solicitud {i}: Timeout")
        except Exception as e:
            print(f"❌ Solicitud {i}: Error - {e}")
    
    print()
    print("-" * 70)
    print(f"📊 RESULTADOS:")
    print(f"   Exitosas: {success_count}")
    print(f"   Rate Limited: {rate_limited_count}")
    print()
    
    if rate_limited_count > 0:
        print("✅ RATE LIMITING FUNCIONANDO CORRECTAMENTE")
        print("   El servidor está bloqueando solicitudes excesivas")
    else:
        print("⚠️  No se alcanzó el límite (puede ser que el límite sea muy alto)")
    
    return rate_limited_count > 0

def test_rate_limit_login(num_requests=25):
    """Prueba el rate limit en el endpoint de login"""
    print()
    print("=" * 70)
    print("🧪 PRUEBA DE RATE LIMITING - LOGIN")
    print("=" * 70)
    print(f"\nEnviando {num_requests} solicitudes de login con credenciales incorrectas...")
    print("(Este es el escenario de ataque de fuerza bruta)")
    print("(Límite: 20/minuto en desarrollo)")
    print()
    
    success_count = 0
    rate_limited_count = 0
    
    credentials = {
        "email": "test@example.com",
        "password": "wrongpassword"
    }
    
    for i in range(1, num_requests + 1):
        try:
            response = requests.post(
                f"{API_URL}/auth/login",
                json=credentials,
                timeout=2
            )
            
            if response.status_code == 401:
                success_count += 1
                print(f"✅ Solicitud {i}: Credenciales inválidas (401) - esperado")
            elif response.status_code == 429:
                rate_limited_count += 1
                print(f"🛑 Solicitud {i}: Rate Limited (429) - ¡PROTEGIDO!")
                data = response.json()
                print(f"   Mensaje: {data.get('detail', 'N/A')}")
                print(f"   Retry After: {response.headers.get('Retry-After', 'N/A')} segundos")
                break  # Detener al primer rate limit
            else:
                print(f"⚠️  Solicitud {i}: Status {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"⏱️  Solicitud {i}: Timeout")
        except Exception as e:
            print(f"❌ Solicitud {i}: Error - {e}")
        
        time.sleep(0.1)  # Pequeña pausa entre solicitudes
    
    print()
    print("-" * 70)
    print(f"📊 RESULTADOS:")
    print(f"   Intentos procesados: {success_count}")
    print(f"   Bloqueados por Rate Limit: {rate_limited_count}")
    print()
    
    if rate_limited_count > 0:
        print("✅ PROTECCIÓN CONTRA FUERZA BRUTA ACTIVA")
        print("   El sistema está bloqueando intentos de login excesivos")
    else:
        print("⚠️  No se alcanzó el límite")
    
    return rate_limited_count > 0

def check_rate_limit_headers():
    """Verifica que los headers de rate limiting estén presentes"""
    print()
    print("=" * 70)
    print("🧪 VERIFICACIÓN DE HEADERS DE RATE LIMITING")
    print("=" * 70)
    print()
    
    try:
        response = requests.get(f"{API_URL}/health")
        
        print("Headers de Rate Limiting en la respuesta:")
        print()
        
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After'
        ]
        
        found_headers = False
        for header in rate_limit_headers:
            value = response.headers.get(header)
            if value:
                print(f"   ✅ {header}: {value}")
                found_headers = True
            else:
                print(f"   ⚠️  {header}: No presente")
        
        print()
        if found_headers:
            print("✅ Headers de rate limiting configurados correctamente")
        else:
            print("⚠️  No se encontraron headers de rate limiting")
        
        return found_headers
        
    except Exception as e:
        print(f"❌ Error al verificar headers: {e}")
        return False

def main():
    print("=" * 70)
    print("🔐 PRUEBAS DE RATE LIMITING - API Login Sistema")
    print("=" * 70)
    print()
    print("⚠️  NOTA: Asegúrate de que el servidor esté corriendo")
    print(f"   URL: {API_URL}")
    print()
    input("Presiona Enter para comenzar las pruebas...")
    print()
    
    # Verificar que el servidor esté disponible
    try:
        response = requests.get(f"{API_URL}/health", timeout=2)
        if response.status_code != 200:
            print("❌ El servidor no está respondiendo correctamente")
            sys.exit(1)
    except Exception as e:
        print(f"❌ No se puede conectar al servidor: {e}")
        print(f"   Asegúrate de que el servidor esté corriendo en {API_URL}")
        sys.exit(1)
    
    print("✅ Servidor disponible")
    print()
    
    # Ejecutar pruebas
    test1 = check_rate_limit_headers()
    test2 = test_rate_limit_public(num_requests=210)
    test3 = test_rate_limit_login(num_requests=25)
    
    # Resumen final
    print()
    print("=" * 70)
    print("📊 RESUMEN FINAL")
    print("=" * 70)
    print()
    print(f"Headers de Rate Limiting: {'✅ Configurados' if test1 else '⚠️  No encontrados'}")
    print(f"Rate Limiting Público: {'✅ Funcionando' if test2 else '⚠️  No activado'}")
    print(f"Protección Login: {'✅ Activa' if test3 else '⚠️  No activada'}")
    print()
    
    if test2 and test3:
        print("🎉 ¡RATE LIMITING COMPLETAMENTE FUNCIONAL!")
        print()
        print("Tu API está protegida contra:")
        print("   ✅ Ataques de fuerza bruta en login")
        print("   ✅ Abuso de endpoints públicos")
        print("   ✅ Solicitudes excesivas por IP")
    else:
        print("⚠️  Algunas protecciones no están funcionando correctamente")
        print("   Revisa la configuración del rate limiting")
    
    print()
    print("=" * 70)

if __name__ == "__main__":
    main()
