#!/usr/bin/env python3
"""
Test de Security Headers
=========================

Script para verificar que todos los headers de seguridad estén presentes
y correctamente configurados en las respuestas de la API.
"""

import requests
import sys
from colorama import init, Fore, Style
from typing import Dict, List, Tuple

# Inicializar colorama
init(autoreset=True)

API_URL = "http://127.0.0.1:8000"

# Headers de seguridad esperados
REQUIRED_HEADERS = {
    "X-Frame-Options": {
        "expected": "DENY",
        "description": "Previene clickjacking - No permite iframes",
        "severity": "HIGH"
    },
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "description": "Previene MIME sniffing - Respeta Content-Type",
        "severity": "HIGH"
    },
    "X-XSS-Protection": {
        "expected": "1; mode=block",
        "description": "Protección XSS del navegador",
        "severity": "MEDIUM"
    },
    "Content-Security-Policy": {
        "expected": "default-src 'self'",  # Al menos debe contener esto
        "description": "Política de seguridad de contenido - Previene XSS",
        "severity": "HIGH",
        "check_contains": True
    },
    "Referrer-Policy": {
        "expected": "strict-origin-when-cross-origin",
        "description": "Control de información del referrer",
        "severity": "MEDIUM"
    },
    "Permissions-Policy": {
        "expected": "geolocation=(), microphone=(), camera=()",
        "description": "Control de APIs del navegador",
        "severity": "MEDIUM",
        "check_contains": True
    },
    "Cache-Control": {
        "expected": None,  # Depende del endpoint
        "description": "Control de caché (endpoints sensibles)",
        "severity": "MEDIUM",
        "optional": True
    }
}

# Headers que solo deben estar en producción
PRODUCTION_ONLY_HEADERS = {
    "Strict-Transport-Security": {
        "expected": "max-age=31536000",
        "description": "Fuerza HTTPS (solo en producción)",
        "severity": "CRITICAL",
        "check_contains": True
    }
}


def print_header():
    """Imprime el encabezado del test"""
    print("\n" + "="*80)
    print(f"{Fore.CYAN}🔒 TEST DE SECURITY HEADERS{Style.RESET_ALL}")
    print("="*80 + "\n")


def check_header(
    header_name: str,
    header_value: str,
    expected_value: str,
    check_contains: bool = False
) -> Tuple[bool, str]:
    """
    Verifica si un header tiene el valor correcto
    
    Args:
        header_name: Nombre del header
        header_value: Valor actual del header
        expected_value: Valor esperado
        check_contains: Si True, verifica que contenga el valor en lugar de igualdad exacta
        
    Returns:
        Tuple (is_valid, message)
    """
    if not header_value:
        return False, "Header no presente"
    
    if check_contains:
        if expected_value.lower() in header_value.lower():
            return True, f"Presente y contiene '{expected_value}'"
        else:
            return False, f"No contiene '{expected_value}'"
    else:
        if header_value.lower() == expected_value.lower():
            return True, "Valor correcto"
        else:
            return False, f"Valor incorrecto: '{header_value}'"


def test_endpoint_headers(url: str, endpoint_name: str) -> Dict:
    """
    Prueba los headers de seguridad en un endpoint específico
    
    Args:
        url: URL completa del endpoint
        endpoint_name: Nombre descriptivo del endpoint
        
    Returns:
        Dict con resultados del test
    """
    print(f"\n{Fore.CYAN}Testing: {endpoint_name}{Style.RESET_ALL}")
    print(f"URL: {url}")
    print("-" * 80)
    
    try:
        response = requests.get(url, allow_redirects=False)
        headers = response.headers
        
        results = {
            "endpoint": endpoint_name,
            "url": url,
            "status_code": response.status_code,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "missing": 0,
            "headers_checked": []
        }
        
        # Verificar headers requeridos
        for header_name, config in REQUIRED_HEADERS.items():
            results["total"] += 1
            
            header_value = headers.get(header_name)
            expected = config["expected"]
            is_optional = config.get("optional", False)
            check_contains = config.get("check_contains", False)
            
            if header_value:
                if expected is None:
                    # Header sin valor esperado específico
                    results["passed"] += 1
                    status = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}"
                    message = f"Presente: '{header_value}'"
                else:
                    is_valid, message = check_header(
                        header_name, header_value, expected, check_contains
                    )
                    
                    if is_valid:
                        results["passed"] += 1
                        status = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}"
                    else:
                        results["failed"] += 1
                        status = f"{Fore.RED}✗ FAIL{Style.RESET_ALL}"
            else:
                if is_optional:
                    status = f"{Fore.YELLOW}⚠ SKIP{Style.RESET_ALL}"
                    message = "Header opcional no presente"
                    results["total"] -= 1  # No cuenta para el total
                else:
                    results["missing"] += 1
                    status = f"{Fore.RED}✗ MISS{Style.RESET_ALL}"
                    message = "Header no presente"
            
            severity_color = {
                "CRITICAL": Fore.RED,
                "HIGH": Fore.YELLOW,
                "MEDIUM": Fore.BLUE,
                "LOW": Fore.WHITE
            }.get(config["severity"], Fore.WHITE)
            
            print(f"{status} [{severity_color}{config['severity']}{Style.RESET_ALL}] "
                  f"{header_name}")
            print(f"     {config['description']}")
            print(f"     {message}")
            
            results["headers_checked"].append({
                "name": header_name,
                "value": header_value,
                "expected": expected,
                "status": "pass" if header_value and (expected is None or is_valid) else "fail"
            })
        
        return results
        
    except Exception as e:
        print(f"{Fore.RED}✗ ERROR: {e}{Style.RESET_ALL}")
        return {
            "endpoint": endpoint_name,
            "url": url,
            "error": str(e),
            "total": 0,
            "passed": 0,
            "failed": 0,
            "missing": 0
        }


def run_tests():
    """Ejecuta todos los tests de security headers"""
    print_header()
    
    # Verificar que el servidor esté corriendo
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"{Fore.RED}❌ El servidor no está respondiendo correctamente{Style.RESET_ALL}")
            return 1
    except Exception as e:
        print(f"{Fore.RED}❌ No se puede conectar al servidor en {API_URL}{Style.RESET_ALL}")
        print(f"Error: {e}")
        print(f"\n{Fore.YELLOW}Asegúrate de que el servidor esté corriendo:{Style.RESET_ALL}")
        print(f"  uvicorn main:app --reload")
        return 1
    
    # Endpoints a probar
    endpoints = [
        (f"{API_URL}/health", "Health Check (Público)"),
        (f"{API_URL}/public/qr/current", "QR Público"),
        (f"{API_URL}/docs", "OpenAPI Docs"),
    ]
    
    all_results = []
    
    for url, name in endpoints:
        result = test_endpoint_headers(url, name)
        all_results.append(result)
    
    # Resumen general
    print("\n" + "="*80)
    print(f"{Fore.CYAN}📊 RESUMEN GENERAL{Style.RESET_ALL}")
    print("="*80)
    
    total_passed = sum(r.get("passed", 0) for r in all_results)
    total_failed = sum(r.get("failed", 0) for r in all_results)
    total_missing = sum(r.get("missing", 0) for r in all_results)
    total_checks = sum(r.get("total", 0) for r in all_results)
    
    print(f"\nEndpoints probados: {len(endpoints)}")
    print(f"Headers verificados: {total_checks}")
    print(f"{Fore.GREEN}✓ Pasados: {total_passed}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Fallados: {total_failed}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Faltantes: {total_missing}{Style.RESET_ALL}")
    
    if total_checks > 0:
        score = (total_passed / total_checks) * 100
        print(f"\n{Fore.CYAN}Puntuación de Seguridad: {score:.1f}%{Style.RESET_ALL}")
        
        if score >= 90:
            print(f"{Fore.GREEN}🎉 ¡Excelente! Los headers de seguridad están correctamente configurados{Style.RESET_ALL}")
        elif score >= 70:
            print(f"{Fore.YELLOW}⚠️  Bueno, pero hay margen de mejora{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Se necesitan mejoras importantes en los headers de seguridad{Style.RESET_ALL}")
    
    print()
    
    # Verificar headers de producción
    print(f"\n{Fore.CYAN}📝 NOTA: Headers de Producción{Style.RESET_ALL}")
    print("-" * 80)
    print(f"Los siguientes headers solo deben estar presentes en producción:")
    for header_name, config in PRODUCTION_ONLY_HEADERS.items():
        print(f"  • {header_name}: {config['description']}")
    print(f"\nPara habilitar modo producción, configura:")
    print(f"  ENVIRONMENT=production en .env")
    print()
    
    return 0 if total_failed == 0 and total_missing == 0 else 1


def main():
    """Función principal"""
    return run_tests()


if __name__ == "__main__":
    sys.exit(main())
