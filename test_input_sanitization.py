#!/usr/bin/env python3
"""
Test de Sanitización de Inputs
===============================

Script para probar la sanitización contra ataques comunes:
- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- HTML Injection
"""

import sys
import re
from colorama import init, Fore, Style
from utils.input_sanitizer import (
    sanitize_string,
    sanitize_html,
    sanitize_name,
    sanitize_address,
    sanitize_filename,
    InputSanitizer
)

# Inicializar colorama
init(autoreset=True)

# Payloads maliciosos para testing
MALICIOUS_PAYLOADS = {
    "SQL Injection": [
        ("' OR '1'='1", "SQL injection básico"),
        ("admin'--", "SQL comentario"),
        ("'; DROP TABLE users; --", "SQL DROP TABLE"),
        ("' UNION SELECT * FROM users--", "SQL UNION"),
        ("1' AND '1'='1", "SQL AND"),
    ],
    "XSS": [
        ("<script>alert('XSS')</script>", "XSS básico con script"),
        ("<img src=x onerror=alert('XSS')>", "XSS con img tag"),
        ("<iframe src='javascript:alert(1)'>", "XSS con iframe"),
        ("javascript:alert('XSS')", "JavaScript URL"),
        ("<svg onload=alert('XSS')>", "XSS con SVG"),
        ("<<SCRIPT>alert('XSS');//<</SCRIPT>", "XSS ofuscado"),
    ],
    "Path Traversal": [
        ("../../etc/passwd", "Path traversal básico"),
        ("..\\..\\windows\\system32", "Path traversal Windows"),
        ("%2e%2e%2fetc%2fpasswd", "Path traversal URL encoded"),
        ("....//....//etc/passwd", "Path traversal con puntos extra"),
    ],
    "HTML Injection": [
        ("<h1>Injected</h1>", "HTML heading"),
        ("<a href='#'>Click</a>", "HTML link"),
        ("<style>body{display:none}</style>", "CSS injection"),
    ],
    "Control Characters": [
        ("Name\x00Null", "Null byte"),
        ("Name\nNewline", "Newline character"),
        ("Name\rReturn", "Carriage return"),
        ("Name\tTab", "Tab character"),
    ],
}

# Casos de nombres válidos (deberían pasar)
VALID_NAMES = [
    ("Juan Pérez", "Nombre español con tilde"),
    ("María José García", "Nombre compuesto"),
    ("O'Connor", "Nombre con apóstrofe"),
    ("Jean-Claude", "Nombre con guión"),
    ("José Ñoño", "Nombre con ñ"),
    ("Müller", "Nombre con diéresis"),
]

# Casos de direcciones válidas
VALID_ADDRESSES = [
    ("Calle Principal #123", "Dirección con número"),
    ("Av. Libertador, 4to piso", "Dirección con piso"),
    ("Carrera 7 #45-30", "Dirección colombiana"),
    ("Rúa dos Bancos, 25°", "Dirección con grado"),
]


def print_header():
    """Imprime el encabezado del test"""
    print("\n" + "="*80)
    print(f"{Fore.CYAN}🛡️ TEST DE SANITIZACIÓN DE INPUTS{Style.RESET_ALL}")
    print("="*80 + "\n")


def test_malicious_payloads():
    """Prueba payloads maliciosos"""
    print(f"\n{Fore.YELLOW}═══ TESTING PAYLOADS MALICIOSOS ═══{Style.RESET_ALL}\n")
    
    total_tests = 0
    passed_tests = 0
    
    for category, payloads in MALICIOUS_PAYLOADS.items():
        print(f"\n{Fore.CYAN}📌 {category}{Style.RESET_ALL}")
        print("-" * 80)
        
        for payload, description in payloads:
            total_tests += 1
            
            # Usar sanitize_filename para Path Traversal, sanitize_string para el resto
            if category == "Path Traversal":
                sanitized = sanitize_filename(payload)
            else:
                sanitized = sanitize_string(payload)
            
            # Verificar que no contenga el payload original
            is_safe = payload.lower() not in sanitized.lower()
            
            # Verificar con is_safe_string
            safety_check = InputSanitizer.is_safe_string(sanitized)
            
            if is_safe and safety_check:
                status = f"{Fore.GREEN}✓ BLOCKED{Style.RESET_ALL}"
                passed_tests += 1
            else:
                status = f"{Fore.RED}✗ FAILED{Style.RESET_ALL}"
            
            print(f"{status} | {description}")
            print(f"  Input:     '{payload[:50]}{'...' if len(payload) > 50 else ''}'")
            print(f"  Sanitized: '{sanitized[:50]}{'...' if len(sanitized) > 50 else ''}'")
    
    return passed_tests, total_tests


def test_valid_inputs():
    """Prueba inputs válidos que deberían pasar"""
    print(f"\n\n{Fore.YELLOW}═══ TESTING INPUTS VÁLIDOS ═══{Style.RESET_ALL}\n")
    
    total_tests = 0
    passed_tests = 0
    
    # Test nombres
    print(f"\n{Fore.CYAN}📌 Nombres Válidos{Style.RESET_ALL}")
    print("-" * 80)
    
    for name, description in VALID_NAMES:
        total_tests += 1
        sanitized = sanitize_name(name)
        
        # El nombre debería mantenerse similar
        is_valid = len(sanitized) >= 2 and sanitized.replace(" ", "").replace("-", "").replace("'", "").isalpha()
        
        if is_valid:
            status = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}"
            passed_tests += 1
        else:
            status = f"{Fore.RED}✗ FAIL{Style.RESET_ALL}"
        
        print(f"{status} | {description}")
        print(f"  Input:     '{name}'")
        print(f"  Sanitized: '{sanitized}'")
    
    # Test direcciones
    print(f"\n{Fore.CYAN}📌 Direcciones Válidas{Style.RESET_ALL}")
    print("-" * 80)
    
    for address, description in VALID_ADDRESSES:
        total_tests += 1
        sanitized = sanitize_address(address)
        
        # La dirección debería mantenerse con longitud razonable
        is_valid = len(sanitized) >= 5
        
        if is_valid:
            status = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}"
            passed_tests += 1
        else:
            status = f"{Fore.RED}✗ FAIL{Style.RESET_ALL}"
        
        print(f"{status} | {description}")
        print(f"  Input:     '{address}'")
        print(f"  Sanitized: '{sanitized}'")
    
    return passed_tests, total_tests


def test_html_sanitization():
    """Prueba sanitización HTML específica"""
    print(f"\n\n{Fore.YELLOW}═══ TESTING SANITIZACIÓN HTML ═══{Style.RESET_ALL}\n")
    
    test_cases = [
        "<script>alert('XSS')</script>Normal Text",
        "Hello<b>World</b>",
        "<img src=x onerror=alert(1)>",
        "Text with <style>body{display:none}</style> hidden",
    ]
    
    passed = 0
    total = len(test_cases)
    
    for test in test_cases:
        sanitized = sanitize_html(test)
        
        # No debería contener tags HTML
        has_tags = bool(re.search(r'<[^>]+>', sanitized))
        
        if not has_tags:
            status = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}"
            passed += 1
        else:
            status = f"{Fore.RED}✗ FAIL{Style.RESET_ALL}"
        
        print(f"{status}")
        print(f"  Input:     '{test[:60]}{'...' if len(test) > 60 else ''}'")
        print(f"  Sanitized: '{sanitized[:60]}{'...' if len(sanitized) > 60 else ''}'")
    
    return passed, total


def test_filename_sanitization():
    """Prueba sanitización de nombres de archivo"""
    print(f"\n\n{Fore.YELLOW}═══ TESTING SANITIZACIÓN DE FILENAMES ═══{Style.RESET_ALL}\n")
    
    test_cases = [
        ("../../etc/passwd", "Path traversal"),
        ("file<script>.txt", "XSS en filename"),
        ("normal file.txt", "Filename normal"),
        ("file|with|pipes.txt", "Caracteres peligrosos"),
    ]
    
    passed = 0
    total = len(test_cases)
    
    for filename, description in test_cases:
        sanitized = sanitize_filename(filename)
        
        # No debería contener path traversal ni caracteres peligrosos
        is_safe = '..' not in sanitized and not any(c in sanitized for c in '<>:"|?*')
        
        if is_safe:
            status = f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}"
            passed += 1
        else:
            status = f"{Fore.RED}✗ FAIL{Style.RESET_ALL}"
        
        print(f"{status} | {description}")
        print(f"  Input:     '{filename}'")
        print(f"  Sanitized: '{sanitized}'")
    
    return passed, total


def run_tests():
    """Ejecuta todos los tests"""
    print_header()
    
    # Ejecutar tests
    passed_mal, total_mal = test_malicious_payloads()
    passed_val, total_val = test_valid_inputs()
    passed_html, total_html = test_html_sanitization()
    passed_file, total_file = test_filename_sanitization()
    
    # Resumen
    total_passed = passed_mal + passed_val + passed_html + passed_file
    total_tests = total_mal + total_val + total_html + total_file
    
    print("\n" + "="*80)
    print(f"{Fore.CYAN}📊 RESUMEN{Style.RESET_ALL}")
    print("-" * 80)
    print(f"Total de tests: {total_tests}")
    print(f"{Fore.GREEN}✓ Pasados: {total_passed}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Fallados: {total_tests - total_passed}{Style.RESET_ALL}")
    
    score = (total_passed / total_tests) * 100 if total_tests > 0 else 0
    print(f"\n{Fore.CYAN}Puntuación: {score:.1f}%{Style.RESET_ALL}")
    
    if score >= 90:
        print(f"{Fore.GREEN}🎉 ¡Excelente! La sanitización está funcionando correctamente{Style.RESET_ALL}")
    elif score >= 70:
        print(f"{Fore.YELLOW}⚠️  Bueno, pero hay margen de mejora{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ Se necesitan mejoras importantes{Style.RESET_ALL}")
    
    print()
    
    return 0 if total_passed == total_tests else 1


def main():
    """Función principal"""
    return run_tests()


if __name__ == "__main__":
    sys.exit(main())
