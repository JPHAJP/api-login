#!/usr/bin/env python3
"""
Test de Validación de Contraseñas
==================================

Script para probar el sistema de validación de contraseñas.
Prueba diferentes casos: débiles, fuertes, comunes, etc.
"""

import sys
from colorama import init, Fore, Style
from utils.password_validator import validate_password, PasswordValidator

# Inicializar colorama
init(autoreset=True)

# Casos de prueba
TEST_CASES = [
    # (password, descripción, debería_ser_válida)
    ("123456", "Contraseña muy común (solo números)", False),
    ("password", "Contraseña muy común (palabra)", False),
    ("Password", "Solo mayúscula y minúsculas", False),
    ("Password1", "Falta carácter especial", False),
    ("password1!", "Falta mayúscula", False),
    ("PASSWORD1!", "Falta minúscula", False),
    ("Pass1!", "Muy corta (6 caracteres)", False),
    ("Password1!", "Contiene palabra común 'password'", False),
    ("MiPassword123!", "Contiene palabra común 'password123'", False),
    ("C0ntr@señ@Segur@2024", "Contraseña muy fuerte", True),
    ("Admin123!", "Contiene palabra común 'admin'", False),
    ("Qwerty123!", "Contiene palabra común 'qwerty'", False),
    ("MyS3cur3P@ssw0rd!", "Contraseña fuerte con diversidad", True),
    ("aB3$x", "Muy corta pero con todos los tipos", False),
    ("LongPassword123!WithManyCharacters", "Contiene 'password123'", False),
    ("S3gur0T0t@l!", "Contraseña válida y segura", True),
    ("Pr0t3cc10n#2024", "Contraseña válida con números y símbolos", True),
    ("M!Cl@v3F0rt3*", "Contraseña válida sin palabras comunes", True),
]


def print_header():
    """Imprime el encabezado del test"""
    print("\n" + "="*80)
    print(f"{Fore.CYAN}🔐 TEST DE VALIDACIÓN DE CONTRASEÑAS{Style.RESET_ALL}")
    print("="*80 + "\n")


def print_password_result(password: str, description: str, should_be_valid: bool):
    """
    Imprime el resultado de la validación de una contraseña
    
    Args:
        password: Contraseña a probar
        description: Descripción del caso de prueba
        should_be_valid: Si la contraseña debería ser válida
    """
    result = validate_password(password)
    
    # Determinar si el test pasó
    test_passed = result.is_valid == should_be_valid
    
    # Colores según el resultado
    if test_passed:
        status_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}"
        status_text = f"{Fore.GREEN}PASS{Style.RESET_ALL}"
    else:
        status_icon = f"{Fore.RED}✗{Style.RESET_ALL}"
        status_text = f"{Fore.RED}FAIL{Style.RESET_ALL}"
    
    # Mostrar contraseña ofuscada
    password_display = password if len(password) <= 20 else password[:17] + "..."
    
    print(f"\n{status_icon} {status_text} | {description}")
    print(f"  Contraseña: '{password_display}'")
    print(f"  Validez: {result.is_valid} | Esperado: {should_be_valid}")
    print(f"  Fortaleza: {result.strength.upper()} ({result.score}/100)")
    
    # Mostrar barra de fortaleza
    bar_length = 30
    filled = int(bar_length * result.score / 100)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    if result.score < 25:
        bar_color = Fore.RED
    elif result.score < 50:
        bar_color = Fore.YELLOW
    elif result.score < 75:
        bar_color = Fore.BLUE
    else:
        bar_color = Fore.GREEN
    
    print(f"  {bar_color}{bar}{Style.RESET_ALL} {result.score}%")
    
    # Mostrar errores si los hay
    if result.errors:
        print(f"  {Fore.YELLOW}Errores:{Style.RESET_ALL}")
        for error in result.errors:
            print(f"    • {error}")
    
    # Mostrar sugerencias si las hay
    if result.suggestions:
        print(f"  {Fore.CYAN}Sugerencias:{Style.RESET_ALL}")
        for suggestion in result.suggestions:
            print(f"    • {suggestion}")
    
    return test_passed


def run_tests():
    """Ejecuta todos los tests"""
    print_header()
    
    passed = 0
    failed = 0
    
    for password, description, should_be_valid in TEST_CASES:
        test_passed = print_password_result(password, description, should_be_valid)
        if test_passed:
            passed += 1
        else:
            failed += 1
    
    # Resumen final
    print("\n" + "="*80)
    print(f"\n{Fore.CYAN}📊 RESUMEN DE TESTS{Style.RESET_ALL}")
    print("-" * 80)
    print(f"Total de tests: {passed + failed}")
    print(f"{Fore.GREEN}✓ Tests pasados: {passed}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Tests fallados: {failed}{Style.RESET_ALL}")
    
    if failed == 0:
        print(f"\n{Fore.GREEN}🎉 ¡Todos los tests pasaron correctamente!{Style.RESET_ALL}\n")
        return 0
    else:
        print(f"\n{Fore.RED}❌ Algunos tests fallaron. Revisa la implementación.{Style.RESET_ALL}\n")
        return 1


def test_interactive():
    """Modo interactivo para probar contraseñas"""
    print("\n" + "="*80)
    print(f"{Fore.CYAN}🔐 MODO INTERACTIVO - VALIDADOR DE CONTRASEÑAS{Style.RESET_ALL}")
    print("="*80)
    print(f"\n{Fore.YELLOW}Escribe 'salir' para terminar{Style.RESET_ALL}\n")
    
    while True:
        try:
            password = input(f"{Fore.CYAN}Ingresa una contraseña para validar:{Style.RESET_ALL} ")
            
            if password.lower() in ['salir', 'exit', 'quit', 'q']:
                print(f"\n{Fore.GREEN}¡Hasta luego!{Style.RESET_ALL}\n")
                break
            
            if not password:
                print(f"{Fore.RED}❌ Por favor ingresa una contraseña{Style.RESET_ALL}\n")
                continue
            
            print_password_result(password, "Contraseña ingresada", True)
            print()
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.GREEN}¡Hasta luego!{Style.RESET_ALL}\n")
            break
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error: {e}{Style.RESET_ALL}\n")


def main():
    """Función principal"""
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        test_interactive()
        return 0
    else:
        return run_tests()


if __name__ == "__main__":
    sys.exit(main())
