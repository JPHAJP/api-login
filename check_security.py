#!/usr/bin/env python3
"""
Script para verificar la seguridad de los secretos configurados
Ejecutar: python check_security.py
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

def check_secret(name, value, min_length=32):
    """Verifica que un secreto sea seguro"""
    issues = []
    
    # Lista de valores débiles conocidos
    weak_values = [
        'super-secret', 'change-this', 'qr-access-secret-key', 
        'secret', 'password', 'admin', '123456', 'test',
        'GENERA_UN_SECRETO_SEGURO_AQUI', 'GENERA_OTRO_SECRETO_SEGURO_AQUI'
    ]
    
    if not value:
        issues.append(f"❌ {name} no está configurado")
        return False, issues
    
    if any(weak in value.lower() for weak in weak_values):
        issues.append(f"❌ {name} contiene un valor predecible o débil")
        return False, issues
    
    if len(value) < min_length:
        issues.append(f"⚠️  {name} es muy corto (mínimo {min_length} caracteres, actual: {len(value)})")
        return False, issues
    
    # Verificar complejidad básica
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_special = any(not c.isalnum() for c in value)
    
    complexity_score = sum([has_upper, has_lower, has_digit, has_special])
    
    if complexity_score < 3:
        issues.append(f"⚠️  {name} debería tener más variedad de caracteres")
        issues.append(f"   (mayúsculas: {has_upper}, minúsculas: {has_lower}, números: {has_digit}, especiales: {has_special})")
    
    if issues:
        return False, issues
    
    return True, ["✅ Secreto seguro"]

def main():
    print("=" * 70)
    print("🔐 VERIFICACIÓN DE SEGURIDAD DE SECRETOS")
    print("=" * 70)
    print()
    
    all_passed = True
    
    # Verificar JWT_SECRET_KEY
    jwt_secret = os.getenv('JWT_SECRET_KEY')
    passed, messages = check_secret('JWT_SECRET_KEY', jwt_secret, min_length=32)
    all_passed = all_passed and passed
    
    print("🔑 JWT_SECRET_KEY:")
    for msg in messages:
        print(f"   {msg}")
    print()
    
    # Verificar QR_ACCESS_SECRET
    qr_secret = os.getenv('QR_ACCESS_SECRET')
    passed, messages = check_secret('QR_ACCESS_SECRET', qr_secret, min_length=32)
    all_passed = all_passed and passed
    
    print("🔑 QR_ACCESS_SECRET:")
    for msg in messages:
        print(f"   {msg}")
    print()
    
    # Verificar DATABASE_ENCRYPTION_KEY (opcional)
    db_secret = os.getenv('DATABASE_ENCRYPTION_KEY')
    if db_secret:
        passed, messages = check_secret('DATABASE_ENCRYPTION_KEY', db_secret, min_length=32)
        all_passed = all_passed and passed
        
        print("🔑 DATABASE_ENCRYPTION_KEY (opcional):")
        for msg in messages:
            print(f"   {msg}")
        print()
    else:
        print("ℹ️  DATABASE_ENCRYPTION_KEY no está configurado (opcional)")
        print()
    
    # Verificar ENVIRONMENT
    env = os.getenv('ENVIRONMENT', 'development')
    print(f"🌍 ENVIRONMENT: {env}")
    if env == 'production' and not all_passed:
        print("   ❌ CRÍTICO: Hay secretos débiles en producción!")
    print()
    
    print("=" * 70)
    
    if all_passed:
        print("✅ TODOS LOS SECRETOS SON SEGUROS")
        print()
        print("✨ Tu configuración de seguridad está lista!")
        return 0
    else:
        print("❌ ALGUNOS SECRETOS SON DÉBILES O FALTAN")
        print()
        print("📝 RECOMENDACIONES:")
        print("1. Ejecuta: python generate_secrets.py")
        print("2. Copia los secretos generados a tu archivo .env")
        print("3. Reinicia el servidor")
        print("4. Ejecuta este script nuevamente para verificar")
        return 1

if __name__ == "__main__":
    sys.exit(main())
