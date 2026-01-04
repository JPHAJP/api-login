#!/usr/bin/env python3
"""
Script para generar secretos criptográficamente seguros
Ejecutar: python generate_secrets.py
"""

import secrets
import string

def generate_secret_key(length=64):
    """Genera una clave secreta segura usando caracteres alfanuméricos y especiales"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_hex_secret(length=32):
    """Genera una clave secreta en formato hexadecimal"""
    return secrets.token_hex(length)

def generate_urlsafe_secret(length=32):
    """Genera una clave secreta URL-safe"""
    return secrets.token_urlsafe(length)

if __name__ == "__main__":
    print("=" * 70)
    print("🔐 GENERADOR DE SECRETOS CRIPTOGRÁFICAMENTE SEGUROS")
    print("=" * 70)
    print()
    print("⚠️  IMPORTANTE: Guarda estos secretos en tu archivo .env")
    print("⚠️  NO los compartas ni los incluyas en control de versiones")
    print()
    print("-" * 70)
    
    # JWT Secret Key
    jwt_secret = generate_secret_key(64)
    print("🔑 JWT_SECRET_KEY (para tokens de autenticación):")
    print(f"   {jwt_secret}")
    print()
    
    # QR Access Secret
    qr_secret = generate_hex_secret(32)
    print("🔑 QR_ACCESS_SECRET (para códigos QR):")
    print(f"   {qr_secret}")
    print()
    
    # Database Encryption Key (para el futuro)
    db_secret = generate_hex_secret(32)
    print("🔑 DATABASE_ENCRYPTION_KEY (opcional - para cifrado de datos):")
    print(f"   {db_secret}")
    print()
    
    print("-" * 70)
    print()
    print("📋 COPIA Y PEGA EN TU ARCHIVO .env:")
    print("=" * 70)
    print()
    print(f"JWT_SECRET_KEY={jwt_secret}")
    print(f"QR_ACCESS_SECRET={qr_secret}")
    print(f"DATABASE_ENCRYPTION_KEY={db_secret}")
    print()
    print("=" * 70)
    print()
    print("✅ PRÓXIMOS PASOS:")
    print("1. Copia las líneas de arriba")
    print("2. Pega en tu archivo .env (reemplaza los valores existentes)")
    print("3. Guarda el archivo .env")
    print("4. Reinicia tu servidor")
    print()
    print("⚠️  RECORDATORIO:")
    print("- Mantén estos secretos en tu .env")
    print("- Asegúrate de que .env esté en .gitignore")
    print("- Usa secretos diferentes para desarrollo y producción")
    print("- Nunca expongas estos secretos públicamente")
    print()
