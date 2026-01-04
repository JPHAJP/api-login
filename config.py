import os
import sys
from dotenv import load_dotenv

load_dotenv()

# Determinar si estamos en producción
IS_PRODUCTION = os.getenv('ENVIRONMENT', 'development') == 'production'

def get_required_env(key: str, default: str = None) -> str:
    """
    Obtiene una variable de entorno requerida.
    En producción, falla si no existe o es el valor por defecto débil.
    """
    value = os.getenv(key, default)
    
    # Lista de valores débiles que no deben usarse en producción
    weak_values = ['super-secret', 'change-this', 'qr-access-secret-key', 'secret', 'password']
    
    if IS_PRODUCTION:
        if not value:
            print(f"❌ ERROR CRÍTICO: {key} no está configurado en producción")
            sys.exit(1)
        
        if any(weak in value.lower() for weak in weak_values):
            print(f"❌ ERROR CRÍTICO: {key} tiene un valor débil en producción")
            print(f"   Ejecuta 'python generate_secrets.py' para generar secretos seguros")
            sys.exit(1)
    
    return value

# Configuración JWT
SECRET_KEY = get_required_env('JWT_SECRET_KEY', 'super-secret')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRES', 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 7))

# Configuración de archivos
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'data/identificaciones')
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 5242880))  # 5MB por defecto
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Configuración QR
QR_EXPIRY_MINUTES = 5
QR_ACCESS_SECRET = get_required_env('QR_ACCESS_SECRET', 'qr-access-secret-key')

# Crear directorio de uploads si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)