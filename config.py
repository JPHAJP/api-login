import os
from dotenv import load_dotenv

load_dotenv()

# Configuración JWT
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'super-secret')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRES', 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 7))

# Configuración de archivos
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'data/identificaciones')
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 5242880))  # 5MB por defecto
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Configuración QR
QR_EXPIRY_MINUTES = 5
QR_ACCESS_SECRET = os.getenv('QR_ACCESS_SECRET', 'qr-access-secret-key')

# Configuración Google Drive
GOOGLE_CREDENTIALS_PATH = os.getenv('GOOGLE_CREDENTIALS_PATH', 'credentials.json')
GOOGLE_TOKEN_PATH = os.getenv('GOOGLE_TOKEN_PATH', 'token.json')
GOOGLE_SERVICE_ACCOUNT_PATH = os.getenv('GOOGLE_SERVICE_ACCOUNT_PATH')
GOOGLE_DRIVE_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
GOOGLE_DRIVE_ENABLED = os.getenv('GOOGLE_DRIVE_ENABLED', 'false').lower() == 'true'

# Crear directorio de uploads si no existe (para compatibilidad)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)