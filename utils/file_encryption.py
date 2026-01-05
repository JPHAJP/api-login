"""
Módulo para encriptar y desencriptar archivos usando Fernet (criptografía simétrica).
Utiliza la clave DATABASE_ENCRYPTION_KEY del archivo .env
"""
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Union


def _derive_key_from_secret(secret: str) -> bytes:
    """
    Deriva una clave de 32 bytes compatible con Fernet desde un secreto arbitrario.
    
    Args:
        secret: La clave secreta del .env
        
    Returns:
        bytes: Una clave de 32 bytes derivada
    """
    # Usamos un salt fijo para que la misma clave siempre genere el mismo resultado
    # En producción, esto es aceptable ya que la clave base ya es segura
    salt = b'static_salt_for_file_encryption'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
    return key


def get_encryption_key() -> bytes:
    """
    Obtiene la clave de encriptación desde las variables de entorno.
    
    Returns:
        bytes: La clave de encriptación derivada
        
    Raises:
        ValueError: Si la clave no está configurada
    """
    encryption_key = os.getenv('DATABASE_ENCRYPTION_KEY')
    if not encryption_key:
        raise ValueError("DATABASE_ENCRYPTION_KEY no está configurada en el archivo .env")
    
    return _derive_key_from_secret(encryption_key)


def encrypt_file(file_path: str, output_path: str = None) -> str:
    """
    Encripta un archivo usando la clave del .env.
    
    Args:
        file_path: Ruta del archivo a encriptar
        output_path: Ruta donde guardar el archivo encriptado (opcional).
                     Si no se especifica, sobrescribe el archivo original.
    
    Returns:
        str: La ruta del archivo encriptado
        
    Raises:
        FileNotFoundError: Si el archivo no existe
        ValueError: Si la clave de encriptación no está configurada
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"El archivo {file_path} no existe")
    
    # Obtener la clave de encriptación
    key = get_encryption_key()
    fernet = Fernet(key)
    
    # Leer el archivo original
    with open(file_path, 'rb') as file:
        original_data = file.read()
    
    # Encriptar los datos
    encrypted_data = fernet.encrypt(original_data)
    
    # Determinar la ruta de salida
    if output_path is None:
        output_path = file_path
    
    # Guardar el archivo encriptado
    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    return output_path


def decrypt_file(encrypted_file_path: str, output_path: str = None) -> Union[str, bytes]:
    """
    Desencripta un archivo usando la clave del .env.
    
    Args:
        encrypted_file_path: Ruta del archivo encriptado
        output_path: Ruta donde guardar el archivo desencriptado (opcional).
                     Si no se especifica, retorna los bytes desencriptados sin guardar.
    
    Returns:
        str o bytes: La ruta del archivo desencriptado si output_path fue especificado,
                     o los bytes desencriptados si no.
        
    Raises:
        FileNotFoundError: Si el archivo no existe
        ValueError: Si la clave de encriptación no está configurada
        cryptography.fernet.InvalidToken: Si el archivo no puede ser desencriptado (clave incorrecta o archivo corrupto)
    """
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"El archivo {encrypted_file_path} no existe")
    
    # Obtener la clave de encriptación
    key = get_encryption_key()
    fernet = Fernet(key)
    
    # Leer el archivo encriptado
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    
    # Desencriptar los datos
    decrypted_data = fernet.decrypt(encrypted_data)
    
    # Si se especifica output_path, guardar el archivo
    if output_path:
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        return output_path
    
    # Si no, retornar los bytes desencriptados
    return decrypted_data


def encrypt_file_content(content: bytes) -> bytes:
    """
    Encripta contenido en memoria sin necesidad de archivos.
    
    Args:
        content: Los bytes a encriptar
        
    Returns:
        bytes: El contenido encriptado
        
    Raises:
        ValueError: Si la clave de encriptación no está configurada
    """
    key = get_encryption_key()
    fernet = Fernet(key)
    return fernet.encrypt(content)


def decrypt_file_content(encrypted_content: bytes) -> bytes:
    """
    Desencripta contenido en memoria sin necesidad de archivos.
    
    Args:
        encrypted_content: Los bytes encriptados
        
    Returns:
        bytes: El contenido desencriptado
        
    Raises:
        ValueError: Si la clave de encriptación no está configurada
        cryptography.fernet.InvalidToken: Si el contenido no puede ser desencriptado
    """
    key = get_encryption_key()
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_content)
