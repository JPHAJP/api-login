import os
import secrets
import hashlib
import base64
import io
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import qrcode
from PIL import Image

from models import QRCode

# Configuración QR
QR_EXPIRY_MINUTES = 5
QR_ACCESS_SECRET = os.getenv('QR_ACCESS_SECRET', 'qr-access-secret-key')

def generate_qr_code_string() -> str:
    """Genera un código QR único basado en timestamp y secreto"""
    timestamp = datetime.now().isoformat()
    random_bytes = secrets.token_bytes(16)
    data = f"{timestamp}:{QR_ACCESS_SECRET}:{random_bytes.hex()}"
    return hashlib.sha256(data.encode()).hexdigest()

def create_qr_image(data: str) -> str:
    """Crea una imagen QR y la retorna como base64"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()

def cleanup_expired_qr_codes(db: Session):
    """Limpia códigos QR expirados de la base de datos"""
    expired_codes = db.query(QRCode).filter(QRCode.expires_at < datetime.now()).all()
    for code in expired_codes:
        code.is_active = False
    db.commit()

def get_or_create_current_qr(db: Session) -> QRCode:
    """Obtiene el QR actual válido o crea uno nuevo si no existe o expiró"""
    # Limpiar códigos expirados
    cleanup_expired_qr_codes(db)
    
    # Buscar QR activo y no expirado
    current_qr = db.query(QRCode).filter(
        QRCode.is_active == True,
        QRCode.expires_at > datetime.now()
    ).first()
    
    if current_qr:
        return current_qr
    
    # Crear nuevo QR code
    code = generate_qr_code_string()
    expires_at = datetime.now() + timedelta(minutes=QR_EXPIRY_MINUTES)
    
    new_qr = QRCode(
        code=code,
        expires_at=expires_at,
        is_active=True
    )
    
    db.add(new_qr)
    db.commit()
    db.refresh(new_qr)
    
    return new_qr