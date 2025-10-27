from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from database import get_db
from models import User, QRCode, AccessLog, AccessType
from schemas import (
    UserResponse, QRCodeGenerate, QRScanRequest
)
from utils.auth import get_current_user, get_admin_user
from utils.qr import get_or_create_current_qr, create_qr_image
from datetime import datetime

router = APIRouter(tags=["Usuario"])

@router.get("/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        nombre_completo=current_user.nombre_completo,
        apellidos=current_user.apellidos,
        direccion=current_user.direccion,
        edad=current_user.edad,
        telefono=current_user.telefono,
        role=current_user.role,
        is_authorized=current_user.is_authorized,
        authorization_status=current_user.authorization_status,
        authorization_info=current_user.authorization_info,
        created_at=current_user.created_at,
        authorized_at=current_user.authorized_at,
        unauthorized_at=current_user.unauthorized_at
    )

@router.get("/qr/current", response_model=QRCodeGenerate)
async def get_current_qr(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Obtiene el código QR actual válido - Solo para administradores"""
    
    try:
        current_qr = get_or_create_current_qr(db)
        qr_image = create_qr_image(current_qr.code)
        
        return QRCodeGenerate(
            qr_image=qr_image,
            code=current_qr.code,
            expires_at=current_qr.expires_at
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al generar código QR"
        )

@router.post("/qr/scan")
async def scan_qr_code(
    scan_request: QRScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escanea un código QR para entrada o salida - Solo para usuarios autorizados"""
    # Verificar que el usuario esté autorizado
    if current_user.authorization_status != "authorized":
        status_message = {
            "pending": "Tu cuenta está pendiente de autorización",
            "unauthorized": f"Tu acceso ha sido desautorizado. {current_user.authorization_info or 'Contacta al administrador.'}"
        }.get(current_user.authorization_status, "Estado de autorización inválido")
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=status_message
        )
    
    # Verificar que el código QR existe y no ha expirado
    qr_code = db.query(QRCode).filter(
        QRCode.code == scan_request.qr_code,
        QRCode.is_active == True
    ).first()
    
    if not qr_code:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Código QR no válido"
        )
    
    if qr_code.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código QR expirado"
        )
    
    # Verificar lógica de entrada/salida
    last_access = db.query(AccessLog).filter(
        AccessLog.user_id == current_user.id
    ).order_by(AccessLog.timestamp.desc()).first()
    
    if scan_request.access_type == "entry":
        # Verificar que el usuario no esté ya dentro
        if last_access and last_access.access_type == AccessType.ENTRY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ya tienes una entrada registrada. Debes salir primero."
            )
    else:  # exit
        # Verificar que el usuario esté dentro
        if not last_access or last_access.access_type == AccessType.EXIT:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No tienes una entrada registrada. Debes entrar primero."
            )
    
    # Crear registro de acceso
    access_log = AccessLog(
        user_id=current_user.id,
        qr_code_id=qr_code.id,
        access_type=AccessType.ENTRY if scan_request.access_type == "entry" else AccessType.EXIT,
        timestamp=datetime.now(),
        is_manual=False
    )
    
    db.add(access_log)
    db.commit()
    db.refresh(access_log)
    
    return {
        "message": f"{'Entrada' if scan_request.access_type == 'entry' else 'Salida'} registrada exitosamente",
        "access_log": {
            "id": access_log.id,
            "access_type": access_log.access_type.value,
            "timestamp": access_log.timestamp.isoformat(),
            "user_name": f"{current_user.nombre_completo} {current_user.apellidos}"
        }
    }