"""
Endpoint para manejar imágenes de identificación almacenadas en Google Drive
"""

from fastapi import APIRouter, HTTPException, Depends, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from database import get_db
from models import User
from utils.auth import get_current_user
from utils.google_drive import download_identification_image, delete_identification_image

router = APIRouter(prefix="/images", tags=["Gestión de Imágenes"])

@router.get("/identification/{user_id}")
async def get_identification_image(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Descargar imagen de identificación de un usuario desde Google Drive
    Solo accesible por administradores o por el propio usuario
    """
    # Verificar permisos
    if current_user.role != 'admin' and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos para acceder a esta imagen."
        )
    
    # Buscar usuario
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    # Verificar que tenga imagen en Google Drive
    if not target_user.foto_identificacion_drive_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No se encontró imagen de identificación para este usuario."
        )
    
    # Descargar de Google Drive
    drive_result = download_identification_image(target_user.foto_identificacion_drive_id)
    
    if not drive_result.get('success'):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al descargar imagen: {drive_result.get('error', 'Error desconocido')}"
        )
    
    # Determinar tipo de contenido
    metadata = drive_result.get('metadata', {})
    mime_type = metadata.get('mimeType', 'image/jpeg')
    
    # Crear respuesta con la imagen
    image_stream = io.BytesIO(drive_result.get('content'))
    
    return StreamingResponse(
        io.BytesIO(drive_result.get('content')),
        media_type=mime_type,
        headers={
            "Content-Disposition": f"inline; filename=identification_{user_id}.jpg"
        }
    )

@router.delete("/identification/{user_id}")
async def delete_identification_image_endpoint(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Eliminar imagen de identificación de un usuario desde Google Drive
    Solo accesible por administradores
    """
    # Verificar permisos (solo admin)
    if current_user.role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo los administradores pueden eliminar imágenes."
        )
    
    # Buscar usuario
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    # Verificar que tenga imagen en Google Drive
    if not target_user.foto_identificacion_drive_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No se encontró imagen de identificación para este usuario."
        )
    
    # Eliminar de Google Drive
    drive_result = delete_identification_image(target_user.foto_identificacion_drive_id)
    
    if not drive_result.get('success'):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar imagen: {drive_result.get('error', 'Error desconocido')}"
        )
    
    # Limpiar referencias en la base de datos
    target_user.foto_identificacion_drive_id = None
    target_user.foto_identificacion_path = None
    db.commit()
    
    return {
        "message": f"Imagen de identificación del usuario {user_id} eliminada exitosamente.",
        "drive_response": drive_result.get('message')
    }

@router.get("/identification/{user_id}/info")
async def get_identification_image_info(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Obtener información sobre la imagen de identificación sin descargarla
    """
    # Verificar permisos
    if current_user.role != 'admin' and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos para acceder a esta información."
        )
    
    # Buscar usuario
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    return {
        "user_id": user_id,
        "has_identification": bool(target_user.foto_identificacion_drive_id),
        "drive_id": target_user.foto_identificacion_drive_id,
        "legacy_path": target_user.foto_identificacion_path,
        "drive_url": f"https://drive.google.com/file/d/{target_user.foto_identificacion_drive_id}/view" if target_user.foto_identificacion_drive_id else None
    }