from datetime import timedelta, datetime
from typing import Dict, Any
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename
import os

from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, Form, status
from sqlalchemy.orm import Session

from database import get_db
from models import User
from schemas import UserLogin, Token, UserAuthStatusResponse
from utils.auth import (
    create_access_token, create_refresh_token, get_current_user, 
    get_refresh_token_user, _normalize_email, validate_phone, 
    allowed_file
)
from utils.google_drive import upload_identification_image
from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS, 
    UPLOAD_FOLDER, ALLOWED_EXTENSIONS, GOOGLE_DRIVE_ENABLED
)

router = APIRouter(prefix="/auth", tags=["Autenticación"])

@router.post('/register', response_model=Dict[str, Any])
async def register(
    email: str = Form(...),
    password: str = Form(...),
    nombre_completo: str = Form(...),
    apellidos: str = Form(...),
    direccion: str = Form(...),
    edad: int = Form(...),
    telefono: str = Form(...),
    role: str = Form(...),
    foto_identificacion: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Validar archivo
    if not foto_identificacion.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se seleccionó ningún archivo."
        )
    
    if not allowed_file(foto_identificacion.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de archivo no válido. Solo se permiten PNG, JPG, JPEG."
        )
    
    # Validar datos del formulario
    try:
        normalized_email = _normalize_email(email)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email inválido: {str(e)}"
        )
    
    # Validar contraseña
    if len(password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe tener al menos 6 caracteres."
        )
    
    # Validar edad
    if edad < 18 or edad > 120:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debe ser mayor de edad (18 años o más)."
        )
    
    # Validar teléfono
    if not validate_phone(telefono):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de teléfono inválido (debe tener 10-15 dígitos)."
        )
    
    # Validar rol
    valid_roles = ['voluntarios', 'personal', 'servicio_social', 'visitas', 
                   'familiares', 'donantes', 'proveedores']
    if role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rol inválido. Roles válidos: {', '.join(valid_roles)}"
        )
    
    # Verificar si el email ya existe
    if db.query(User).filter(User.email == normalized_email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El email ya está registrado."
        )
    
    # Leer contenido del archivo de identificación
    filename = secure_filename(foto_identificacion.filename)
    file_extension = filename.rsplit('.', 1)[1].lower()
    
    try:
        content = await foto_identificacion.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al leer el archivo de identificación."
        )
    
    # Crear usuario temporalmente para obtener el ID
    try:
        user = User(
            email=normalized_email,
            nombre_completo=nombre_completo.strip(),
            apellidos=apellidos.strip(),
            direccion=direccion.strip(),
            edad=edad,
            telefono=telefono.strip(),
            role=role,
            is_authorized=False,  # Requiere autorización de admin
        )
        
        # Establecer la contraseña usando el método del modelo
        user.set_password(password)
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Guardar archivo (Google Drive o local según configuración)
        if GOOGLE_DRIVE_ENABLED:
            # Subir archivo a Google Drive
            drive_result = upload_identification_image(content, user.id, file_extension)
            
            if not drive_result.get('success'):
                # Si falla la subida a Drive, eliminar usuario y mostrar error
                db.delete(user)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error al subir archivo a Google Drive: {drive_result.get('error', 'Error desconocido')}"
                )
            
            # Actualizar usuario con ID de Google Drive
            user.foto_identificacion_drive_id = drive_result.get('file_id')
            user.foto_identificacion_path = f"drive://{drive_result.get('file_id')}"
            
        else:
            # Guardar archivo localmente (método original)
            filename = secure_filename(foto_identificacion.filename)
            unique_filename = f"user_{user.id}_id.{file_extension}"
            file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
            
            try:
                with open(file_path, "wb") as f:
                    f.write(content)
                user.foto_identificacion_path = file_path
            except Exception as e:
                # Si falla el guardado local, eliminar usuario y mostrar error
                db.delete(user)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al guardar el archivo de identificación localmente."
                )
        
        db.commit()
        
        # Preparar información de respuesta
        user_info = {
            "id": user.id,
            "email": user.email,
            "nombre_completo": user.nombre_completo,
            "apellidos": user.apellidos,
            "role": user.role,
            "is_authorized": user.is_authorized,
            "created_at": user.created_at.isoformat()
        }
        
        # Agregar información del archivo según el método de almacenamiento
        if GOOGLE_DRIVE_ENABLED and 'drive_result' in locals():
            user_info["foto_identificacion_info"] = {
                "storage_type": "google_drive",
                "drive_id": drive_result.get('file_id'),
                "drive_url": drive_result.get('drive_url'),
                "upload_time": drive_result.get('created_time')
            }
        else:
            user_info["foto_identificacion_info"] = {
                "storage_type": "local",
                "file_path": user.foto_identificacion_path if user.foto_identificacion_path else None
            }
        
        return {
            "message": "Usuario registrado exitosamente. Pendiente de autorización por un administrador.",
            "user": user_info
        }
        
    except HTTPException:
        # Re-lanzar HTTPException tal como están
        raise
    except Exception as e:
        # Limpiar usuario si hay error
        try:
            if 'user' in locals() and user.id:
                db.delete(user)
                db.commit()
        except:
            pass
        
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor."
        )

@router.post("/login", response_model=Token)
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    try:
        email = _normalize_email(user_credentials.email)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email inválido: {ve}"
        )

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas."
        )
    
    try:
        password_valid = user.check_password(user_credentials.password)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor. Por favor contacta al administrador."
        )
    
    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas."
        )
    
    # Verificar estado de autorización
    # Los admins siempre pueden iniciar sesión
    if user.role != 'admin':
        if user.authorization_status == "pending":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tu cuenta está pendiente de autorización. Contacta al administrador."
            )
        # Los usuarios autorizados y desautorizados SÍ pueden iniciar sesión
        # pero los desautorizados tendrán restricciones en ciertos endpoints
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={
            "sub": str(user.id), 
            "email": user.email, 
            "role": user.role, 
            "is_authorized": user.is_authorized,
            "authorization_status": user.authorization_status
        },
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id)},
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.get("/status", response_model=UserAuthStatusResponse)
async def get_auth_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Verificar el estado de autorización del usuario actual
    Retorna información detallada sobre permisos y restricciones
    """
    # Obtener información del admin que autorizó (si aplica)
    authorized_by_name = None
    if current_user.authorized_by_id:
        authorized_by = db.query(User).filter(User.id == current_user.authorized_by_id).first()
        if authorized_by:
            authorized_by_name = f"{authorized_by.nombre_completo} {authorized_by.apellidos}"
    
    # Obtener información del admin que desautorizó (si aplica)
    unauthorized_by_name = None
    if current_user.unauthorized_by_id:
        unauthorized_by = db.query(User).filter(User.id == current_user.unauthorized_by_id).first()
        if unauthorized_by:
            unauthorized_by_name = f"{unauthorized_by.nombre_completo} {unauthorized_by.apellidos}"
    
    # Determinar permisos según el estado
    can_login = True  # Si llegó hasta aquí, ya puede hacer login
    can_access_qr = current_user.authorization_status == "authorized"
    
    # Generar mensaje apropiado según el estado
    if current_user.authorization_status == "pending":
        message = "Tu cuenta está pendiente de autorización. Contacta al administrador para obtener acceso completo."
    elif current_user.authorization_status == "authorized":
        message = "Tu cuenta está autorizada. Tienes acceso completo al sistema."
    elif current_user.authorization_status == "unauthorized":
        message = f"Tu cuenta ha sido desautorizada. {current_user.authorization_info or 'Contacta al administrador para más información.'}"
    else:
        message = "Estado de autorización desconocido."
    
    return UserAuthStatusResponse(
        user_id=current_user.id,
        email=current_user.email,
        nombre_completo=current_user.nombre_completo,
        authorization_status=current_user.authorization_status,
        authorization_info=current_user.authorization_info,
        can_login=can_login,
        can_access_qr=can_access_qr,
        authorized_at=current_user.authorized_at,
        unauthorized_at=current_user.unauthorized_at,
        authorized_by_name=authorized_by_name,
        unauthorized_by_name=unauthorized_by_name,
        message=message
    )

@router.post("/refresh", response_model=Dict[str, str])
async def refresh_token(user: User = Depends(get_refresh_token_user)):
    # Verificar que el usuario siga autorizado (excepto admins)
    if user.role != 'admin' and user.authorization_status != "authorized":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Tu cuenta ya no está autorizada. Estado: {user.authorization_status}. {user.authorization_info}"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role, "is_authorized": user.is_authorized},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token}