import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from models import User, AccessLog, AccessType
from schemas import (
    AdminStats, UserDetailedResponse, UserSearchResponse, UserCurrentlyInside,
    ManualExitRequest, AccessLogStats, AccessLogResponse, UserAuthorizationResponse,
    UserDeletionCheckResponse, UnauthorizeUserRequest
)
from utils.auth import get_admin_user
from utils.qr import get_or_create_current_qr

router = APIRouter(prefix="/admin", tags=["Administración"])

@router.get('/users/pending')
async def get_pending_users(
    page: int = 1,
    per_page: int = 20,
    role_filter: Optional[str] = None,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    # Limitar per_page máximo
    per_page = min(per_page, 100)
    
    query = db.query(User).filter(User.is_authorized == False)
    
    if role_filter and role_filter in ['voluntarios', 'personal', 'servicio_social', 
                                       'visitas', 'familiares', 'donantes', 'proveedores']:
        query = query.filter(User.role == role_filter)
    
    # Calcular offset
    offset = (page - 1) * per_page
    
    # Obtener total y usuarios paginados
    total = query.count()
    users = query.offset(offset).limit(per_page).all()
    
    user_responses = [
        {
            "id": user.id,
            "email": user.email,
            "nombre_completo": user.nombre_completo,
            "apellidos": user.apellidos,
            "direccion": user.direccion,
            "edad": user.edad,
            "telefono": user.telefono,
            "role": user.role,
            "created_at": user.created_at.isoformat()
        } for user in users
    ]
    
    total_pages = (total + per_page - 1) // per_page
    
    return {
        "users": user_responses,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages
    }

@router.post('/users/{user_id}/authorize')
async def authorize_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.authorization_status == "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya está autorizado."
        )
    
    # Autorizar usuario
    user.is_authorized = True
    user.authorization_status = "authorized"
    user.authorization_info = f"Autorizado por {admin_user.nombre_completo} {admin_user.apellidos} el {datetime.now().strftime('%d/%m/%Y %H:%M')}"
    user.authorized_at = datetime.now()
    user.authorized_by_id = admin_user.id
    user.unauthorized_at = None  # Limpiar fecha de desautorización si existía
    user.unauthorized_by_id = None
    
    db.commit()
    
    return {
        "message": "Usuario autorizado exitosamente.",
        "user": {
            "id": user.id,
            "email": user.email,
            "nombre_completo": user.nombre_completo,
            "apellidos": user.apellidos,
            "role": user.role,
            "is_authorized": user.is_authorized,
            "authorized_at": user.authorized_at.isoformat() if user.authorized_at else None
        }
    }

@router.post('/users/{user_id}/reject')
async def reject_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    # Verificar que el usuario NO esté autorizado
    if user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede eliminar un usuario ya autorizado. Use el endpoint 'unauthorize' para desautorizar al usuario."
        )
    
    # Verificar que el usuario no tenga registros de acceso (doble seguridad)
    access_logs_count = db.query(AccessLog).filter(AccessLog.user_id == user_id).count()
    if access_logs_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede eliminar un usuario que tiene registros de acceso. Use el endpoint 'unauthorize' para desautorizar al usuario."
        )
    
    # Verificar que no sea admin
    if user.role == 'admin':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede eliminar un usuario administrador."
        )
    
    try:
        # Eliminar archivo de identificación si existe
        if user.foto_identificacion_path and os.path.exists(user.foto_identificacion_path):
            try:
                os.remove(user.foto_identificacion_path)
            except Exception:
                pass  # No fallar si no se puede eliminar el archivo
        
        # Eliminar usuario
        db.delete(user)
        db.commit()
        
        return {"message": f"Usuario {user.nombre_completo} {user.apellidos} rechazado y eliminado exitosamente."}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el usuario. Es posible que tenga datos relacionados que impiden su eliminación."
        )

@router.get('/users/{user_id}/can-delete', response_model=UserDeletionCheckResponse)
async def check_if_user_can_be_deleted(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Verifica si un usuario puede ser eliminado de forma segura"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    reasons_cannot_delete = []
    
    # Verificar si está autorizado
    if user.is_authorized:
        reasons_cannot_delete.append("Usuario ya está autorizado")
    
    # Verificar si es admin
    if user.role == 'admin':
        reasons_cannot_delete.append("No se pueden eliminar administradores")
    
    # Verificar si tiene registros de acceso
    access_logs_count = db.query(AccessLog).filter(AccessLog.user_id == user_id).count()
    if access_logs_count > 0:
        reasons_cannot_delete.append(f"Usuario tiene {access_logs_count} registros de acceso")
    
    # Verificar si autorizó a otros usuarios
    authorized_users_count = db.query(User).filter(User.authorized_by_id == user_id).count()
    if authorized_users_count > 0:
        reasons_cannot_delete.append(f"Usuario autorizó a {authorized_users_count} otros usuarios")
    
    can_delete = len(reasons_cannot_delete) == 0
    
    return {
        "can_delete": can_delete,
        "user_id": user_id,
        "user_name": f"{user.nombre_completo} {user.apellidos}",
        "reasons_cannot_delete": reasons_cannot_delete,
        "recommended_action": "unauthorize" if user.is_authorized else ("delete" if can_delete else "cannot_delete")
    }

@router.post('/users/{user_id}/unauthorize', response_model=UserAuthorizationResponse)
async def unauthorize_user(
    user_id: int,
    unauthorize_request: UnauthorizeUserRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Quitar autorización a un usuario previamente autorizado.
    IMPORTANTE: Los usuarios nunca se eliminan si fueron autorizados alguna vez.
    Solo se marca como no autorizado para auditoría y control.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.authorization_status != "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"El usuario no está autorizado actualmente. Estado actual: {user.authorization_status}. Info: {user.authorization_info}"
        )
    
    # Verificar que no sea admin (protección extra)
    if user.role == 'admin':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede desautorizar a un administrador."
        )
    
    # Desautorizar usuario (mantener historial completo)
    user.is_authorized = False
    user.authorization_status = "unauthorized"
    user.authorization_info = f"Desautorizado por {admin_user.nombre_completo} {admin_user.apellidos} el {datetime.now().strftime('%d/%m/%Y %H:%M')}. Razón: {unauthorize_request.reason}"
    user.unauthorized_at = datetime.now()
    user.unauthorized_by_id = admin_user.id
    # Mantener authorized_at para historial
    
    db.commit()
    db.refresh(user)
    
    # Obtener información del admin que originalmente autorizó y desautorizó
    authorized_by_name = None
    if user.authorized_by_id:
        authorized_by = db.query(User).filter(User.id == user.authorized_by_id).first()
        if authorized_by:
            authorized_by_name = f"{authorized_by.nombre_completo} {authorized_by.apellidos}"
    
    unauthorized_by_name = None
    if user.unauthorized_by_id:
        unauthorized_by = db.query(User).filter(User.id == user.unauthorized_by_id).first()
        if unauthorized_by:
            unauthorized_by_name = f"{unauthorized_by.nombre_completo} {unauthorized_by.apellidos}"
    
    # Construir respuesta detallada
    user_detailed = UserDetailedResponse(
        id=user.id,
        email=user.email,
        nombre_completo=user.nombre_completo,
        apellidos=user.apellidos,
        direccion=user.direccion,
        edad=user.edad,
        telefono=user.telefono,
        role=user.role,
        is_authorized=user.is_authorized,
        authorization_status=user.authorization_status,
        authorization_info=user.authorization_info,
        foto_identificacion_path=user.foto_identificacion_path,
        created_at=user.created_at,
        authorized_at=user.authorized_at,
        unauthorized_at=user.unauthorized_at,
        authorized_by_id=user.authorized_by_id,
        authorized_by_name=authorized_by_name,
        unauthorized_by_id=user.unauthorized_by_id,
        unauthorized_by_name=unauthorized_by_name
    )
    
    return UserAuthorizationResponse(
        message=f"Autorización removida para {user.nombre_completo} {user.apellidos}",
        user=user_detailed,
        action_by=f"{admin_user.nombre_completo} {admin_user.apellidos}",
        reason=unauthorize_request.reason
    )

@router.post('/users/{user_id}/reauthorize', response_model=UserAuthorizationResponse)
async def reauthorize_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Re-autorizar un usuario que fue previamente desautorizado.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.authorization_status == "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya está autorizado."
        )
    
    # Re-autorizar usuario
    user.is_authorized = True
    user.authorization_status = "authorized"
    user.authorization_info = f"Re-autorizado por {admin_user.nombre_completo} {admin_user.apellidos} el {datetime.now().strftime('%d/%m/%Y %H:%M')}"
    user.authorized_at = datetime.now()
    user.authorized_by_id = admin_user.id
    user.unauthorized_at = None  # Limpiar fecha de desautorización
    user.unauthorized_by_id = None
    
    db.commit()
    db.refresh(user)
    
    # Construir respuesta detallada
    user_detailed = UserDetailedResponse(
        id=user.id,
        email=user.email,
        nombre_completo=user.nombre_completo,
        apellidos=user.apellidos,
        direccion=user.direccion,
        edad=user.edad,
        telefono=user.telefono,
        role=user.role,
        is_authorized=user.is_authorized,
        authorization_status=user.authorization_status,
        authorization_info=user.authorization_info,
        foto_identificacion_path=user.foto_identificacion_path,
        created_at=user.created_at,
        authorized_at=user.authorized_at,
        unauthorized_at=user.unauthorized_at,
        authorized_by_id=user.authorized_by_id,
        authorized_by_name=f"{admin_user.nombre_completo} {admin_user.apellidos}",
        unauthorized_by_id=user.unauthorized_by_id,
        unauthorized_by_name=None  # Se limpió al re-autorizar
    )
    
    return UserAuthorizationResponse(
        message=f"Usuario re-autorizado exitosamente: {user.nombre_completo} {user.apellidos}",
        user=user_detailed,
        action_by=f"{admin_user.nombre_completo} {admin_user.apellidos}",
        reason=None
    )

@router.get('/users/{user_id}/identification')
async def get_user_identification(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if not user.foto_identificacion_path or not os.path.exists(user.foto_identificacion_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fotografía de identificación no encontrada."
        )
    
    try:
        return FileResponse(
            user.foto_identificacion_path,
            media_type='application/octet-stream',
            filename=f"identificacion_usuario_{user_id}.jpg"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al acceder al archivo de identificación."
        )

@router.get("/stats", response_model=AdminStats)
async def admin_stats(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    total_users = db.query(User).count()
    total_authorized = db.query(User).filter(User.is_authorized == True).count()
    total_pending = db.query(User).filter(User.is_authorized == False).count()
    
    # Contar por roles
    roles_count = {}
    all_roles = ['admin', 'voluntarios', 'personal', 'servicio_social', 
                 'visitas', 'familiares', 'donantes', 'proveedores']
    
    for role in all_roles:
        roles_count[role] = db.query(User).filter(User.role == role).count()
    
    return AdminStats(
        users_total=total_users,
        users_authorized=total_authorized,
        users_pending=total_pending,
        users_by_role=roles_count
    )

@router.get("/access-logs", response_model=AccessLogStats)
async def get_access_logs(
    date: Optional[str] = None,  # Formato: YYYY-MM-DD
    page: int = 1,
    per_page: int = 50,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Obtiene logs de acceso filtrados por fecha"""
    # Limitar per_page máximo
    per_page = min(per_page, 100)
    
    query = db.query(AccessLog).join(User, AccessLog.user_id == User.id).order_by(AccessLog.timestamp.desc())
    
    # Filtrar por fecha si se proporciona
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
            start_datetime = datetime.combine(target_date, datetime.min.time())
            end_datetime = datetime.combine(target_date, datetime.max.time())
            query = query.filter(
                AccessLog.timestamp >= start_datetime,
                AccessLog.timestamp <= end_datetime
            )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Formato de fecha inválido. Use YYYY-MM-DD"
            )
    else:
        # Si no se especifica fecha, mostrar solo el día actual
        today = datetime.now().date()
        start_datetime = datetime.combine(today, datetime.min.time())
        end_datetime = datetime.combine(today, datetime.max.time())
        query = query.filter(
            AccessLog.timestamp >= start_datetime,
            AccessLog.timestamp <= end_datetime
        )
    
    # Calcular estadísticas
    all_logs_today = query.all() if not date else query.all()
    total_entries = sum(1 for log in all_logs_today if log.access_type == AccessType.ENTRY)
    total_exits = sum(1 for log in all_logs_today if log.access_type == AccessType.EXIT)
    
    # Calcular usuarios actualmente dentro
    user_status = {}
    for log in sorted(all_logs_today, key=lambda x: x.timestamp):
        if log.access_type == AccessType.ENTRY:
            user_status[log.user_id] = True
        else:
            user_status[log.user_id] = False
    
    currently_inside = sum(1 for inside in user_status.values() if inside)
    
    # Paginación
    offset = (page - 1) * per_page
    paginated_logs = query.offset(offset).limit(per_page).all()
    
    # Convertir a response format
    log_responses = []
    for log in paginated_logs:
        log_responses.append(AccessLogResponse(
            id=log.id,
            user_id=log.user_id,
            user_name=f"{log.user.nombre_completo} {log.user.apellidos}",
            user_email=log.user.email,
            qr_code_id=log.qr_code_id,
            access_type=log.access_type.value,
            timestamp=log.timestamp,
            notes=log.notes,
            is_manual=log.is_manual,
            manual_by_admin_id=log.manual_by_admin_id,
            manual_by_admin_name=f"{log.manual_by_admin.nombre_completo} {log.manual_by_admin.apellidos}" if log.manual_by_admin else None
        ))
    
    return AccessLogStats(
        total_entries=total_entries,
        total_exits=total_exits,
        currently_inside=currently_inside,
        logs=log_responses
    )

@router.get("/users-inside", response_model=List[UserCurrentlyInside])
async def get_users_currently_inside(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Obtiene la lista de usuarios que han entrado pero no han salido"""
    # Obtener todos los logs de acceso del día actual
    today = datetime.now().date()
    start_datetime = datetime.combine(today, datetime.min.time())
    end_datetime = datetime.combine(today, datetime.max.time())
    
    logs = db.query(AccessLog).join(User, AccessLog.user_id == User.id).filter(
        AccessLog.timestamp >= start_datetime,
        AccessLog.timestamp <= end_datetime
    ).order_by(AccessLog.timestamp.asc()).all()
    
    # Calcular estado actual de cada usuario
    user_status = {}
    user_last_entry = {}
    
    for log in logs:
        if log.access_type == AccessType.ENTRY:
            user_status[log.user_id] = True
            user_last_entry[log.user_id] = log
        else:
            user_status[log.user_id] = False
    
    # Filtrar usuarios que están dentro
    users_inside = []
    for user_id, is_inside in user_status.items():
        if is_inside and user_id in user_last_entry:
            entry_log = user_last_entry[user_id]
            user = entry_log.user
            
            users_inside.append(UserCurrentlyInside(
                id=user.id,
                email=user.email,
                nombre_completo=user.nombre_completo,
                apellidos=user.apellidos,
                role=user.role,
                entry_time=entry_log.timestamp,
                entry_id=entry_log.id
            ))
    
    return sorted(users_inside, key=lambda x: x.entry_time)

@router.post("/users/{user_id}/manual-exit")
async def register_manual_exit(
    user_id: int,
    exit_request: ManualExitRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Registra una salida manual para un usuario que olvidó salir"""
    # Verificar que el usuario existe
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    # Verificar que el usuario está actualmente dentro
    today = datetime.now().date()
    start_datetime = datetime.combine(today, datetime.min.time())
    
    last_access = db.query(AccessLog).filter(
        AccessLog.user_id == user_id,
        AccessLog.timestamp >= start_datetime
    ).order_by(AccessLog.timestamp.desc()).first()
    
    if not last_access or last_access.access_type == AccessType.EXIT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario no tiene una entrada registrada hoy"
        )
    
    # Obtener QR actual para el registro
    current_qr = get_or_create_current_qr(db)
    
    # Crear registro de salida manual
    exit_log = AccessLog(
        user_id=user_id,
        qr_code_id=current_qr.id,
        access_type=AccessType.EXIT,
        timestamp=datetime.now(),
        notes=exit_request.notes or "Salida registrada manualmente por administrador",
        is_manual=True,
        manual_by_admin_id=admin_user.id
    )
    
    db.add(exit_log)
    db.commit()
    db.refresh(exit_log)
    
    return {
        "message": f"Salida registrada manualmente para {user.nombre_completo} {user.apellidos}",
        "access_log": {
            "id": exit_log.id,
            "user_name": f"{user.nombre_completo} {user.apellidos}",
            "access_type": exit_log.access_type.value,
            "timestamp": exit_log.timestamp.isoformat(),
            "is_manual": exit_log.is_manual,
            "notes": exit_log.notes
        }
    }

@router.get("/users/search", response_model=UserSearchResponse)
async def search_users(
    category: Optional[str] = None,  # Filtro por rol/categoría
    search: Optional[str] = None,    # Búsqueda por nombre o email
    page: int = 1,
    per_page: int = 20,
    include_pending: bool = True,    # Incluir usuarios pendientes de autorización
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Buscar y listar usuarios con filtros avanzados
    
    - category: Filtrar por rol específico (admin, voluntarios, personal, etc.)
    - search: Buscar por nombre completo, apellidos o email (búsqueda parcial)
    - include_pending: Si incluir usuarios no autorizados (por defecto True)
    """
    # Limitar per_page máximo
    per_page = min(per_page, 100)
    
    # Construir query base
    query = db.query(User)
    
    # Filtro por categoría/rol
    if category:
        valid_categories = ['admin', 'voluntarios', 'personal', 'servicio_social', 
                           'visitas', 'familiares', 'donantes', 'proveedores']
        if category in valid_categories:
            query = query.filter(User.role == category)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Categoría inválida. Categorías válidas: {', '.join(valid_categories)}"
            )
    
    # Filtro por texto (nombre, apellidos o email)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (User.nombre_completo.ilike(search_term)) |
            (User.apellidos.ilike(search_term)) |
            (User.email.ilike(search_term))
        )
    
    # Filtro por estado de autorización
    if not include_pending:
        query = query.filter(User.is_authorized == True)
    
    # Ordenar por fecha de creación (más recientes primero)
    query = query.order_by(User.created_at.desc())
    
    # Calcular total antes de paginación
    total = query.count()
    
    # Aplicar paginación
    offset = (page - 1) * per_page
    users = query.offset(offset).limit(per_page).all()
    
    # Construir respuesta con datos detallados
    user_responses = []
    for user in users:
        # Obtener información del admin que autorizó y desautorizó (si aplica)
        authorized_by_name = None
        if user.authorized_by_id:
            authorized_by = db.query(User).filter(User.id == user.authorized_by_id).first()
            if authorized_by:
                authorized_by_name = f"{authorized_by.nombre_completo} {authorized_by.apellidos}"
        
        unauthorized_by_name = None
        if user.unauthorized_by_id:
            unauthorized_by = db.query(User).filter(User.id == user.unauthorized_by_id).first()
            if unauthorized_by:
                unauthorized_by_name = f"{unauthorized_by.nombre_completo} {unauthorized_by.apellidos}"
        
        user_responses.append(UserDetailedResponse(
            id=user.id,
            email=user.email,
            nombre_completo=user.nombre_completo,
            apellidos=user.apellidos,
            direccion=user.direccion,
            edad=user.edad,
            telefono=user.telefono,
            role=user.role,
            is_authorized=user.is_authorized,
            authorization_status=user.authorization_status,
            authorization_info=user.authorization_info,
            foto_identificacion_path=user.foto_identificacion_path,
            created_at=user.created_at,
            authorized_at=user.authorized_at,
            unauthorized_at=user.unauthorized_at,
            authorized_by_id=user.authorized_by_id,
            authorized_by_name=authorized_by_name,
            unauthorized_by_id=user.unauthorized_by_id,
            unauthorized_by_name=unauthorized_by_name
        ))
    
    total_pages = (total + per_page - 1) // per_page
    
    return UserSearchResponse(
        users=user_responses,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages
    )

@router.get('/users/{user_id}/identification-file')
async def get_user_identification_file(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Obtener el archivo de identificación de un usuario específico
    Devuelve la imagen directamente para mostrar en navegador
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if not user.foto_identificacion_path or not os.path.exists(user.foto_identificacion_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fotografía de identificación no encontrada."
        )
    
    try:
        # Determinar el tipo MIME basado en la extensión
        file_extension = user.foto_identificacion_path.lower().split('.')[-1]
        media_type_map = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp'
        }
        media_type = media_type_map.get(file_extension, 'image/jpeg')
        
        return FileResponse(
            user.foto_identificacion_path,
            media_type=media_type,
            filename=f"identificacion_usuario_{user_id}_{user.nombre_completo.replace(' ', '_')}.{file_extension}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al acceder al archivo de identificación."
        )