"""
Módulo para manejar logs de seguridad del sistema.
Registra eventos importantes como intentos fallidos de login, cambios de contraseña, etc.
"""
import json
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import Request

from models import SecurityLog, SecurityEventType, User


def get_client_ip(request: Request) -> str:
    """
    Obtiene la dirección IP del cliente desde la request.
    Maneja proxies y balanceadores de carga.
    """
    # Intentar obtener desde headers de proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback al client directo
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> str:
    """Obtiene el User-Agent del cliente."""
    return request.headers.get("User-Agent", "unknown")


def log_security_event(
    db: Session,
    event_type: SecurityEventType,
    description: str,
    user_id: Optional[int] = None,
    performed_by_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict] = None,
    severity: str = "info"
):
    """
    Registra un evento de seguridad en la base de datos.
    
    Args:
        db: Sesión de base de datos
        event_type: Tipo de evento (de SecurityEventType)
        description: Descripción del evento
        user_id: ID del usuario afectado (opcional)
        performed_by_id: ID del usuario que realizó la acción (opcional)
        ip_address: Dirección IP del cliente (opcional)
        user_agent: User-Agent del cliente (opcional)
        metadata: Información adicional en formato dict (opcional)
        severity: Nivel de severidad: 'info', 'warning', 'critical'
    """
    try:
        security_log = SecurityLog(
            event_type=event_type,
            user_id=user_id,
            performed_by_id=performed_by_id,
            ip_address=ip_address,
            user_agent=user_agent,
            description=description,
            event_metadata=json.dumps(metadata) if metadata else None,
            severity=severity,
            timestamp=datetime.now()
        )
        
        db.add(security_log)
        db.commit()
        
        # Si es crítico, también lo mostramos en consola
        if severity == "critical":
            print(f"🚨 SECURITY ALERT: {event_type.value} - {description}")
        
    except Exception as e:
        print(f"Error al registrar evento de seguridad: {e}")
        db.rollback()


def log_failed_login(
    db: Session,
    request: Request,
    email: str,
    user_id: Optional[int] = None,
    reason: str = "Contraseña incorrecta"
):
    """
    Registra un intento fallido de login.
    """
    log_security_event(
        db=db,
        event_type=SecurityEventType.FAILED_LOGIN,
        description=f"Intento fallido de login para {email}: {reason}",
        user_id=user_id,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        metadata={"email": email, "reason": reason},
        severity="warning"
    )


def log_successful_login(
    db: Session,
    request: Request,
    user: User
):
    """
    Registra un login exitoso (para contexto y análisis).
    """
    log_security_event(
        db=db,
        event_type=SecurityEventType.SUCCESSFUL_LOGIN,
        description=f"Login exitoso para {user.email}",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        metadata={"email": user.email, "role": user.role},
        severity="info"
    )


def log_password_changed(
    db: Session,
    user: User,
    changed_by_admin: bool = False,
    admin_user: Optional[User] = None
):
    """
    Registra un cambio de contraseña.
    """
    if changed_by_admin and admin_user:
        event_type = SecurityEventType.PASSWORD_CHANGED_BY_ADMIN
        description = f"Contraseña cambiada por administrador {admin_user.email} para usuario {user.email}"
        performed_by_id = admin_user.id
        severity = "warning"
    else:
        event_type = SecurityEventType.PASSWORD_CHANGED
        description = f"Usuario {user.email} cambió su contraseña"
        performed_by_id = user.id
        severity = "info"
    
    log_security_event(
        db=db,
        event_type=event_type,
        description=description,
        user_id=user.id,
        performed_by_id=performed_by_id,
        metadata={"changed_by_admin": changed_by_admin},
        severity=severity
    )


def log_user_authorized(
    db: Session,
    user: User,
    admin_user: User
):
    """
    Registra cuando un usuario es autorizado.
    """
    log_security_event(
        db=db,
        event_type=SecurityEventType.USER_AUTHORIZED,
        description=f"Usuario {user.email} autorizado por {admin_user.email}",
        user_id=user.id,
        performed_by_id=admin_user.id,
        metadata={"user_role": user.role},
        severity="info"
    )


def log_user_unauthorized(
    db: Session,
    user: User,
    admin_user: User,
    reason: Optional[str] = None
):
    """
    Registra cuando un usuario es suspendido/desautorizado.
    """
    description = f"Usuario {user.email} desautorizado por {admin_user.email}"
    if reason:
        description += f". Razón: {reason}"
    
    log_security_event(
        db=db,
        event_type=SecurityEventType.USER_UNAUTHORIZED,
        description=description,
        user_id=user.id,
        performed_by_id=admin_user.id,
        metadata={"reason": reason, "user_role": user.role},
        severity="warning"
    )


def log_user_reauthorized(
    db: Session,
    user: User,
    admin_user: User
):
    """
    Registra cuando un usuario es reactivado.
    """
    log_security_event(
        db=db,
        event_type=SecurityEventType.USER_REAUTHORIZED,
        description=f"Usuario {user.email} re-autorizado por {admin_user.email}",
        user_id=user.id,
        performed_by_id=admin_user.id,
        metadata={"user_role": user.role},
        severity="info"
    )


def log_account_locked(
    db: Session,
    request: Request,
    user: User,
    failed_attempts: int
):
    """
    Registra cuando una cuenta es bloqueada por múltiples intentos fallidos.
    """
    log_security_event(
        db=db,
        event_type=SecurityEventType.ACCOUNT_LOCKED,
        description=f"Cuenta {user.email} bloqueada temporalmente por {failed_attempts} intentos fallidos",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        metadata={"failed_attempts": failed_attempts},
        severity="critical"
    )


def log_account_unlocked(
    db: Session,
    user: User,
    admin_user: Optional[User] = None
):
    """
    Registra cuando una cuenta es desbloqueada.
    """
    if admin_user:
        description = f"Cuenta {user.email} desbloqueada por administrador {admin_user.email}"
        performed_by_id = admin_user.id
    else:
        description = f"Cuenta {user.email} desbloqueada automáticamente por expiración del bloqueo"
        performed_by_id = None
    
    log_security_event(
        db=db,
        event_type=SecurityEventType.ACCOUNT_UNLOCKED,
        description=description,
        user_id=user.id,
        performed_by_id=performed_by_id,
        severity="info"
    )


def check_failed_login_attempts(
    db: Session,
    request: Request,
    user: User,
    max_attempts: int = 5,
    lockout_duration_minutes: int = 30
) -> bool:
    """
    Verifica y maneja intentos fallidos de login.
    
    Returns:
        bool: True si la cuenta está bloqueada, False en caso contrario
    """
    # Verificar si ya está bloqueada
    if user.account_locked_until:
        if user.account_locked_until > datetime.now():
            return True
        else:
            # El bloqueo expiró, desbloquear
            user.account_locked_until = None
            user.failed_login_attempts = 0
            log_account_unlocked(db, user)
            db.commit()
    
    # Incrementar contador de intentos fallidos
    user.failed_login_attempts += 1
    user.last_failed_login = datetime.now()
    
    # Si alcanzó el máximo, bloquear la cuenta
    if user.failed_login_attempts >= max_attempts:
        user.account_locked_until = datetime.now() + timedelta(minutes=lockout_duration_minutes)
        log_account_locked(db, request, user, user.failed_login_attempts)
        db.commit()
        return True
    
    db.commit()
    return False


def reset_failed_login_attempts(db: Session, user: User):
    """
    Resetea el contador de intentos fallidos después de un login exitoso.
    """
    if user.failed_login_attempts > 0:
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.account_locked_until = None
        db.commit()


def get_security_logs(
    db: Session,
    user_id: Optional[int] = None,
    event_type: Optional[SecurityEventType] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Obtiene logs de seguridad con filtros opcionales.
    """
    query = db.query(SecurityLog)
    
    if user_id:
        query = query.filter(SecurityLog.user_id == user_id)
    
    if event_type:
        query = query.filter(SecurityLog.event_type == event_type)
    
    if severity:
        query = query.filter(SecurityLog.severity == severity)
    
    if start_date:
        query = query.filter(SecurityLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(SecurityLog.timestamp <= end_date)
    
    # Ordenar por más reciente primero
    query = query.order_by(SecurityLog.timestamp.desc())
    
    # Paginación
    total = query.count()
    logs = query.offset(offset).limit(limit).all()
    
    return {
        'logs': [log.to_dict() for log in logs],
        'total': total,
        'limit': limit,
        'offset': offset
    }


def get_users_with_failed_logins(
    db: Session,
    min_attempts: int = 3
):
    """
    Obtiene usuarios con múltiples intentos fallidos de login.
    Útil para detectar posibles ataques o problemas de seguridad.
    """
    users = db.query(User).filter(
        User.failed_login_attempts >= min_attempts
    ).order_by(User.failed_login_attempts.desc()).all()
    
    return [
        {
            'user_id': user.id,
            'email': user.email,
            'nombre_completo': f"{user.nombre_completo} {user.apellidos}",
            'failed_attempts': user.failed_login_attempts,
            'last_failed_login': user.last_failed_login.isoformat() if user.last_failed_login else None,
            'account_locked': user.account_locked_until is not None and user.account_locked_until > datetime.now(),
            'locked_until': user.account_locked_until.isoformat() if user.account_locked_until else None
        }
        for user in users
    ]
