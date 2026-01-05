"""
Configuración de Rate Limiting para la API
Protege contra ataques de fuerza bruta y abuso de endpoints
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, status
from fastapi.responses import JSONResponse
import os

# Determinar si estamos en desarrollo o producción
IS_DEVELOPMENT = os.getenv('ENVIRONMENT', 'development') == 'development'

# Configurar límites más permisivos en desarrollo
if IS_DEVELOPMENT:
    # Desarrollo: límites generosos para testing
    DEFAULT_RATE_LIMIT = "100/minute"
    AUTH_RATE_LIMIT = "20/minute"  # Login y registro
    ADMIN_RATE_LIMIT = "50/minute"
    PUBLIC_RATE_LIMIT = "200/minute"  # Endpoints públicos
else:
    # Producción: límites estrictos
    DEFAULT_RATE_LIMIT = "30/minute"
    AUTH_RATE_LIMIT = "5/minute"  # Login y registro (crítico)
    ADMIN_RATE_LIMIT = "20/minute"
    PUBLIC_RATE_LIMIT = "60/minute"  # Endpoints públicos

# Inicializar el limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[DEFAULT_RATE_LIMIT],
    storage_uri="memory://",  # Usar memoria (para producción considera Redis)
    strategy="fixed-window",  # Estrategia de ventana fija
    headers_enabled=False  # Deshabilitar inyección automática de headers para evitar conflictos
)

# Handler personalizado para errores de rate limit
def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Maneja errores cuando se excede el rate limit
    Retorna un mensaje claro al usuario
    """
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "Demasiadas solicitudes",
            "detail": "Has excedido el límite de solicitudes. Por favor, espera un momento e intenta nuevamente.",
            "retry_after": f"{exc.detail}"
        },
        headers={
            "Retry-After": str(60)  # Sugerir reintentar después de 60 segundos
        }
    )

# Decoradores comunes para facilitar el uso
def limit_auth():
    """Rate limit para endpoints de autenticación (login, registro)"""
    return limiter.limit(AUTH_RATE_LIMIT)

def limit_admin():
    """Rate limit para endpoints administrativos"""
    return limiter.limit(ADMIN_RATE_LIMIT)

def limit_public():
    """Rate limit para endpoints públicos"""
    return limiter.limit(PUBLIC_RATE_LIMIT)

def limit_default():
    """Rate limit por defecto"""
    return limiter.limit(DEFAULT_RATE_LIMIT)
