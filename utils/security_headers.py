"""
Security Headers Middleware
============================

Middleware para agregar headers de seguridad HTTP a todas las respuestas.
Protege contra ataques comunes como XSS, clickjacking, MIME sniffing, etc.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from typing import Callable
import os


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware que agrega headers de seguridad a todas las respuestas HTTP.
    
    Headers implementados:
    - X-Frame-Options: Previene clickjacking
    - X-Content-Type-Options: Previene MIME sniffing
    - X-XSS-Protection: Protección XSS del navegador
    - Strict-Transport-Security: Fuerza HTTPS (solo en producción)
    - Content-Security-Policy: Política de seguridad de contenido
    - Referrer-Policy: Control de información del referrer
    - Permissions-Policy: Control de APIs del navegador
    """
    
    def __init__(self, app, environment: str = "development"):
        super().__init__(app)
        self.environment = environment
        self.is_production = environment == "production"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Procesa la request y agrega headers de seguridad a la response
        
        Args:
            request: Request HTTP entrante
            call_next: Siguiente middleware/handler
            
        Returns:
            Response con headers de seguridad agregados
        """
        response = await call_next(request)
        
        # Excepción para documentación de API (Swagger UI y ReDoc)
        is_docs_path = request.url.path in ["/docs", "/redoc", "/openapi.json"]
        
        # 1. X-Frame-Options - Previene clickjacking
        # DENY: No permite que la página sea mostrada en un frame
        response.headers["X-Frame-Options"] = "DENY"
        
        # 2. X-Content-Type-Options - Previene MIME sniffing
        # nosniff: El navegador debe respetar el Content-Type declarado
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # 3. X-XSS-Protection - Protección XSS del navegador
        # 1; mode=block: Habilita filtro XSS y bloquea la página si detecta ataque
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # 4. Strict-Transport-Security (HSTS) - Solo en producción
        # Fuerza que el navegador solo use HTTPS
        if self.is_production:
            # max-age=31536000: 1 año en segundos
            # includeSubDomains: Aplica a todos los subdominios
            # preload: Permite inclusión en lista HSTS preload
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # 5. Content-Security-Policy (CSP) - Previene XSS y otros ataques
        # Excepción para documentación: CSP más permisivo
        if is_docs_path:
            # CSP permisivo para Swagger UI y ReDoc
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "  # Swagger necesita inline
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "  # Swagger necesita inline
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'"
            )
        elif self.is_production:
            # Política estricta para producción
            csp = (
                "default-src 'self'; "  # Solo contenido del mismo origen
                "script-src 'self'; "  # Solo scripts del mismo origen
                "style-src 'self' 'unsafe-inline'; "  # Estilos del mismo origen + inline
                "img-src 'self' data: https:; "  # Imágenes del mismo origen, data URIs y HTTPS
                "font-src 'self'; "  # Fuentes del mismo origen
                "connect-src 'self'; "  # Conexiones API del mismo origen
                "frame-ancestors 'none'; "  # No permite iframes (refuerza X-Frame-Options)
                "base-uri 'self'; "  # Previene inyección de <base>
                "form-action 'self'; "  # Solo formularios al mismo origen
                "upgrade-insecure-requests"  # Actualiza HTTP a HTTPS automáticamente
            )
        else:
            # Política más permisiva para desarrollo
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Permite inline para dev
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https: http:; "  # Permite HTTP en dev
                "font-src 'self' data:; "
                "connect-src 'self' http://localhost:* http://127.0.0.1:*; "  # APIs locales
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        
        response.headers["Content-Security-Policy"] = csp
        
        # 6. Referrer-Policy - Control de información del referrer
        # strict-origin-when-cross-origin: Envía origin solo en cross-origin
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # 7. Permissions-Policy (antes Feature-Policy) - Control de APIs del navegador
        # Deshabilita APIs peligrosas o no necesarias
        permissions = (
            "geolocation=(), "  # No permite geolocalización
            "microphone=(), "  # No permite micrófono
            "camera=(), "  # No permite cámara
            "payment=(), "  # No permite Payment Request API
            "usb=(), "  # No permite acceso USB
            "magnetometer=(), "  # No permite magnetómetro
            "gyroscope=(), "  # No permite giroscopio
            "accelerometer=()"  # No permite acelerómetro
        )
        response.headers["Permissions-Policy"] = permissions
        
        # 8. Cache-Control - Control de caché para endpoints sensibles
        # Si es un endpoint de autenticación o admin, no cachear
        path = request.url.path
        if any(sensitive in path for sensitive in ["/auth/", "/admin/", "/user/"]):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        return response


def get_security_headers_middleware(environment: str = None):
    """
    Factory function para crear el middleware con la configuración correcta
    
    Args:
        environment: Ambiente (development/production). Si None, lee de ENV
        
    Returns:
        Clase del middleware configurada
    """
    if environment is None:
        environment = os.getenv("ENVIRONMENT", "development")
    
    class ConfiguredSecurityHeadersMiddleware(SecurityHeadersMiddleware):
        def __init__(self, app):
            super().__init__(app, environment=environment)
    
    return ConfiguredSecurityHeadersMiddleware


# Headers de seguridad recomendados según OWASP
OWASP_RECOMMENDED_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}


def check_security_headers(headers: dict) -> dict:
    """
    Verifica si los headers de seguridad están presentes
    
    Args:
        headers: Diccionario de headers HTTP
        
    Returns:
        Dict con resultado de la verificación
    """
    results = {
        "total": len(OWASP_RECOMMENDED_HEADERS),
        "present": 0,
        "missing": [],
        "headers": {}
    }
    
    for header_name in OWASP_RECOMMENDED_HEADERS.keys():
        header_value = headers.get(header_name) or headers.get(header_name.lower())
        
        if header_value:
            results["present"] += 1
            results["headers"][header_name] = header_value
        else:
            results["missing"].append(header_name)
    
    results["score"] = (results["present"] / results["total"]) * 100
    
    return results
