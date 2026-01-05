# 🔒 Headers de Seguridad HTTP

## 📋 Descripción

Middleware que agrega headers de seguridad HTTP a todas las respuestas de la API, protegiendo contra ataques comunes como XSS, clickjacking, MIME sniffing y otros vectores de ataque.

## ✅ Headers Implementados

### 1. **X-Frame-Options: DENY**

**Propósito**: Previene ataques de clickjacking

**Protege contra**:
- Clickjacking: Atacante coloca tu sitio en un iframe invisible y engaña al usuario para que haga clic
- UI Redressing: Superposición de elementos maliciosos sobre tu interfaz

**Valor**: `DENY`
- No permite que la página sea mostrada en ningún frame/iframe
- Alternativas: `SAMEORIGIN` (solo iframes del mismo origen)

**Severidad**: 🔴 HIGH

---

### 2. **X-Content-Type-Options: nosniff**

**Propósito**: Previene MIME type sniffing

**Protege contra**:
- MIME confusion attacks: Navegador interpreta archivo como tipo diferente
- Ejecución de JavaScript disfrazado como imagen o texto

**Valor**: `nosniff`
- Fuerza al navegador a respetar el Content-Type declarado
- No intenta adivinar el tipo de contenido

**Severidad**: 🔴 HIGH

---

### 3. **X-XSS-Protection: 1; mode=block**

**Propósito**: Protección XSS del navegador

**Protege contra**:
- Cross-Site Scripting (XSS) reflejado
- Inyección de scripts maliciosos

**Valor**: `1; mode=block`
- `1`: Habilita el filtro XSS
- `mode=block`: Bloquea completamente la página si detecta XSS

**Nota**: Header legacy, pero útil para navegadores antiguos

**Severidad**: 🟡 MEDIUM

---

### 4. **Content-Security-Policy (CSP)**

**Propósito**: Política de seguridad de contenido - La defensa más poderosa contra XSS

**Protege contra**:
- XSS (Cross-Site Scripting)
- Inyección de datos
- Ataques de código malicioso

#### Configuración de Desarrollo:
```
default-src 'self';
script-src 'self' 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https: http:;
font-src 'self' data:;
connect-src 'self' http://localhost:* http://127.0.0.1:*;
frame-ancestors 'none';
base-uri 'self';
form-action 'self'
```

#### Configuración de Producción:
```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
upgrade-insecure-requests
```

**Directivas principales**:
- `default-src 'self'`: Por defecto, solo contenido del mismo origen
- `script-src`: Control de scripts (elimina `unsafe-inline`/`unsafe-eval` en prod)
- `frame-ancestors 'none'`: Refuerza X-Frame-Options
- `upgrade-insecure-requests`: Actualiza HTTP a HTTPS automáticamente (solo prod)

**Severidad**: 🔴 HIGH

---

### 5. **Strict-Transport-Security (HSTS)** 🏭 Solo Producción

**Propósito**: Fuerza el uso de HTTPS

**Protege contra**:
- Man-in-the-Middle (MITM) attacks
- Protocol downgrade attacks
- Cookie hijacking

**Valor**: `max-age=31536000; includeSubDomains; preload`
- `max-age=31536000`: 1 año (en segundos)
- `includeSubDomains`: Aplica a todos los subdominios
- `preload`: Elegible para lista HSTS preload de navegadores

**⚠️ IMPORTANTE**: Solo se agrega en producción (ENVIRONMENT=production)

**Severidad**: 🔴 CRITICAL (en producción)

---

### 6. **Referrer-Policy: strict-origin-when-cross-origin**

**Propósito**: Controla qué información de referrer se envía

**Protege contra**:
- Fuga de información en URLs
- Exposición de tokens en query strings

**Valor**: `strict-origin-when-cross-origin`
- Same-origin: Envía URL completa
- Cross-origin: Solo envía el origen (https://example.com)
- Downgrade (HTTPS→HTTP): No envía referrer

**Severidad**: 🟡 MEDIUM

---

### 7. **Permissions-Policy**

**Propósito**: Control de APIs y features del navegador

**Protege contra**:
- Uso no autorizado de features sensibles
- Acceso a hardware (cámara, micrófono, GPS)

**Valor**: 
```
geolocation=(), microphone=(), camera=(), 
payment=(), usb=(), magnetometer=(), 
gyroscope=(), accelerometer=()
```

**Deshabilita**:
- 📍 Geolocalización
- 🎤 Micrófono
- 📷 Cámara
- 💳 Payment API
- 🔌 USB
- 🧭 Sensores de movimiento

**Severidad**: 🟡 MEDIUM

---

### 8. **Cache-Control** (Condicional)

**Propósito**: Control de caché para endpoints sensibles

**Protege contra**:
- Exposición de datos sensibles en caché
- Información almacenada en navegador/proxy

**Valor** (para endpoints `/auth/`, `/admin/`, `/user/`):
```
no-store, no-cache, must-revalidate, private
```

**Headers adicionales**:
- `Pragma: no-cache`
- `Expires: 0`

**Severidad**: 🟡 MEDIUM

---

## 🛠️ Implementación

### Estructura de Archivos

```
utils/
  └── security_headers.py    # Middleware de security headers
main.py                       # Integración del middleware
test_security_headers.py      # Tests automatizados
```

### Uso en FastAPI

```python
from utils.security_headers import get_security_headers_middleware

# Agregar middleware (ANTES de CORS)
app.add_middleware(get_security_headers_middleware())
```

### Configuración por Ambiente

El middleware se configura automáticamente según `ENVIRONMENT`:

```bash
# Desarrollo (default)
ENVIRONMENT=development

# Producción
ENVIRONMENT=production
```

**Diferencias**:

| Feature | Development | Production |
|---------|-------------|------------|
| HSTS | ❌ Deshabilitado | ✅ Habilitado |
| CSP `unsafe-inline` scripts | ✅ Permitido | ❌ Bloqueado |
| CSP `unsafe-eval` | ✅ Permitido | ❌ Bloqueado |
| CSP HTTP images | ✅ Permitido | ❌ Solo HTTPS |
| CSP `upgrade-insecure-requests` | ❌ No | ✅ Sí |
| API local (localhost) | ✅ Permitida | ❌ Bloqueada |

---

## 🧪 Testing

### Ejecutar Tests

```bash
# Test completo de security headers
python test_security_headers.py
```

### Verificar Headers Manualmente

```bash
# Con curl
curl -v http://127.0.0.1:8000/health 2>&1 | grep -i "< "

# Con httpie
http GET http://127.0.0.1:8000/health
```

### Ejemplo de Salida (Test)

```
================================================================================
🔒 TEST DE SECURITY HEADERS
================================================================================

Testing: Health Check (Público)
URL: http://127.0.0.1:8000/health
--------------------------------------------------------------------------------
✓ PASS [HIGH] X-Frame-Options
     Previene clickjacking - No permite iframes
     Valor correcto
✓ PASS [HIGH] X-Content-Type-Options
     Previene MIME sniffing - Respeta Content-Type
     Valor correcto
✓ PASS [MEDIUM] X-XSS-Protection
     Protección XSS del navegador
     Valor correcto
✓ PASS [HIGH] Content-Security-Policy
     Política de seguridad de contenido - Previene XSS
     Presente y contiene 'default-src 'self''
✓ PASS [MEDIUM] Referrer-Policy
     Control de información del referrer
     Valor correcto
✓ PASS [MEDIUM] Permissions-Policy
     Control de APIs del navegador
     Presente y contiene 'geolocation=(), microphone=(), camera=()'

================================================================================
📊 RESUMEN GENERAL
================================================================================

Endpoints probados: 3
Headers verificados: 18
✓ Pasados: 18
✗ Fallados: 0
✗ Faltantes: 0

Puntuación de Seguridad: 100.0%
🎉 ¡Excelente! Los headers de seguridad están correctamente configurados
```

---

## 📊 Herramientas de Análisis

### Online Security Scanners

1. **[Security Headers](https://securityheaders.com/)**
   - Escanea tu sitio y da una calificación A-F
   - Recomendaciones específicas

2. **[Mozilla Observatory](https://observatory.mozilla.org/)**
   - Análisis completo de seguridad
   - Incluye SSL/TLS, headers, y más

3. **[OWASP ZAP](https://www.zaproxy.org/)**
   - Scanner de seguridad completo
   - Detecta vulnerabilidades

### Browser DevTools

```
1. Abre DevTools (F12)
2. Ve a Network tab
3. Haz una request
4. Ve a Headers
5. Busca "Response Headers"
```

---

## 🎯 Puntuación de Seguridad

### Objetivo: **100% (A+)**

| Puntuación | Calificación | Estado |
|------------|--------------|--------|
| 90-100% | A+ | 🎉 Excelente |
| 80-89% | A | ✅ Muy bueno |
| 70-79% | B | ⚠️ Bueno |
| 60-69% | C | ⚠️ Aceptable |
| <60% | F | ❌ Necesita mejoras |

---

## 🚀 Despliegue en Producción

### Checklist Pre-Producción

- [ ] Configurar `ENVIRONMENT=production` en .env
- [ ] Verificar certificado SSL/TLS válido
- [ ] Probar todos los endpoints con headers de producción
- [ ] Verificar que CSP no bloquea funcionalidad
- [ ] Agregar dominio a HSTS preload (opcional pero recomendado)
- [ ] Configurar Content-Type correcto para assets
- [ ] Revisar CORS para dominios de producción

### HSTS Preload

Para máxima seguridad, agrega tu dominio a la lista HSTS preload:

1. Cumple los requisitos:
   - HSTS con `max-age` >= 31536000 (1 año)
   - Directiva `includeSubDomains`
   - Directiva `preload`
   - Redirige HTTP a HTTPS
   - Todos los subdominios sirven HTTPS válido

2. Envía a: https://hstspreload.org/

**⚠️ ADVERTENCIA**: Esto es (casi) irreversible. Asegúrate de estar listo.

---

## 📚 Referencias y Recursos

### Documentación Oficial

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Content Security Policy Reference](https://content-security-policy.com/)

### Estándares

- [RFC 7034 - X-Frame-Options](https://tools.ietf.org/html/rfc7034)
- [RFC 6797 - HSTS](https://tools.ietf.org/html/rfc6797)
- [W3C CSP Level 3](https://www.w3.org/TR/CSP3/)

### Guías

- [Google Web Fundamentals - Security](https://developers.google.com/web/fundamentals/security)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---

## 🔧 Troubleshooting

### Headers no aparecen

**Problema**: Los headers de seguridad no están en las respuestas

**Soluciones**:
1. Reinicia el servidor uvicorn
2. Verifica que el middleware esté registrado ANTES de CORS
3. Comprueba que no haya errores en los logs

```bash
# Reiniciar servidor
pkill -f uvicorn
uvicorn main:app --reload
```

### CSP bloquea recursos

**Problema**: Content-Security-Policy bloquea CSS/JS/imágenes

**Soluciones**:
1. En desarrollo: Headers ya son permisivos
2. En producción: Ajusta las directivas según tus necesidades
3. Revisa console del navegador para ver qué está bloqueado
4. Agrega dominios específicos a las directivas

```python
# Ejemplo: Permitir CDN externo
csp = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.example.com; "
    "style-src 'self' https://cdn.example.com; "
    # ...
)
```

### HSTS causa problemas

**Problema**: No puedes acceder al sitio después de habilitar HSTS

**Soluciones**:
1. Solo habilita HSTS cuando tengas SSL/TLS funcionando
2. Empieza con `max-age` corto para probar (300 = 5 minutos)
3. Limpia HSTS del navegador:
   - Chrome: chrome://net-internals/#hsts
   - Firefox: about:preferences#privacy → Clear Data

---

## ⏱️ Tiempo de Implementación

**Total: ~15 minutos** ✅

- Creación del middleware: 5 min
- Integración en FastAPI: 2 min
- Testing y validación: 5 min
- Documentación: 3 min

---

## 📈 Impacto en Seguridad

### Antes
- ❌ Sin protección contra clickjacking
- ❌ Sin protección contra XSS
- ❌ Sin control de caché
- ❌ Vulnerable a MIME sniffing
- 🔴 **Puntuación: 0%**

### Después
- ✅ Protección completa contra clickjacking
- ✅ Múltiples capas contra XSS
- ✅ Control de caché en endpoints sensibles
- ✅ MIME type enforcement
- ✅ Control de features del navegador
- 🟢 **Puntuación: 100%**

---

**Estado**: ✅ Implementado
**Fecha**: Enero 2026
**Versión**: 1.0.0
