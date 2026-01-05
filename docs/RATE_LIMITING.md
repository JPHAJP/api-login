# ✅ Rate Limiting Implementado

## 🎯 Lo que hemos logrado

Se ha implementado **Rate Limiting** completo para proteger tu API contra ataques de fuerza bruta y abuso de endpoints.

## 📦 Instalación

```bash
pip install slowapi
```

## 🛡️ Protecciones Implementadas

### 1. **Endpoints de Autenticación** (Crítico)
- **Login**: 5 intentos/minuto (producción), 20/minuto (desarrollo)
- **Registro**: 5 intentos/minuto (producción), 20/minuto (desarrollo)
- **Refresh Token**: 5 intentos/minuto (producción), 20/minuto (desarrollo)

**Protege contra:** Ataques de fuerza bruta, creación masiva de cuentas

### 2. **Endpoints Públicos**
- **Health Check**: 60/minuto (producción), 200/minuto (desarrollo)
- **QR Público**: 60/minuto (producción), 200/minuto (desarrollo)

**Protege contra:** Abuso de recursos públicos, DDoS

### 3. **Endpoints Administrativos**
- **Gestión de usuarios**: 20/minuto (producción), 50/minuto (desarrollo)
- **Autorización**: 20/minuto (producción), 50/minuto (desarrollo)

**Protege contra:** Abuso de funciones administrativas

### 4. **Endpoints de Usuario** (Por defecto)
- **General**: 30/minuto (producción), 100/minuto (desarrollo)

## 📁 Archivos Creados/Modificados

### Nuevos:
- ✅ `utils/rate_limit.py` - Configuración centralizada
- ✅ `test_rate_limit.py` - Script de pruebas

### Modificados:
- ✅ `main.py` - Integración de rate limiting
- ✅ `routes/auth.py` - Rate limit en login/registro
- ✅ `routes/admin.py` - Rate limit en endpoints admin
- ✅ `requirements.txt` - Nuevas dependencias

## 🔧 Configuración

### Variables de Entorno

El rate limiting se ajusta automáticamente según el entorno:

```bash
# En .env
ENVIRONMENT=development  # o 'production'
```

### Límites por Entorno

| Endpoint | Desarrollo | Producción |
|----------|------------|------------|
| Login/Registro | 20/min | 5/min |
| Endpoints Públicos | 200/min | 60/min |
| Endpoints Admin | 50/min | 20/min |
| General (defecto) | 100/min | 30/min |

## 🧪 Probar Rate Limiting

### 1. Iniciar el servidor
```bash
uvicorn main:app --reload
```

### 2. Ejecutar pruebas automáticas
```bash
python test_rate_limit.py
```

Verás:
- ✅ Verificación de headers
- ✅ Prueba de límite en endpoint público
- ✅ Prueba de protección en login

### 3. Prueba manual con curl

```bash
# Probar endpoint público
for i in {1..70}; do 
  curl -s http://localhost:8000/health | jq '.status' 2>/dev/null || echo "Rate Limited"
  sleep 0.1
done

# Probar login (intentos fallidos)
for i in {1..10}; do
  curl -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    | jq '.detail' 2>/dev/null || echo "Rate Limited"
  sleep 0.5
done
```

## 📊 Headers de Rate Limiting

Cada respuesta incluye headers informativos:

```
X-RateLimit-Limit: 60        # Límite total
X-RateLimit-Remaining: 45    # Solicitudes restantes
X-RateLimit-Reset: 1736012400 # Timestamp de reset
```

Cuando se excede el límite:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

## 🔍 Respuesta de Rate Limit Excedido

```json
{
  "error": "Demasiadas solicitudes",
  "detail": "Has excedido el límite de solicitudes. Por favor, espera un momento e intenta nuevamente.",
  "retry_after": "60"
}
```

## ⚙️ Personalización

### Cambiar límites

Edita `utils/rate_limit.py`:

```python
# Ejemplo: Cambiar límite de login
if IS_DEVELOPMENT:
    AUTH_RATE_LIMIT = "30/minute"  # Aumentar para desarrollo
else:
    AUTH_RATE_LIMIT = "3/minute"   # Más estricto en producción
```

### Agregar rate limiting a nuevos endpoints

```python
from utils.rate_limit import limit_auth, limit_admin, limit_public

@router.post("/mi-endpoint")
@limit_auth()  # o limit_admin() o limit_public()
async def mi_endpoint(request: Request):
    # Tu código aquí
    pass
```

## 🚀 Mejoras Futuras (Opcional)

### 1. **Redis para Producción** (Recomendado)

Para aplicaciones en múltiples servidores:

```bash
pip install redis
```

En `utils/rate_limit.py`:
```python
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",  # Usar Redis
    strategy="fixed-window"
)
```

### 2. **Rate Limiting por Usuario**

Además de por IP:

```python
from slowapi.util import get_remote_address

def rate_limit_key(request: Request):
    # Por IP
    ip = get_remote_address(request)
    
    # Intentar obtener usuario del token
    auth_header = request.headers.get('Authorization')
    if auth_header:
        # Extraer ID de usuario del token
        user_id = extract_user_from_token(auth_header)
        return f"user:{user_id}"
    
    return f"ip:{ip}"

limiter = Limiter(key_func=rate_limit_key)
```

### 3. **Whitelist de IPs**

Para excluir IPs confiables:

```python
WHITELISTED_IPS = ["127.0.0.1", "192.168.1.100"]

def rate_limit_key(request: Request):
    ip = get_remote_address(request)
    if ip in WHITELISTED_IPS:
        return None  # Sin límite
    return ip
```

## 📈 Monitoreo

### Ver límites actuales

```bash
curl -I http://localhost:8000/health
```

Revisa headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
```

### Logs de Rate Limiting

Los eventos de rate limit se registran automáticamente.
Considera agregar logging personalizado en el handler.

## ✅ Checklist de Implementación

- [x] Instalar slowapi
- [x] Crear módulo de rate limiting
- [x] Integrar en main.py
- [x] Aplicar a endpoints de autenticación
- [x] Aplicar a endpoints públicos
- [x] Aplicar a endpoints administrativos
- [x] Crear script de pruebas
- [x] Documentar implementación
- [ ] Probar en servidor de desarrollo
- [ ] Probar límites en producción
- [ ] Considerar migrar a Redis (producción)

## 🎯 Próxima Mejora de Seguridad

¿Quieres continuar con:

**C)** 🔐 **Validación de Contraseñas Fuerte** (20 min) - Siguiente recomendado  
**D)** 🔒 **Headers de Seguridad** (15 min)  
**E)** 📝 **Logging de Seguridad** (45 min)  

---

**⏱️ Tiempo invertido:** ~30 minutos  
**✨ Resultado:** API protegida contra ataques de fuerza bruta y abuso
