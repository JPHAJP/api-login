# 🚀 Inicio Rápido - Nueva Ruta Pública de QR

## ¿Qué cambió?

Ahora puedes obtener el código QR **sin necesidad de autenticación** mediante un endpoint público.

---

## 📍 Nuevo Endpoint

```
GET http://localhost:8000/public/qr/current
```

**✨ No requiere token de autenticación**

---

## 🏃‍♂️ Prueba Rápida

### 1. Iniciar el servidor

```bash
cd /home/jpha/Documents/jp_services/api-login
python main.py
```

O con uvicorn:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Probar con curl

```bash
# Obtener el QR
curl http://localhost:8000/public/qr/current

# Con formato bonito
curl http://localhost:8000/public/qr/current | jq
```

### 3. Ver en el navegador

Visita la documentación interactiva:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

Busca la sección **"Públicas"** en el menú lateral.

### 4. Usar la interfaz HTML

Abre en tu navegador:
```bash
firefox /home/jpha/Documents/jp_services/api-login/qr_display.html
```

O inicia un servidor local:
```bash
cd /home/jpha/Documents/jp_services/api-login
python -m http.server 8080
# Luego visita: http://localhost:8080/qr_display.html
```

### 5. Ejecutar pruebas automáticas

```bash
cd /home/jpha/Documents/jp_services/api-login
python test_qr_public.py
```

---

## 📖 Ejemplo de Uso en JavaScript

```javascript
// Obtener el QR
fetch('http://localhost:8000/public/qr/current')
  .then(response => response.json())
  .then(data => {
    console.log('Código QR:', data.code);
    console.log('Expira en:', data.expires_at);
    
    // Mostrar imagen
    const img = document.createElement('img');
    img.src = `data:image/png;base64,${data.qr_image}`;
    document.body.appendChild(img);
  });
```

---

## 📖 Ejemplo de Uso en Python

```python
import requests

# Obtener el QR
response = requests.get('http://localhost:8000/public/qr/current')
data = response.json()

print(f"Código: {data['code']}")
print(f"Expira: {data['expires_at']}")
print(f"Imagen base64: {data['qr_image'][:50]}...")
```

---

## 🔐 Seguridad

| Acción | ¿Requiere Auth? | ¿Quién puede? |
|--------|-----------------|---------------|
| **Ver QR** | ❌ No | Cualquiera |
| **Escanear QR** | ✅ Sí | Usuarios autorizados |
| **Gestionar usuarios** | ✅ Sí | Solo administradores |

---

## 📄 Respuesta del Endpoint

```json
{
  "qr_image": "iVBORw0KGgoAAAANSUhEUgAA...",
  "code": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...",
  "expires_at": "2026-01-03T23:00:00"
}
```

- **qr_image**: Imagen PNG en formato base64
- **code**: Código único del QR (SHA256)
- **expires_at**: Timestamp de expiración (5 minutos)

---

## 🎨 Archivos Nuevos Creados

1. **`README_QR_PUBLIC.md`** - Documentación completa
2. **`CHANGELOG_QR_PUBLIC.md`** - Resumen de cambios
3. **`qr_display.html`** - Página de demostración
4. **`test_qr_public.py`** - Script de pruebas
5. **`QUICKSTART.md`** - Este archivo

---

## 📝 Archivos Modificados

1. **`main.py`**
   - ✅ Nuevo endpoint público `/qr/current`
   - ✅ Tags de OpenAPI configurados
   - ✅ Importaciones actualizadas

2. **`routes/user.py`**
   - ✅ Documentación mejorada en todos los endpoints
   - ✅ Descripciones detalladas
   - ✅ Nota sobre endpoint público en ruta de admin

---

## ⚙️ Configuración CORS

Si necesitas acceder desde otro dominio, edita `main.py`:

```python
allowed_origins = [
    'http://localhost:3000',    # React
    'http://localhost:5173',    # Vite
    'https://tu-dominio.com',   # Tu dominio
]
```

---

## 🔧 Variables de Entorno

Asegúrate de tener configurado en `.env`:

```env
QR_ACCESS_SECRET=tu-secreto-seguro-aqui
```

---

## 📚 Más Información

- Ver **`README_QR_PUBLIC.md`** para documentación completa
- Ver **`CHANGELOG_QR_PUBLIC.md`** para detalles técnicos
- Visitar http://localhost:8000/docs para documentación interactiva

---

## ✅ Checklist Rápido

- [ ] Servidor ejecutándose
- [ ] Probar con curl: `curl http://localhost:8000/public/qr/current`
- [ ] Ver documentación: http://localhost:8000/docs
- [ ] Probar interfaz HTML: `qr_display.html`
- [ ] Ejecutar tests: `python test_qr_public.py`

---

## 🆘 Solución de Problemas

### Error de conexión
```bash
# Verificar que el servidor esté corriendo
curl http://localhost:8000/health
```

### CORS error
- Añade tu dominio a `allowed_origins` en `main.py`

### Módulo no encontrado
```bash
# Instalar dependencias
pip install -r requirements.txt
```

---

**¡Listo para usar! 🎉**

Para cualquier duda, consulta la documentación completa en `README_QR_PUBLIC.md`
