# 🚀 Integración con Google Drive - Resumen de Cambios

## 📋 Cambios Implementados

### ✅ 1. Nuevo Módulo de Google Drive
- **Archivo**: `utils/google_drive.py`
- **Funcionalidades**:
  - Autenticación OAuth 2.0 y Service Account
  - Subida de archivos a Google Drive
  - Descarga de archivos desde Google Drive
  - Eliminación de archivos
  - Creación de carpetas
  - Gestión de permisos

### ✅ 2. Migración de Base de Datos
- **Archivo**: `utils/migrate_drive_field.py`
- **Cambios**: Agregado campo `foto_identificacion_drive_id` a la tabla `users`
- **Compatibilidad**: Mantiene el campo `foto_identificacion_path` existente

### ✅ 3. Endpoints de Gestión de Imágenes
- **Archivo**: `routes/images.py`
- **Nuevos Endpoints**:
  - `GET /images/identification/{user_id}` - Descargar imagen
  - `GET /images/identification/{user_id}/info` - Info de imagen
  - `DELETE /images/identification/{user_id}` - Eliminar imagen

### ✅ 4. Modificación del Registro de Usuarios
- **Archivo**: `routes/auth.py`
- **Cambios**: 
  - Integración con Google Drive al registrar usuarios
  - Sistema híbrido (local/Drive según configuración)
  - Manejo de errores mejorado

### ✅ 5. Configuración Actualizada
- **Archivo**: `config.py`
- **Nuevas Variables**:
  ```env
  GOOGLE_DRIVE_ENABLED=true/false
  GOOGLE_CREDENTIALS_PATH=credentials.json
  GOOGLE_TOKEN_PATH=token.json
  GOOGLE_SERVICE_ACCOUNT_PATH=service-account-key.json
  GOOGLE_DRIVE_FOLDER_ID=carpeta_específica_id
  ```

### ✅ 6. Utilidades de Migración
- **Archivo**: `utils/migrate_to_drive.py`
- **Funcionalidades**:
  - Migrar archivos locales existentes a Google Drive
  - Verificar estado de migración
  - Reportes detallados de progreso

### ✅ 7. Sistema de Pruebas
- **Archivo**: `utils/test_google_drive.py`
- **Funcionalidades**:
  - Verificar conexión con Google Drive
  - Probar subida/descarga de archivos
  - Validar configuración completa

### ✅ 8. Documentación Completa
- **Archivo**: `docs/GOOGLE_DRIVE_SETUP.md`
- **Contenido**:
  - Guía paso a paso de configuración
  - Troubleshooting
  - Configuración OAuth vs Service Account
  - Mejores prácticas de seguridad

## 🔧 Configuración Necesaria

### 1. Variables de Entorno
Copiar `.env.example` a `.env` y configurar:

```env
# Habilitar Google Drive
GOOGLE_DRIVE_ENABLED=true

# Para desarrollo (OAuth)
GOOGLE_CREDENTIALS_PATH=credentials.json
GOOGLE_TOKEN_PATH=token.json

# Para producción (Service Account) - RECOMENDADO
GOOGLE_SERVICE_ACCOUNT_PATH=service-account-key.json

# Carpeta específica (opcional)
GOOGLE_DRIVE_FOLDER_ID=1ABC123def456GHI789jkl
```

### 2. Credenciales de Google
- **Desarrollo**: Descargar `credentials.json` desde Google Cloud Console
- **Producción**: Crear Service Account y descargar `service-account-key.json`

### 3. Migración de Base de Datos
```bash
python utils/migrate_drive_field.py
```

### 4. Migración de Archivos (Opcional)
```bash
# Si ya tienes imágenes locales
python utils/migrate_to_drive.py
```

## 🧪 Pruebas y Validación

### 1. Probar Configuración
```bash
python utils/test_google_drive.py
```

### 2. Verificar Migración
```bash
python utils/migrate_to_drive.py verify
```

### 3. Probar API
```bash
# Iniciar servidor
python main.py

# Probar registro con imagen
curl -X POST "http://localhost:8000/auth/register" \
  -F "email=test@example.com" \
  -F "password=test123456" \
  -F "nombre_completo=Test" \
  -F "apellidos=User" \
  -F "direccion=Test Address" \
  -F "edad=25" \
  -F "telefono=1234567890" \
  -F "role=voluntarios" \
  -F "foto_identificacion=@/path/to/image.jpg"
```

## 💡 Beneficios de la Integración

### 🔒 Seguridad
- Las imágenes no son públicas por defecto
- Control de acceso granular
- Respaldo automático en la nube

### ⚡ Rendimiento
- Sin límites de almacenamiento local
- CDN global de Google
- Descargas optimizadas

### 🔧 Escalabilidad
- Soporte para millones de archivos
- Sin preocupación por espacio en disco
- Fácil gestión desde Google Drive

### 🛠️ Mantenimiento
- Sistema híbrido (local/Drive)
- Migración gradual posible
- Fallback automático

## 🚨 Consideraciones Importantes

### 1. Compatibilidad Hacia Atrás
- ✅ Los archivos locales existentes siguen funcionando
- ✅ Migración gradual opcional
- ✅ Sistema híbrido configurable

### 2. Rendimiento
- Primera autenticación OAuth puede requerir navegador
- Service Account recomendado para producción
- Cacheo de tokens automático

### 3. Costos
- Google Drive: 15GB gratuitos, luego pago por uso
- APIs de Google: Gratuitas hasta límites generosos

### 4. Seguridad
- Credenciales nunca incluir en repositorio git
- Service Account más seguro que OAuth para producción
- Permisos mínimos recomendados

## 📞 Soporte y Troubleshooting

### Problemas Comunes:

1. **Error de credenciales**
   ```bash
   python utils/test_google_drive.py
   ```

2. **Archivos no aparecen en Drive**
   - Verificar `GOOGLE_DRIVE_FOLDER_ID`
   - Verificar permisos de Service Account

3. **Token expirado**
   - Eliminar `token.json` y re-autenticar

4. **Migración fallida**
   ```bash
   python utils/migrate_to_drive.py verify
   ```

### Logs de Debug:
Activar logs detallados agregando al inicio de `main.py`:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 🎉 ¡Integración Completada!

Tu API ahora soporta almacenamiento de imágenes en Google Drive con:
- ✅ Sistema híbrido local/nube
- ✅ Migración automática
- ✅ Pruebas completas
- ✅ Documentación detallada
- ✅ Compatibilidad total

**Próximos pasos:**
1. Configurar credenciales de Google Drive
2. Ejecutar `python utils/test_google_drive.py`
3. Migrar archivos existentes si los hay
4. ¡Disfrutar del almacenamiento en la nube!

Para cualquier duda, revisa la documentación en `docs/GOOGLE_DRIVE_SETUP.md`