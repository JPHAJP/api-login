# Configuración de Google Drive para API Login

Este documento explica cómo configurar Google Drive para almacenar las imágenes de identificación en lugar de guardarlas localmente.

## 🚀 Pasos de Configuración

### 1. Crear un Proyecto en Google Cloud Console

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un nuevo proyecto o selecciona uno existente
3. Habilita la API de Google Drive:
   - Ve a "APIs y servicios" > "Biblioteca"
   - Busca "Google Drive API"
   - Haz clic en "HABILITAR"

### 2. Configurar Credenciales

Tienes dos opciones: **OAuth 2.0** (para desarrollo) o **Service Account** (recomendado para producción).

#### Opción A: OAuth 2.0 (Desarrollo)

1. Ve a "APIs y servicios" > "Credenciales"
2. Haz clic en "CREAR CREDENCIALES" > "ID de cliente de OAuth 2.0"
3. Configura:
   - Tipo de aplicación: "Aplicación de escritorio"
   - Nombre: "API Login - Google Drive"
4. Descarga el archivo JSON y renómbralo como `credentials.json`
5. Colócalo en la carpeta raíz del proyecto

#### Opción B: Service Account (Producción - Recomendado)

1. Ve a "APIs y servicios" > "Credenciales"
2. Haz clic en "CREAR CREDENCIALES" > "Cuenta de servicio"
3. Configura:
   - Nombre: "api-login-drive-service"
   - Descripción: "Service Account para API Login Google Drive"
4. Omite los roles por ahora (paso opcional)
5. En la cuenta de servicio creada, ve a "Claves"
6. Haz clic en "AGREGAR CLAVE" > "Crear clave nueva" > "JSON"
7. Descarga el archivo y renómbralo como `service-account-key.json`
8. Colócalo en la carpeta raíz del proyecto

### 3. Configurar Variables de Entorno

Copia el archivo `.env.example` a `.env` y actualiza las siguientes variables:

```env
# Habilitar Google Drive
GOOGLE_DRIVE_ENABLED=true

# OAuth 2.0 (Desarrollo)
GOOGLE_CREDENTIALS_PATH=credentials.json
GOOGLE_TOKEN_PATH=token.json

# Service Account (Producción)
GOOGLE_SERVICE_ACCOUNT_PATH=service-account-key.json

# Carpeta específica en Drive (opcional)
GOOGLE_DRIVE_FOLDER_ID=1ABC123def456GHI789jkl
```

### 4. (Opcional) Crear Carpeta Específica en Google Drive

Si quieres organizar las imágenes en una carpeta específica:

1. Ve a [Google Drive](https://drive.google.com/)
2. Crea una nueva carpeta (ej: "API-Login-Identificaciones")
3. Comparte la carpeta con la cuenta de servicio (solo si usas Service Account):
   - Clic derecho > Compartir
   - Agrega el email de la cuenta de servicio con permisos de "Editor"
4. Copia el ID de la carpeta de la URL:
   - URL: `https://drive.google.com/drive/folders/1ABC123def456GHI789jkl`
   - ID: `1ABC123def456GHI789jkl`
5. Agrega el ID a tu archivo `.env`:
   ```env
   GOOGLE_DRIVE_FOLDER_ID=1ABC123def456GHI789jkl
   ```

### 5. Ejecutar Migración de Base de Datos

Si es la primera vez que configuras Google Drive:

```bash
python utils/migrate_drive_field.py
```

### 6. (Opcional) Migrar Archivos Existentes

Si ya tienes imágenes guardadas localmente y quieres migrarlas a Google Drive:

```bash
# Verificar estado actual
python utils/migrate_to_drive.py verify

# Ejecutar migración
python utils/migrate_to_drive.py
```

## 🔧 Uso

### Registro de Usuarios

Una vez configurado, los usuarios nuevos que se registren tendrán sus imágenes de identificación guardadas automáticamente en Google Drive.

### Acceso a Imágenes

Los administradores pueden acceder a las imágenes mediante los nuevos endpoints:

- `GET /images/identification/{user_id}` - Descargar imagen
- `GET /images/identification/{user_id}/info` - Obtener información de la imagen
- `DELETE /images/identification/{user_id}` - Eliminar imagen (solo admin)

### Compatibilidad

El sistema mantiene compatibilidad con archivos locales existentes. Si `GOOGLE_DRIVE_ENABLED=false`, seguirá funcionando con el sistema de archivos local.

## 🔐 Seguridad

- Las imágenes en Google Drive no son públicas por defecto
- Solo usuarios autenticados pueden acceder a las imágenes
- Los administradores pueden ver cualquier imagen
- Los usuarios solo pueden ver su propia imagen
- Se recomienda usar Service Account para producción

## 🚨 Troubleshooting

### Error: "Archivo de credenciales no encontrado"
- Verifica que el archivo `credentials.json` o `service-account-key.json` esté en la carpeta correcta
- Verifica las rutas en las variables de entorno

### Error: "Token inválido o expirado"
- Elimina el archivo `token.json` y vuelve a autenticar
- Para Service Account, verifica que el archivo JSON sea válido

### Error: "Permisos insuficientes"
- Verifica que la API de Google Drive esté habilitada
- Para Service Account, verifica que tenga acceso a la carpeta de Drive

### Los archivos no aparecen en Drive
- Verifica que `GOOGLE_DRIVE_FOLDER_ID` sea correcto
- Verifica que la cuenta de servicio tenga permisos sobre la carpeta

## 📞 Soporte

Si encuentras problemas:
1. Verifica los logs de la aplicación
2. Usa `python utils/migrate_to_drive.py verify` para verificar el estado
3. Revisa que todas las variables de entorno estén configuradas correctamente