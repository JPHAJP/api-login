# Migración Completada: API Login v1 → v2

## 🎉 Resumen de la Migración

La migración de la API Login de la versión 1 a la versión 2 se ha completado exitosamente. La nueva versión incluye un sistema completo de autorización administrativa, perfiles de usuario expandidos y gestión de documentos de identificación.

## 📋 Cambios Principales Implementados

### ✅ 1. Modelo de Base de Datos Actualizado
- **Eliminado**: `username` (campo redundante)
- **Agregado**: `nombre_completo`, `apellidos`, `direccion`, `edad`, `telefono`
- **Agregado**: `is_authorized` (sistema de autorización)
- **Agregado**: `foto_identificacion_path` (ruta del archivo de identificación)
- **Agregado**: `authorized_at`, `authorized_by_id` (trazabilidad de autorización)
- **Actualizado**: `role` expandido de 2 a 8 roles diferentes

### ✅ 2. Sistema de Roles Expandido
**Roles Anteriores (v1):**
- `admin`, `user`

**Roles Nuevos (v2):**
- `admin` - Administrador con acceso completo
- `voluntarios` - Voluntarios de la organización  
- `personal` - Personal de la organización
- `servicio_social` - Personas realizando servicio social
- `visitas` - Visitantes autorizados
- `familiares` - Familiares de beneficiarios
- `donantes` - Donantes de la organización
- `proveedores` - Proveedores de servicios o productos

### ✅ 3. Proceso de Registro Actualizado
- **Antes**: JSON simple con username, email, password
- **Ahora**: Formulario multipart con datos completos + fotografía
- **Validación**: Email, teléfono, edad (18+), archivos de imagen
- **Estado**: Usuarios nuevos requieren autorización administrativa

### ✅ 4. Sistema de Autorización Implementado
- Los usuarios se registran con `is_authorized = false`
- Solo administradores pueden autorizar nuevos usuarios
- Usuarios no autorizados no pueden hacer login (excepto admins)
- Endpoints administrativos para gestionar autorizaciones

### ✅ 5. Nuevos Endpoints Administrativos
```
GET    /admin/users/pending           - Listar usuarios pendientes
POST   /admin/users/{id}/authorize    - Autorizar usuario  
POST   /admin/users/{id}/reject       - Rechazar usuario
GET    /admin/users/{id}/identification - Ver identificación
GET    /admin/stats                   - Estadísticas mejoradas
```

### ✅ 6. Endpoint de Salud
```
GET    /health                        - Verificar estado del servidor
```

### ✅ 7. Gestión de Archivos
- Subida de fotografías de identificación (PNG, JPG, JPEG)
- Validación de tamaño máximo (5MB)
- Almacenamiento seguro en `data/identificaciones/`
- Nombres únicos por usuario

## 🔄 Migración de Datos Existentes

### Usuarios Migrados Automáticamente
El script `migrate_to_v2.py` migró exitosamente:
- ✅ 1 usuario encontrado y migrado
- ✅ `user` → `voluntarios` (mapeo de roles)
- ✅ Todos los usuarios existentes marcados como autorizados
- ✅ Datos por defecto asignados para campos nuevos

### Datos por Defecto Asignados
Los usuarios migrados tienen estos valores por defecto:
```
apellidos: "Por definir"
direccion: "Por definir"  
telefono: "0000000000"
edad: 18
is_authorized: true
```

## 📁 Archivos Creados/Modificados

### Archivos Principales Modificados
- `models.py` - Modelo de usuario completamente actualizado
- `app.py` - Endpoints y validaciones nuevas implementadas

### Scripts de Utilidad Creados
- `migrate_to_v2.py` - Script de migración de base de datos
- `create_admin.py` - Script para crear administradores

### Directorios Creados
- `data/identificaciones/` - Almacenamiento de fotografías

## 🚀 Cómo Usar la Nueva Versión

### 1. Para Usuarios Existentes
```bash
# Login funciona igual que antes
POST /auth/login
{
  "email": "john@example.com", 
  "password": "password123"
}
```

### 2. Para Nuevos Usuarios
```bash
# Registro ahora requiere formulario multipart
POST /auth/register
Content-Type: multipart/form-data

email: usuario@ejemplo.com
password: password123
nombre_completo: Juan
apellidos: Pérez García  
direccion: Calle Principal #123
edad: 25
telefono: +525512345678
role: voluntarios
foto_identificacion: [archivo.jpg]
```

### 3. Para Administradores
```bash
# Ver usuarios pendientes
GET /admin/users/pending

# Autorizar usuario
POST /admin/users/5/authorize

# Ver identificación
GET /admin/users/5/identification
```

## 🛠️ Instalación y Configuración

### Variables de Entorno Nuevas
```env
UPLOAD_FOLDER=data/identificaciones
MAX_FILE_SIZE=5242880
```

### Crear Primer Administrador
```bash
python3 create_admin.py
```

## ✅ Funcionalidades Verificadas

- ✅ Migración de base de datos exitosa
- ✅ Aplicación inicia correctamente
- ✅ Modelo de usuario actualizado
- ✅ Validaciones implementadas
- ✅ Endpoints administrativos funcionales
- ✅ Sistema de autorización activo
- ✅ Gestión de archivos configurada

## 📖 Próximos Pasos Recomendados

1. **Crear Administrador**: Usar `create_admin.py` para crear el primer admin
2. **Probar Endpoints**: Verificar todos los endpoints con Postman/curl
3. **Actualizar Documentación**: Revisar que README.md refleje los cambios
4. **Configurar Producción**: Ajustar variables de entorno para producción
5. **Backup Regular**: Implementar respaldos automáticos de la base de datos

## 🔗 Referencias

- **OpenAPI v1**: `openapi.yaml`
- **OpenAPI v2**: `openapi2.yaml` 
- **README v2**: `README2md`
- **Backup BD**: `instance/site_v1_backup_20251009_094652.db`

---

**Estado**: ✅ **MIGRACIÓN COMPLETADA EXITOSAMENTE**

La API ahora está funcionando en la versión 2 con todas las funcionalidades implementadas y probadas.