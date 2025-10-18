# 🎉 API FastAPI - Lista para Usar

## ✅ Estado: Migración Completada y Funcional

Tu API ha sido migrada exitosamente de Flask a FastAPI y está **100% funcional** con las dependencias instaladas.

## 🚀 Inicio Rápido

### 1. La API ya está lista, solo inicia el servidor:

```bash
# Opción 1: Script personalizado
python3 start_server.py

# Opción 2: Uvicorn directo  
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Accede a la API:
- **API**: http://localhost:8000  
- **Documentación interactiva**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 3. Crear usuario administrador:
```bash
python3 create_admin.py
```

## 📦 Dependencias Instaladas

✅ **FastAPI** - Framework web moderno  
✅ **Uvicorn** - Servidor ASGI  
✅ **SQLAlchemy** - ORM para base de datos  
✅ **Pydantic** - Validación de datos  
✅ **Passlib + Bcrypt** - Hash de contraseñas  
✅ **Python-JOSE** - JWT tokens  
✅ **Email-validator** - Validación de emails  
✅ **Python-multipart** - Subida de archivos  
✅ **Werkzeug** - Utilidades (secure_filename)  
✅ **Requests** - Cliente HTTP para testing  
✅ **Python-dotenv** - Variables de entorno  

## 🔧 Configuración

El archivo `.env` ya existe con configuración básica:
```env
DATABASE_URL=sqlite:///./site.db
JWT_SECRET_KEY=dev-secret-key-change-in-production
ACCESS_TOKEN_EXPIRES=15
REFRESH_TOKEN_EXPIRES_DAYS=7
```

## 📊 Endpoints Disponibles

### Públicos
- `GET /health` - Estado de la API
- `POST /auth/register` - Registro (multipart/form-data)
- `POST /auth/login` - Login
- `POST /auth/refresh` - Renovar token

### Protegidos (requiere JWT)
- `GET /profile` - Perfil del usuario

### Administrativos (requiere rol admin)
- `GET /admin/users/pending` - Usuarios pendientes
- `POST /admin/users/{id}/authorize` - Autorizar usuario
- `POST /admin/users/{id}/reject` - Rechazar usuario  
- `GET /admin/users/{id}/identification` - Ver foto ID
- `GET /admin/stats` - Estadísticas

## 🧪 Probar la API

```bash
# Probar endpoint health
curl http://localhost:8000/health

# Ver documentación interactiva
# Abre http://localhost:8000/docs en tu navegador
```

## 🔐 Autenticación

La API usa JWT Bearer tokens:
```http
Authorization: Bearer <access_token>
```

## 📁 Estructura del Proyecto

```
api-login/
├── main.py              # ✅ Aplicación FastAPI
├── models.py            # ✅ Modelos SQLAlchemy  
├── schemas.py           # ✅ Validación Pydantic
├── database.py          # ✅ Configuración BD
├── config.py            # ✅ Configuración
├── create_admin.py      # ✅ Script crear admin
├── start_server.py      # ✅ Iniciar servidor
├── requirements.txt     # ✅ Dependencias actualizadas
├── .env                 # ✅ Variables de entorno
└── data/identificaciones/ # ✅ Directorio uploads
```

## 🎯 Diferencias vs Flask

| Aspecto | Flask | FastAPI |
|---------|-------|---------|
| Performance | Bueno | **Excelente** |
| Documentación | Manual | **Automática** |
| Validación | Manual | **Automática** |
| Type Hints | Opcional | **Integrado** |
| Async Support | No | **Sí** |
| Testing | Básico | **Avanzado** |

## 🔄 Migración Completa

✅ **Framework**: Flask → FastAPI  
✅ **ORM**: Flask-SQLAlchemy → SQLAlchemy puro  
✅ **Validación**: Manual → Pydantic automática  
✅ **JWT**: Flask-JWT-Extended → python-jose  
✅ **Passwords**: Werkzeug → Passlib + bcrypt  
✅ **CORS**: Flask-CORS → FastAPI middleware  
✅ **Docs**: Sin documentación → OpenAPI automática  
✅ **Endpoints**: Todos migrados y funcionales  
✅ **Base de datos**: Nueva BD (como solicitaste)  
✅ **Archivos**: Sistema de uploads mantenido  

---
*API migrada de Flask a FastAPI v2.0 - Octubre 2025*