# API Login - Sistema de Autenticación con Roles y Autorización

Sistema completo de autenticación REST API construido con Flask que proporciona registro de usuarios, sistema de autorización, múltiples roles y autenticación basada en JWT. Los usuarios deben ser autorizados por un administrador antes de poder acceder al sistema.

## Características

- ✅ Registro de usuarios con validación completa de datos personales
- ✅ Sistema de autorización administrativa para nuevos usuarios
- ✅ 8 roles de usuario diferentes con permisos específicos
- ✅ Autenticación JWT con tokens de acceso y refresh
- ✅ Gestión de fotografías de identificación oficial
- ✅ Validación de email, teléfono y datos personales
- ✅ Panel administrativo para aprobar/rechazar usuarios
- ✅ Base de datos SQLite con SQLAlchemy ORM
- ✅ Seguridad con hash de contraseñas
- ✅ Endpoints protegidos por roles

## Stack Tecnológico

- **Framework**: Flask 3.1.2
- **Base de Datos**: SQLite con SQLAlchemy ORM
- **Autenticación**: JWT tokens usando Flask-JWT-Extended
- **Hash de Contraseñas**: Werkzeug security utilities
- **Validación de Email**: email-validator library
- **Manejo de Archivos**: Werkzeug file utilities
- **Variables de Entorno**: python-dotenv

## Roles del Sistema

| Rol              | Descripción                                | Autorización Requerida |
| ---------------- | ------------------------------------------ | ---------------------- |
| `admin`          | Administrador con acceso completo          | No (creado manualmente)|
| `voluntarios`    | Voluntarios de la organización             | Sí                     |
| `personal`       | Personal de la organización                | Sí                     |
| `servicio_social`| Personas realizando servicio social        | Sí                     |
| `visitas`        | Visitantes autorizados                     | Sí                     |
| `familiares`     | Familiares de beneficiarios                | Sí                     |
| `donantes`       | Donantes de la organización                | Sí                     |
| `proveedores`    | Proveedores de servicios o productos       | Sí                     |

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd api-login
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory:

```env
DATABASE_URL=sqlite:///site.db
JWT_SECRET_KEY=tu-clave-super-secreta-aqui-cambiala-en-produccion
ACCESS_TOKEN_EXPIRES=15
REFRESH_TOKEN_EXPIRES_DAYS=7
UPLOAD_FOLDER=data/identificaciones
MAX_FILE_SIZE=5242880
```

5. Create dir:
```bash
mkdir -p data/identificaciones
mkdir -p instance
```

6. Run the application:

```bash
python app.py
```

The API will be available at `http://localhost:8000`

## Environment Variables

| Variable                     | Description                             | Default Value       |
| ---------------------------- | --------------------------------------- | ------------------- |
| `DATABASE_URL`               | Database connection string              | `sqlite:///site.db` |
| `JWT_SECRET_KEY`             | Secret key for JWT token signing        | `super-secret`      |
| `ACCESS_TOKEN_EXPIRES`       | Access token expiration time in minutes | `15`                |
| `REFRESH_TOKEN_EXPIRES_DAYS` | Refresh token expiration time in days   | `7`                 |
| `UPLOAD_FOLDER`              | Carpeta para almacenar identificaciones | `data/identificaciones`|
| `MAX_FILE_SIZE`              | Tamaño máximo de archivo (bytes)        | `5242880` (5MB)     |

## API Endpoints

### Endpoints Públicos

#### Verificar Estado del Servidor
```http
GET /health
```
**Response (200 OK):**
```
{
  "status": "ok",
  "time": "2025-10-09T10:30:00.123456"
}
```

#### Register User

```http
POST /auth/register
Content-Type: multipart/form-data
```
**Parámetros del formulario:**
| Campo               | Tipo    | Requerido   | Descripción                     |
| --------------------|---------|-------------|---------------------------------|
| email               | string  | Sí          | Email válido y único            |
| password            | string  | Sí          | Contraseña (mínimo 6 caracteres)|
| nombre_completo     | string  | Sí          | Nombre(s) del usuario           |
| apellidos           | string  | Sí          | Apellidos del usuario           |
| direccion           | string  | Sí          | Dirección completa              |
| edad                | integer | Sí          | Edad (18+)                      |
| telefono            | string  | Sí          | Teléfono (10 dígitos)           |
| foto_identificacion | file    | Sí          | Imagen JPG/PNG (máx 5MB)        |
| role                | string  | Sí          | Rol solicitado                  |

**Response (201 Created):**

```json
{
  "message": "Usuario registrado exitosamente. Pendiente de autorización por un administrador.",
  "user": {
    "id": 5,
    "email": "juan.perez@example.com",
    "nombre_completo": "Juan",
    "apellidos": "Pérez García",
    "direccion": "Calle Principal #123",
    "edad": 28,
    "telefono": "+525512345678",
    "role": "voluntarios",
    "is_authorized": false,
    "foto_identificacion_path": "/data/identificaciones/user_5_id.jpg",
    "created_at": "2025-10-09T10:30:00.123456",
    "authorized_at": null
  }
}
```

#### Login User

```http
POST /auth/login
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "securepassword123"
}
```

**Response (200 OK):**

```json
{
  "message": "Login exitoso.",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Refresh Token

```http
POST /auth/refresh
Authorization: Bearer <refresh_token>
```

**Response (200 OK):**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Protected Endpoints

#### Get User Profile

```http
GET /profile
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "user": {
    "id": 5,
    "email": "juan.perez@example.com",
    "nombre_completo": "Juan",
    "apellidos": "Pérez García",
    "direccion": "Calle Principal #123",
    "edad": 28,
    "telefono": "+525512345678",
    "role": "voluntarios",
    "is_authorized": true,
    "created_at": "2025-10-09T10:30:00.123456",
    "authorized_at": "2025-10-09T14:20:00.123456"
  }
}
```

**Response Error (403 Forbidden) - Usuario no autorizado:**

```json
{
  "error": "Tu cuenta está pendiente de autorización. Por favor espera a que un administrador apruebe tu registro."
}
```

## Endpoints Administrativos (Solo Admin)

### Listar Usuarios Pendientes
```http
GET /admin/users/pending?page=1&per_page=20&role=voluntarios
Authorization: Bearer <access_token>
```
**Parámetros de consulta:**
| Parámetro   | Tipo    | Descripción                 | Por Defecto |
|-------------|---------|-----------------------------|-------------|
| page        | integer | Número de página            | 1           |
| per_page    | integer | Usuarios por página (1-100) | 20          |
| role        | string  | Filtrar por rol específico  | todos       |

**Response (200 OK):**

```json
{
  "users": [
    {
      "id": 5,
      "email": "juan.perez@example.com",
      "nombre_completo": "Juan",
      "apellidos": "Pérez García",
      "direccion": "Calle Principal #123",
      "edad": 28,
      "telefono": "+525512345678",
      "role": "voluntarios",
      "is_authorized": false,
      "foto_identificacion_path": "/data/identificaciones/user_5_id.jpg",
      "created_at": "2025-10-09T10:30:00.123456",
      "authorized_at": null
    }
  ],
  "total": 15,
  "page": 1,
  "per_page": 20,
  "total_pages": 1
}
```

### Autorizar Usuario
```http
POST /admin/users/5/authorize
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "message": "Usuario autorizado exitosamente.",
  "user": {
    "id": 5,
    "email": "juan.perez@example.com",
    "nombre_completo": "Juan",
    "apellidos": "Pérez García",
    "role": "voluntarios",
    "is_authorized": true,
    "authorized_at": "2025-10-09T14:20:00.123456"
  }
}
```

### Deny User
```http
POST /admin/users/5/reject
Authorization: Bearer <access_token>
Content-Type: application/json
```
**Response (200 OK):**

```json
{
  "message": "Usuario rechazado y eliminado exitosamente."
}
```

### Ver Identificación de Usuario
```http
GET /admin/users/5/identification
Authorization: Bearer <access_token>
```
**Response (200 OK):**
Devuelve la imagen directamente (image/jpeg o image/png)

### Estadísticas sistema
```http
GET /admin/stats
Authorization: Bearer <access_token>
```
**Response (200 OK):**

```json
{
  "users_total": 150,
  "users_authorized": 120,
  "users_pending": 30,
  "users_by_role": {
    "admin": 5,
    "voluntarios": 40,
    "personal": 25,
    "servicio_social": 15,
    "visitas": 20,
    "familiares": 30,
    "donantes": 10,
    "proveedores": 5
  }
}
```

## Error Responses

The API returns consistent error responses in the following format:

```json
{
  "error": "Error message description"
}
```

### Common Error Codes

- `400 Bad Request`: Missing required fields, invalid email format, password too short
- `401 Unauthorized`: Invalid credentials, expired or invalid token
- `403 Forbidden`: suario no autorizado o permisos insuficientes
- `404 Not Found`: User not found
- `409 Conflict`: Email already registered

## Validation Rules

### Registro de Usuario
|Campo               | Validación                               |
|--------------------| -----------------------------------------|
|email               | Formato válido, único en la base de datos|
|password            | Mínimo 6 caracteres                      |
|nombre_completo     | 1-100 caracteres, no vacío               |
|apellidos           | 1-100 caracteres, no vacío               |
|direccion           | 1-255 caracteres, no vacío               |
|edad                | Entero entre 18 y 120                    |
|telefono            | 10 dígitos, puede incluir +              |
|foto_identificacion | JPG/PNG, máximo 5MB                      |
|role                | Debe ser uno de los 8 roles válidos      |


### Email Validation

- Emails are normalized (lowercased, trimmed)
- Email format validation using the `email-validator` library
- Deliverability checking is disabled for performance

## Security Features

- Passwords are hashed using Werkzeug's secure password hashing
- JWT tokens with configurable expiration times
- Separate access and refresh tokens
- Email normalization to prevent duplicate accounts
- No sensitive information exposed in error messages
- CORS protection (can be configured as needed)

## Workflow
### Register and Auth
```mermaid
sequenceDiagram
    participant U as Usuario
    participant API as API
    participant DB as Base de Datos
    participant A as Admin

    U->>API: POST /auth/register (con datos + foto)
    API->>DB: Guardar usuario (is_authorized=false)
    API->>U: 201: Usuario creado (pendiente)
    
    A->>API: GET /admin/users/pending
    API->>A: Lista de usuarios pendientes
    
    A->>API: GET /admin/users/{id}/identification
    API->>A: Imagen de identificación
    
    A->>API: POST /admin/users/{id}/authorize
    API->>DB: Actualizar is_authorized=true
    API->>A: 200: Usuario autorizado
    
    U->>API: POST /auth/login
    API->>U: 200: Tokens JWT
```

### Auth
```mermaid
sequenceDiagram
    participant U as Usuario
    participant API as API
    participant DB as Base de Datos

    U->>API: POST /auth/login (email + password)
    API->>DB: Verificar credenciales
    DB->>API: Usuario encontrado
    API->>API: Verificar is_authorized=true
    API->>API: Generar tokens JWT
    API->>U: access_token + refresh_token
    
    U->>API: GET /profile (con access_token)
    API->>API: Validar token
    API->>DB: Obtener datos del usuario
    API->>U: Información del perfil
```

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    nombre_completo VARCHAR(100) NOT NULL,
    apellidos VARCHAR(100) NOT NULL,
    direccion VARCHAR(255) NOT NULL,
    edad INTEGER NOT NULL,
    telefono VARCHAR(20) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'voluntarios',
    is_authorized BOOLEAN NOT NULL DEFAULT FALSE,
    foto_identificacion_path VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    authorized_at DATETIME,
    authorized_by_id INTEGER,
    FOREIGN KEY (authorized_by_id) REFERENCES users (id),
    CHECK (edad >= 18),
    CHECK (role IN ('admin', 'voluntarios', 'personal', 'servicio_social', 
                    'visitas', 'familiares', 'donantes', 'proveedores'))
);
```

### Recomended index
```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_authorized ON users(is_authorized);
CREATE INDEX idx_users_created_at ON users(created_at);
```

## Development

### Project Structure

```
api-login/
├── app.py                      # Aplicación principal Flask
├── models.py                   # Modelos de base de datos
├── requirements.txt            # Dependencias Python
├── .env                        # Variables de entorno (no incluir en git)
├── .gitignore                  # Archivos a ignorar en git
├── openapi.yaml                # Especificación OpenAPI 3.0
├── README.md                   # Este archivo
├── data/
│   └── identificaciones/       # Fotografías de identificación
│       ├── user_1_id.jpg
│       ├── user_2_id.png
│       └── ...
├── instance/
│   └── site.db                 # Base de datos SQLite
└── __pycache__/                # Cache de Python
```

### Running in Development Mode

The application runs in debug mode by default when started with `python app.py`. This enables:

- Automatic reloading on code changes
- Detailed error messages
- Debug toolbar (if configured)

### Database Management

The database is automatically created when the application starts. To reset the database, simply delete the `instance/site.db` file and restart the application.

## Production Considerations

1. **Security**:

   - Change the `JWT_SECRET_KEY` to a strong, randomly generated secret
   - Use a production database (PostgreSQL, MySQL)
   - Enable HTTPS
   - Configure proper CORS settings

2. **Performance**:

   - Use a production WSGI server (Gunicorn, uWSGI)
   - Configure database connection pooling
   - Implement rate limiting
   - Add caching where appropriate

3. **Monitoring**:
   - Add logging
   - Implement health check endpoints
   - Monitor token usage and security events

## License

This project is licensed under the MIT License - see the LICENSE file for details.

