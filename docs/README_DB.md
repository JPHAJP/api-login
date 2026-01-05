# Database Schema Documentation

This project uses a **PostgreSQL** database hosted on **Render.com**. The schema is defined using SQLAlchemy ORM in `models.py`.

## Tables

### 1. `users`
Stores user information, authentication details, and authorization status.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PK, Index | Unique identifier for the user |
| `email` | String(120) | Unique, Not Null, Index | User's email address |
| `password_hash` | String(255) | Not Null | Bcrypt hashed password |
| `nombre_completo` | String(100) | Not Null | User's first name |
| `apellidos` | String(100) | Not Null | User's last name |
| `direccion` | String(255) | Not Null | User's address |
| `edad` | Integer | Not Null | User's age |
| `telefono` | String(20) | Not Null | User's phone number |
| `role` | String(20) | Not Null, Default='voluntarios', Index | User role (e.g., admin, voluntarios, personal) |
| `is_authorized` | Boolean | Not Null, Default=False, Index | Boolean flag for authorization |
| `authorization_status` | String(20) | Not Null, Default='pending', Index | Status: 'pending', 'authorized', 'unauthorized' |
| `authorization_info` | Text | Not Null, Default='Pendiente...' | Additional info about authorization |
| `foto_identificacion_path` | String(255) | Nullable | Path to stored ID photo |
| `created_at` | DateTime | Not Null, Default=now | Account creation timestamp |
| `authorized_at` | DateTime | Nullable | Timestamp when user was authorized |
| `unauthorized_at` | DateTime | Nullable | Timestamp when user was unauthorized |
| `authorized_by_id` | Integer | FK(`users.id`), Nullable | ID of admin who authorized the user |
| `unauthorized_by_id` | Integer | FK(`users.id`), Nullable | ID of admin who unauthorized the user |

**Relationships:**
- `authorized_by`: Links to the User (admin) who authorized this user.
- `unauthorized_by`: Links to the User (admin) who unauthorized this user.
- `access_logs`: One-to-Many relationship with `access_logs` table.

---

### 2. `qr_codes`
Stores generated QR codes for access control.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PK, Index | Unique identifier |
| `code` | String(255) | Unique, Not Null, Index | The unique code string |
| `created_at` | DateTime | Not Null, Default=now | Creation timestamp |
| `expires_at` | DateTime | Not Null | Expiration timestamp |
| `is_active` | Boolean | Not Null, Default=True | Whether the code is currently active |

**Relationships:**
- `access_logs`: One-to-Many relationship with `access_logs` table.

---

### 3. `access_logs`
Records entry and exit events.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PK, Index | Unique identifier |
| `user_id` | Integer | FK(`users.id`), Not Null, Index | User who accessed |
| `qr_code_id` | Integer | FK(`qr_codes.id`), Not Null | QR code used for access |
| `access_type` | Enum | Not Null, Index | Type of access: 'ENTRY' or 'EXIT' |
| `timestamp` | DateTime | Not Null, Default=now, Index | Time of access |
| `notes` | Text | Nullable | Optional notes (e.g., for manual entry) |
| `is_manual` | Boolean | Not Null, Default=False | If the log was created manually by admin |
| `manual_by_admin_id` | Integer | FK(`users.id`), Nullable | Admin who created the manual log |

**Relationships:**
- `user`: Links to the `users` table.
- `qr_code`: Links to the `qr_codes` table.
- `manual_by_admin`: Links to the `users` table (admin).

## Enums

### `AccessType`
- `ENTRY` ("entry")
- `EXIT` ("exit")

### `ROLE_CHOICES`
- "admin"
- "voluntarios"
- "personal"
- "servicio_social"
- "visitas"
- "familiares"
- "donantes"
- "proveedores"
