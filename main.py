import os
import re
import ipaddress
from datetime import timedelta, datetime, timezone
from typing import Optional, List, Dict, Any
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form, status, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# Paginación simple sin dependencias externas

from sqlalchemy.orm import Session
import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv

from database import get_db, engine
from models import User, Base
from schemas import (
    UserCreate, UserLogin, UserResponse, Token, 
    AdminStats, UserUpdate
)

load_dotenv()

# Crear las tablas
Base.metadata.create_all(bind=engine)

# Configuración de seguridad
security = HTTPBearer()

app = FastAPI(
    title="API Login Sistema",
    description="API para sistema de login con autenticación JWT",
    version="2.0.0"
)

# Configuración CORS
allowed_origins = [
    # Desarrollo local - Frontend común
    'http://localhost:3000',     # React/Next.js default
    'http://localhost:5173',     # Vite default
    'http://localhost:8080',     # Vue/otros frameworks
    'http://localhost:4200',     # Angular default
    'http://127.0.0.1:3000', 
    'http://127.0.0.1:5173',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:4200',
    # Frontend en Vercel
    'https://login-proyect-umber.vercel.app',
    # IPs específicas solicitadas
    'http://44.226.145.213', 
    'https://44.226.145.213',
    'http://54.187.200.255', 
    'https://54.187.200.255',
    'http://34.213.214.55', 
    'https://34.213.214.55',
    'http://35.164.95.156', 
    'https://35.164.95.156',
    'http://44.230.95.183', 
    'https://44.230.95.183',
    'http://44.229.200.200', 
    'https://44.229.200.200'
]

allowed_cidrs = [
    '74.220.48.0/24',
    '74.220.56.0/24'
]

def is_origin_allowed(origin: str) -> bool:
    """Verifica si un origin está permitido por IP exacta o CIDR"""
    if not origin:
        return False
    
    try:
        parsed = urlparse(origin)
        host = parsed.hostname
        if not host:
            return False
        
        try:
            ip = ipaddress.ip_address(host)
            for cidr in allowed_cidrs:
                if ip in ipaddress.ip_network(cidr):
                    return True
        except ValueError:
            pass
            
    except Exception:
        pass
    
    return False

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Accept-Language", 
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Origin",
        "Cache-Control",
        "Pragma"
    ],
)

# Middleware adicional para CORS con CIDR (redes IP específicas)
@app.middleware("http")
async def cors_handler(request: Request, call_next):
    if request.method == "OPTIONS":
        origin = request.headers.get('origin')
        if origin and (origin in allowed_origins or is_origin_allowed(origin)):
            response = Response(status_code=200)
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Headers'] = 'Accept, Accept-Language, Content-Language, Content-Type, Authorization, X-Requested-With, Origin, Cache-Control, Pragma'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Max-Age'] = '86400'
            return response
    
    response = await call_next(request)
    
    origin = request.headers.get('origin')
    if origin and is_origin_allowed(origin):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

# Configuración de archivos
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'data/identificaciones')
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 5242880))  # 5MB por defecto
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Crear directorio de uploads si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configuración JWT
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'super-secret')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRES', 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 7))

# Utilidades de autenticación


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Dependencias
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    payload = decode_token(token)
    
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tipo de token inválido"
        )
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado"
        )
    
    # Verificar autorización (excepto para admins)
    if user.role != 'admin' and not user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tu cuenta no está autorizada."
        )
    
    return user

async def get_refresh_token_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    payload = decode_token(token)
    
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Se requiere refresh token"
        )
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado"
        )
    
    return user

async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren permisos de administrador"
        )
    return current_user

# Validaciones y utilidades
def _normalize_email(email: str) -> str:
    try:
        valid = validate_email(email, check_deliverability=False)
        return valid.normalized
    except EmailNotValidError as e:
        raise ValueError(str(e))

def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_phone(phone: str) -> bool:
    # Valida formato de teléfono (10-15 dígitos, puede tener +)
    pattern = r'^\+?[0-9]{10,15}$'
    return re.match(pattern, phone) is not None

# Endpoints públicos


@app.get('/health')
async def health():
    return {
        "status": "ok",
        "time": datetime.now().isoformat(),
        "version": "2.0.0"
    }



# Rutas de autenticación
@app.post('/auth/register', response_model=Dict[str, Any])
async def register(
    email: str = Form(...),
    password: str = Form(...),
    nombre_completo: str = Form(...),
    apellidos: str = Form(...),
    direccion: str = Form(...),
    edad: int = Form(...),
    telefono: str = Form(...),
    role: str = Form(...),
    foto_identificacion: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Validar archivo
    if not foto_identificacion.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se seleccionó ningún archivo."
        )
    
    if not allowed_file(foto_identificacion.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de archivo no válido. Solo se permiten PNG, JPG, JPEG."
        )
    
    # Validar datos del formulario
    try:
        normalized_email = _normalize_email(email)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email inválido: {str(e)}"
        )
    
    # Validar contraseña
    if len(password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe tener al menos 6 caracteres."
        )
    
    # Validar edad
    if edad < 18 or edad > 120:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debe ser mayor de edad (18 años o más)."
        )
    
    # Validar teléfono
    if not validate_phone(telefono):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de teléfono inválido (debe tener 10-15 dígitos)."
        )
    
    # Validar rol
    valid_roles = ['voluntarios', 'personal', 'servicio_social', 'visitas', 
                   'familiares', 'donantes', 'proveedores']
    if role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rol inválido. Roles válidos: {', '.join(valid_roles)}"
        )
    
    # Verificar si el email ya existe
    if db.query(User).filter(User.email == normalized_email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El email ya está registrado."
        )
    
    # Guardar archivo de identificación
    filename = secure_filename(foto_identificacion.filename)
    file_extension = filename.rsplit('.', 1)[1].lower()
    
    # Crear nombre único para el archivo
    unique_filename = f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    
    try:
        content = await foto_identificacion.read()
        with open(file_path, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al guardar el archivo de identificación."
        )
    
    # Crear usuario
    try:
        user = User(
            email=normalized_email,
            nombre_completo=nombre_completo.strip(),
            apellidos=apellidos.strip(),
            direccion=direccion.strip(),
            edad=edad,
            telefono=telefono.strip(),
            role=role,
            is_authorized=False,  # Requiere autorización de admin
            foto_identificacion_path=file_path
        )
        
        # Establecer la contraseña usando el método del modelo
        user.set_password(password)
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        # Renombrar archivo con ID del usuario
        new_filename = f"user_{user.id}_id.{file_extension}"
        new_file_path = os.path.join(UPLOAD_FOLDER, new_filename)
        
        os.rename(file_path, new_file_path)
        user.foto_identificacion_path = new_file_path
        db.commit()
        
        return {
            "message": "Usuario registrado exitosamente. Pendiente de autorización por un administrador.",
            "user": {
                "id": user.id,
                "email": user.email,
                "nombre_completo": user.nombre_completo,
                "apellidos": user.apellidos,
                "role": user.role,
                "is_authorized": user.is_authorized,
                "created_at": user.created_at.isoformat()
            }
        }
        
    except Exception as e:
        # Limpiar archivo si hay error
        if os.path.exists(file_path):
            os.remove(file_path)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor."
        )

@app.post("/auth/login", response_model=Token)
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    try:
        email = _normalize_email(user_credentials.email)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email inválido: {ve}"
        )

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas."
        )
    
    try:
        password_valid = user.check_password(user_credentials.password)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor. Por favor contacta al administrador."
        )
    
    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas."
        )
    
    # Verificar si el usuario está autorizado (excepto para admins)
    if user.role != 'admin' and not user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tu cuenta está pendiente de autorización. Por favor espera a que un administrador apruebe tu registro."
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role, "is_authorized": user.is_authorized},
        expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id)},
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/auth/refresh", response_model=Dict[str, str])
async def refresh_token(user: User = Depends(get_refresh_token_user)):
    # Verificar que el usuario siga autorizado (excepto admins)
    if user.role != 'admin' and not user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tu cuenta ya no está autorizada."
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role, "is_authorized": user.is_authorized},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token}

# Endpoints protegidos
@app.get("/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        nombre_completo=current_user.nombre_completo,
        apellidos=current_user.apellidos,
        direccion=current_user.direccion,
        edad=current_user.edad,
        telefono=current_user.telefono,
        role=current_user.role,
        is_authorized=current_user.is_authorized,
        created_at=current_user.created_at,
        authorized_at=current_user.authorized_at
    )

# Endpoints administrativos
@app.get('/admin/users/pending')
async def get_pending_users(
    page: int = 1,
    per_page: int = 20,
    role_filter: Optional[str] = None,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    # Limitar per_page máximo
    per_page = min(per_page, 100)
    
    query = db.query(User).filter(User.is_authorized == False)
    
    if role_filter and role_filter in ['voluntarios', 'personal', 'servicio_social', 
                                       'visitas', 'familiares', 'donantes', 'proveedores']:
        query = query.filter(User.role == role_filter)
    
    # Calcular offset
    offset = (page - 1) * per_page
    
    # Obtener total y usuarios paginados
    total = query.count()
    users = query.offset(offset).limit(per_page).all()
    
    user_responses = [
        {
            "id": user.id,
            "email": user.email,
            "nombre_completo": user.nombre_completo,
            "apellidos": user.apellidos,
            "direccion": user.direccion,
            "edad": user.edad,
            "telefono": user.telefono,
            "role": user.role,
            "created_at": user.created_at.isoformat()
        } for user in users
    ]
    
    total_pages = (total + per_page - 1) // per_page
    
    return {
        "users": user_responses,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages
    }

@app.post('/admin/users/{user_id}/authorize')
async def authorize_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya está autorizado."
        )
    
    # Autorizar usuario
    user.is_authorized = True
    user.authorized_at = datetime.now()
    user.authorized_by_id = admin_user.id
    
    db.commit()
    
    return {
        "message": "Usuario autorizado exitosamente.",
        "user": {
            "id": user.id,
            "email": user.email,
            "nombre_completo": user.nombre_completo,
            "apellidos": user.apellidos,
            "role": user.role,
            "is_authorized": user.is_authorized,
            "authorized_at": user.authorized_at.isoformat() if user.authorized_at else None
        }
    }

@app.post('/admin/users/{user_id}/reject')
async def reject_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede rechazar un usuario ya autorizado."
        )
    
    # Eliminar archivo de identificación si existe
    if user.foto_identificacion_path and os.path.exists(user.foto_identificacion_path):
        try:
            os.remove(user.foto_identificacion_path)
        except Exception:
            pass  # No fallar si no se puede eliminar el archivo
    
    # Eliminar usuario
    db.delete(user)
    db.commit()
    
    return {"message": "Usuario rechazado y eliminado exitosamente."}

@app.get('/admin/users/{user_id}/identification')
async def get_user_identification(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if not user.foto_identificacion_path or not os.path.exists(user.foto_identificacion_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fotografía de identificación no encontrada."
        )
    
    try:
        return FileResponse(
            user.foto_identificacion_path,
            media_type='application/octet-stream',
            filename=f"identificacion_usuario_{user_id}.jpg"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al acceder al archivo de identificación."
        )

@app.get("/admin/stats", response_model=AdminStats)
async def admin_stats(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    total_users = db.query(User).count()
    total_authorized = db.query(User).filter(User.is_authorized == True).count()
    total_pending = db.query(User).filter(User.is_authorized == False).count()
    
    # Contar por roles
    roles_count = {}
    all_roles = ['admin', 'voluntarios', 'personal', 'servicio_social', 
                 'visitas', 'familiares', 'donantes', 'proveedores']
    
    for role in all_roles:
        roles_count[role] = db.query(User).filter(User.role == role).count()
    
    return AdminStats(
        users_total=total_users,
        users_authorized=total_authorized,
        users_pending=total_pending,
        users_by_role=roles_count
    )

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)