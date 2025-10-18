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
import qrcode
from PIL import Image
import io
import base64
import secrets
import hashlib

from database import get_db, engine
from models import User, Base, QRCode, AccessLog, AccessType
from schemas import (
    UserCreate, UserLogin, UserResponse, Token, 
    AdminStats, UserUpdate, QRCodeResponse, QRCodeGenerate,
    AccessLogCreate, AccessLogResponse, AccessLogStats,
    UserCurrentlyInside, ManualExitRequest, QRScanRequest,
    UserDetailedResponse, UserSearchResponse, UnauthorizeUserRequest,
    UserAuthorizationResponse, UserDeletionCheckResponse, UserAuthStatusResponse
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
    'http://192.168.68.108:5173',
    'http://192.168.68.101:5173',
    'http://192.168.68.108:8000',
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

# Configuración QR
QR_EXPIRY_MINUTES = 5
QR_ACCESS_SECRET = os.getenv('QR_ACCESS_SECRET', 'qr-access-secret-key')

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
    if user.role != 'admin' and user.authorization_status != "authorized":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Tu cuenta no está autorizada. Estado: {user.authorization_status}. Info: {user.authorization_info}"
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

# Funciones para QR Code
def generate_qr_code_string() -> str:
    """Genera un código QR único basado en timestamp y secreto"""
    timestamp = datetime.now().isoformat()
    random_bytes = secrets.token_bytes(16)
    data = f"{timestamp}:{QR_ACCESS_SECRET}:{random_bytes.hex()}"
    return hashlib.sha256(data.encode()).hexdigest()

def create_qr_image(data: str) -> str:
    """Crea una imagen QR y la retorna como base64"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()

def cleanup_expired_qr_codes(db: Session):
    """Limpia códigos QR expirados de la base de datos"""
    expired_codes = db.query(QRCode).filter(QRCode.expires_at < datetime.now()).all()
    for code in expired_codes:
        code.is_active = False
    db.commit()

def get_or_create_current_qr(db: Session) -> QRCode:
    """Obtiene el QR actual válido o crea uno nuevo si no existe o expiró"""
    # Limpiar códigos expirados
    cleanup_expired_qr_codes(db)
    
    # Buscar QR activo y no expirado
    current_qr = db.query(QRCode).filter(
        QRCode.is_active == True,
        QRCode.expires_at > datetime.now()
    ).first()
    
    if current_qr:
        return current_qr
    
    # Crear nuevo QR code
    code = generate_qr_code_string()
    expires_at = datetime.now() + timedelta(minutes=QR_EXPIRY_MINUTES)
    
    new_qr = QRCode(
        code=code,
        expires_at=expires_at,
        is_active=True
    )
    
    db.add(new_qr)
    db.commit()
    db.refresh(new_qr)
    
    return new_qr

# Autenticación especial para QR
async def get_qr_access_auth(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> bool:
    """Autenticación especial para acceso a QR codes"""
    token = credentials.credentials
    
    # Verificar si es el token especial para QR
    if token == QR_ACCESS_SECRET:
        return True
    
    # También permitir tokens de admin
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tipo de token inválido"
            )
        
        # Verificar si el usuario es admin
        # Aquí podríamos hacer una consulta a la DB, pero para simplificar
        # asumimos que si el token es válido y contiene role admin, está ok
        role = payload.get("role")
        if role == "admin":
            return True
            
    except JWTError:
        pass
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Acceso no autorizado para QR codes"
    )

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
    
    # Verificar estado de autorización
    # Los admins siempre pueden iniciar sesión
    if user.role != 'admin':
        if user.authorization_status == "pending":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tu cuenta está pendiente de autorización. Contacta al administrador."
            )
        # Los usuarios autorizados y desautorizados SÍ pueden iniciar sesión
        # pero los desautorizados tendrán restricciones en ciertos endpoints
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={
            "sub": str(user.id), 
            "email": user.email, 
            "role": user.role, 
            "is_authorized": user.is_authorized,
            "authorization_status": user.authorization_status
        },
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

@app.get("/auth/status", response_model=UserAuthStatusResponse)
async def get_auth_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Verificar el estado de autorización del usuario actual
    Retorna información detallada sobre permisos y restricciones
    """
    # Obtener información del admin que autorizó (si aplica)
    authorized_by_name = None
    if current_user.authorized_by_id:
        authorized_by = db.query(User).filter(User.id == current_user.authorized_by_id).first()
        if authorized_by:
            authorized_by_name = f"{authorized_by.nombre_completo} {authorized_by.apellidos}"
    
    # Obtener información del admin que desautorizó (si aplica)
    unauthorized_by_name = None
    if current_user.unauthorized_by_id:
        unauthorized_by = db.query(User).filter(User.id == current_user.unauthorized_by_id).first()
        if unauthorized_by:
            unauthorized_by_name = f"{unauthorized_by.nombre_completo} {unauthorized_by.apellidos}"
    
    # Determinar permisos según el estado
    can_login = True  # Si llegó hasta aquí, ya puede hacer login
    can_access_qr = current_user.authorization_status == "authorized"
    
    # Generar mensaje apropiado según el estado
    if current_user.authorization_status == "pending":
        message = "Tu cuenta está pendiente de autorización. Contacta al administrador para obtener acceso completo."
    elif current_user.authorization_status == "authorized":
        message = "Tu cuenta está autorizada. Tienes acceso completo al sistema."
    elif current_user.authorization_status == "unauthorized":
        message = f"Tu cuenta ha sido desautorizada. {current_user.authorization_info or 'Contacta al administrador para más información.'}"
    else:
        message = "Estado de autorización desconocido."
    
    return UserAuthStatusResponse(
        user_id=current_user.id,
        email=current_user.email,
        nombre_completo=current_user.nombre_completo,
        authorization_status=current_user.authorization_status,
        authorization_info=current_user.authorization_info,
        can_login=can_login,
        can_access_qr=can_access_qr,
        authorized_at=current_user.authorized_at,
        unauthorized_at=current_user.unauthorized_at,
        authorized_by_name=authorized_by_name,
        unauthorized_by_name=unauthorized_by_name,
        message=message
    )

@app.post("/auth/refresh", response_model=Dict[str, str])
async def refresh_token(user: User = Depends(get_refresh_token_user)):
    # Verificar que el usuario siga autorizado (excepto admins)
    if user.role != 'admin' and user.authorization_status != "authorized":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Tu cuenta ya no está autorizada. Estado: {user.authorization_status}. {user.authorization_info}"
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
        authorization_status=current_user.authorization_status,
        authorization_info=current_user.authorization_info,
        created_at=current_user.created_at,
        authorized_at=current_user.authorized_at,
        unauthorized_at=current_user.unauthorized_at
    )

# Endpoints QR
@app.get("/qr/current", response_model=QRCodeGenerate)
async def get_current_qr(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtiene el código QR actual válido - Solo para usuarios autorizados"""
    # Verificar que el usuario esté autorizado
    if current_user.authorization_status != "authorized":
        status_message = {
            "pending": "Tu cuenta está pendiente de autorización",
            "unauthorized": f"Tu acceso ha sido desautorizado. {current_user.authorization_info or 'Contacta al administrador.'}"
        }.get(current_user.authorization_status, "Estado de autorización inválido")
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=status_message
        )
    
    try:
        current_qr = get_or_create_current_qr(db)
        qr_image = create_qr_image(current_qr.code)
        
        return QRCodeGenerate(
            qr_image=qr_image,
            code=current_qr.code,
            expires_at=current_qr.expires_at
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al generar código QR"
        )

@app.post("/qr/scan")
async def scan_qr_code(
    scan_request: QRScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escanea un código QR para entrada o salida - Solo para usuarios autorizados"""
    # Verificar que el usuario esté autorizado
    if current_user.authorization_status != "authorized":
        status_message = {
            "pending": "Tu cuenta está pendiente de autorización",
            "unauthorized": f"Tu acceso ha sido desautorizado. {current_user.authorization_info or 'Contacta al administrador.'}"
        }.get(current_user.authorization_status, "Estado de autorización inválido")
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=status_message
        )
    
    # Verificar que el código QR existe y no ha expirado
    qr_code = db.query(QRCode).filter(
        QRCode.code == scan_request.qr_code,
        QRCode.is_active == True
    ).first()
    
    if not qr_code:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Código QR no válido"
        )
    
    if qr_code.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código QR expirado"
        )
    
    # Verificar lógica de entrada/salida
    last_access = db.query(AccessLog).filter(
        AccessLog.user_id == current_user.id
    ).order_by(AccessLog.timestamp.desc()).first()
    
    if scan_request.access_type == "entry":
        # Verificar que el usuario no esté ya dentro
        if last_access and last_access.access_type == AccessType.ENTRY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ya tienes una entrada registrada. Debes salir primero."
            )
    else:  # exit
        # Verificar que el usuario esté dentro
        if not last_access or last_access.access_type == AccessType.EXIT:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No tienes una entrada registrada. Debes entrar primero."
            )
    
    # Crear registro de acceso
    access_log = AccessLog(
        user_id=current_user.id,
        qr_code_id=qr_code.id,
        access_type=AccessType.ENTRY if scan_request.access_type == "entry" else AccessType.EXIT,
        timestamp=datetime.now(),
        is_manual=False
    )
    
    db.add(access_log)
    db.commit()
    db.refresh(access_log)
    
    return {
        "message": f"{'Entrada' if scan_request.access_type == 'entry' else 'Salida'} registrada exitosamente",
        "access_log": {
            "id": access_log.id,
            "access_type": access_log.access_type.value,
            "timestamp": access_log.timestamp.isoformat(),
            "user_name": f"{current_user.nombre_completo} {current_user.apellidos}"
        }
    }

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
    
    if user.authorization_status == "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya está autorizado."
        )
    
    # Autorizar usuario
    user.is_authorized = True
    user.authorization_status = "authorized"
    user.authorization_info = f"Autorizado por {admin_user.nombre_completo} {admin_user.apellidos} el {datetime.now().strftime('%d/%m/%Y %H:%M')}"
    user.authorized_at = datetime.now()
    user.authorized_by_id = admin_user.id
    user.unauthorized_at = None  # Limpiar fecha de desautorización si existía
    user.unauthorized_by_id = None
    
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
    
    # Verificar que el usuario NO esté autorizado
    if user.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede eliminar un usuario ya autorizado. Use el endpoint 'unauthorize' para desautorizar al usuario."
        )
    
    # Verificar que el usuario no tenga registros de acceso (doble seguridad)
    access_logs_count = db.query(AccessLog).filter(AccessLog.user_id == user_id).count()
    if access_logs_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede eliminar un usuario que tiene registros de acceso. Use el endpoint 'unauthorize' para desautorizar al usuario."
        )
    
    # Verificar que no sea admin
    if user.role == 'admin':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede eliminar un usuario administrador."
        )
    
    try:
        # Eliminar archivo de identificación si existe
        if user.foto_identificacion_path and os.path.exists(user.foto_identificacion_path):
            try:
                os.remove(user.foto_identificacion_path)
            except Exception:
                pass  # No fallar si no se puede eliminar el archivo
        
        # Eliminar usuario
        db.delete(user)
        db.commit()
        
        return {"message": f"Usuario {user.nombre_completo} {user.apellidos} rechazado y eliminado exitosamente."}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el usuario. Es posible que tenga datos relacionados que impiden su eliminación."
        )

@app.get('/admin/users/{user_id}/can-delete', response_model=UserDeletionCheckResponse)
async def check_if_user_can_be_deleted(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Verifica si un usuario puede ser eliminado de forma segura"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    reasons_cannot_delete = []
    
    # Verificar si está autorizado
    if user.is_authorized:
        reasons_cannot_delete.append("Usuario ya está autorizado")
    
    # Verificar si es admin
    if user.role == 'admin':
        reasons_cannot_delete.append("No se pueden eliminar administradores")
    
    # Verificar si tiene registros de acceso
    access_logs_count = db.query(AccessLog).filter(AccessLog.user_id == user_id).count()
    if access_logs_count > 0:
        reasons_cannot_delete.append(f"Usuario tiene {access_logs_count} registros de acceso")
    
    # Verificar si autorizó a otros usuarios
    authorized_users_count = db.query(User).filter(User.authorized_by_id == user_id).count()
    if authorized_users_count > 0:
        reasons_cannot_delete.append(f"Usuario autorizó a {authorized_users_count} otros usuarios")
    
    can_delete = len(reasons_cannot_delete) == 0
    
    return {
        "can_delete": can_delete,
        "user_id": user_id,
        "user_name": f"{user.nombre_completo} {user.apellidos}",
        "reasons_cannot_delete": reasons_cannot_delete,
        "recommended_action": "unauthorize" if user.is_authorized else ("delete" if can_delete else "cannot_delete")
    }

@app.post('/admin/users/{user_id}/unauthorize', response_model=UserAuthorizationResponse)
async def unauthorize_user(
    user_id: int,
    unauthorize_request: UnauthorizeUserRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Quitar autorización a un usuario previamente autorizado.
    IMPORTANTE: Los usuarios nunca se eliminan si fueron autorizados alguna vez.
    Solo se marca como no autorizado para auditoría y control.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.authorization_status != "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"El usuario no está autorizado actualmente. Estado actual: {user.authorization_status}. Info: {user.authorization_info}"
        )
    
    # Verificar que no sea admin (protección extra)
    if user.role == 'admin':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede desautorizar a un administrador."
        )
    
    # Desautorizar usuario (mantener historial completo)
    user.is_authorized = False
    user.authorization_status = "unauthorized"
    user.authorization_info = f"Desautorizado por {admin_user.nombre_completo} {admin_user.apellidos} el {datetime.now().strftime('%d/%m/%Y %H:%M')}. Razón: {unauthorize_request.reason}"
    user.unauthorized_at = datetime.now()
    user.unauthorized_by_id = admin_user.id
    # Mantener authorized_at para historial
    
    db.commit()
    db.refresh(user)
    
    # Obtener información del admin que originalmente autorizó y desautorizó
    authorized_by_name = None
    if user.authorized_by_id:
        authorized_by = db.query(User).filter(User.id == user.authorized_by_id).first()
        if authorized_by:
            authorized_by_name = f"{authorized_by.nombre_completo} {authorized_by.apellidos}"
    
    unauthorized_by_name = None
    if user.unauthorized_by_id:
        unauthorized_by = db.query(User).filter(User.id == user.unauthorized_by_id).first()
        if unauthorized_by:
            unauthorized_by_name = f"{unauthorized_by.nombre_completo} {unauthorized_by.apellidos}"
    
    # Construir respuesta detallada
    user_detailed = UserDetailedResponse(
        id=user.id,
        email=user.email,
        nombre_completo=user.nombre_completo,
        apellidos=user.apellidos,
        direccion=user.direccion,
        edad=user.edad,
        telefono=user.telefono,
        role=user.role,
        is_authorized=user.is_authorized,
        authorization_status=user.authorization_status,
        authorization_info=user.authorization_info,
        foto_identificacion_path=user.foto_identificacion_path,
        created_at=user.created_at,
        authorized_at=user.authorized_at,
        unauthorized_at=user.unauthorized_at,
        authorized_by_id=user.authorized_by_id,
        authorized_by_name=authorized_by_name,
        unauthorized_by_id=user.unauthorized_by_id,
        unauthorized_by_name=unauthorized_by_name
    )
    
    return UserAuthorizationResponse(
        message=f"Autorización removida para {user.nombre_completo} {user.apellidos}",
        user=user_detailed,
        action_by=f"{admin_user.nombre_completo} {admin_user.apellidos}",
        reason=unauthorize_request.reason
    )

@app.post('/admin/users/{user_id}/reauthorize', response_model=UserAuthorizationResponse)
async def reauthorize_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Re-autorizar un usuario que fue previamente desautorizado.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado."
        )
    
    if user.authorization_status == "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya está autorizado."
        )
    
    # Re-autorizar usuario
    user.is_authorized = True
    user.authorization_status = "authorized"
    user.authorization_info = f"Re-autorizado por {admin_user.nombre_completo} {admin_user.apellidos} el {datetime.now().strftime('%d/%m/%Y %H:%M')}"
    user.authorized_at = datetime.now()
    user.authorized_by_id = admin_user.id
    user.unauthorized_at = None  # Limpiar fecha de desautorización
    user.unauthorized_by_id = None
    
    db.commit()
    db.refresh(user)
    
    # Construir respuesta detallada
    user_detailed = UserDetailedResponse(
        id=user.id,
        email=user.email,
        nombre_completo=user.nombre_completo,
        apellidos=user.apellidos,
        direccion=user.direccion,
        edad=user.edad,
        telefono=user.telefono,
        role=user.role,
        is_authorized=user.is_authorized,
        authorization_status=user.authorization_status,
        authorization_info=user.authorization_info,
        foto_identificacion_path=user.foto_identificacion_path,
        created_at=user.created_at,
        authorized_at=user.authorized_at,
        unauthorized_at=user.unauthorized_at,
        authorized_by_id=user.authorized_by_id,
        authorized_by_name=f"{admin_user.nombre_completo} {admin_user.apellidos}",
        unauthorized_by_id=user.unauthorized_by_id,
        unauthorized_by_name=None  # Se limpió al re-autorizar
    )
    
    return UserAuthorizationResponse(
        message=f"Usuario re-autorizado exitosamente: {user.nombre_completo} {user.apellidos}",
        user=user_detailed,
        action_by=f"{admin_user.nombre_completo} {admin_user.apellidos}",
        reason=None
    )

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

@app.get("/admin/access-logs", response_model=AccessLogStats)
async def get_access_logs(
    date: Optional[str] = None,  # Formato: YYYY-MM-DD
    page: int = 1,
    per_page: int = 50,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Obtiene logs de acceso filtrados por fecha"""
    # Limitar per_page máximo
    per_page = min(per_page, 100)
    
    query = db.query(AccessLog).join(User, AccessLog.user_id == User.id).order_by(AccessLog.timestamp.desc())
    
    # Filtrar por fecha si se proporciona
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
            start_datetime = datetime.combine(target_date, datetime.min.time())
            end_datetime = datetime.combine(target_date, datetime.max.time())
            query = query.filter(
                AccessLog.timestamp >= start_datetime,
                AccessLog.timestamp <= end_datetime
            )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Formato de fecha inválido. Use YYYY-MM-DD"
            )
    else:
        # Si no se especifica fecha, mostrar solo el día actual
        today = datetime.now().date()
        start_datetime = datetime.combine(today, datetime.min.time())
        end_datetime = datetime.combine(today, datetime.max.time())
        query = query.filter(
            AccessLog.timestamp >= start_datetime,
            AccessLog.timestamp <= end_datetime
        )
    
    # Calcular estadísticas
    all_logs_today = query.all() if not date else query.all()
    total_entries = sum(1 for log in all_logs_today if log.access_type == AccessType.ENTRY)
    total_exits = sum(1 for log in all_logs_today if log.access_type == AccessType.EXIT)
    
    # Calcular usuarios actualmente dentro
    user_status = {}
    for log in sorted(all_logs_today, key=lambda x: x.timestamp):
        if log.access_type == AccessType.ENTRY:
            user_status[log.user_id] = True
        else:
            user_status[log.user_id] = False
    
    currently_inside = sum(1 for inside in user_status.values() if inside)
    
    # Paginación
    offset = (page - 1) * per_page
    paginated_logs = query.offset(offset).limit(per_page).all()
    
    # Convertir a response format
    log_responses = []
    for log in paginated_logs:
        log_responses.append(AccessLogResponse(
            id=log.id,
            user_id=log.user_id,
            user_name=f"{log.user.nombre_completo} {log.user.apellidos}",
            user_email=log.user.email,
            qr_code_id=log.qr_code_id,
            access_type=log.access_type.value,
            timestamp=log.timestamp,
            notes=log.notes,
            is_manual=log.is_manual,
            manual_by_admin_id=log.manual_by_admin_id,
            manual_by_admin_name=f"{log.manual_by_admin.nombre_completo} {log.manual_by_admin.apellidos}" if log.manual_by_admin else None
        ))
    
    return AccessLogStats(
        total_entries=total_entries,
        total_exits=total_exits,
        currently_inside=currently_inside,
        logs=log_responses
    )

@app.get("/admin/users-inside", response_model=List[UserCurrentlyInside])
async def get_users_currently_inside(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Obtiene la lista de usuarios que han entrado pero no han salido"""
    # Obtener todos los logs de acceso del día actual
    today = datetime.now().date()
    start_datetime = datetime.combine(today, datetime.min.time())
    end_datetime = datetime.combine(today, datetime.max.time())
    
    logs = db.query(AccessLog).join(User, AccessLog.user_id == User.id).filter(
        AccessLog.timestamp >= start_datetime,
        AccessLog.timestamp <= end_datetime
    ).order_by(AccessLog.timestamp.asc()).all()
    
    # Calcular estado actual de cada usuario
    user_status = {}
    user_last_entry = {}
    
    for log in logs:
        if log.access_type == AccessType.ENTRY:
            user_status[log.user_id] = True
            user_last_entry[log.user_id] = log
        else:
            user_status[log.user_id] = False
    
    # Filtrar usuarios que están dentro
    users_inside = []
    for user_id, is_inside in user_status.items():
        if is_inside and user_id in user_last_entry:
            entry_log = user_last_entry[user_id]
            user = entry_log.user
            
            users_inside.append(UserCurrentlyInside(
                id=user.id,
                email=user.email,
                nombre_completo=user.nombre_completo,
                apellidos=user.apellidos,
                role=user.role,
                entry_time=entry_log.timestamp,
                entry_id=entry_log.id
            ))
    
    return sorted(users_inside, key=lambda x: x.entry_time)

@app.post("/admin/users/{user_id}/manual-exit")
async def register_manual_exit(
    user_id: int,
    exit_request: ManualExitRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Registra una salida manual para un usuario que olvidó salir"""
    # Verificar que el usuario existe
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    # Verificar que el usuario está actualmente dentro
    today = datetime.now().date()
    start_datetime = datetime.combine(today, datetime.min.time())
    
    last_access = db.query(AccessLog).filter(
        AccessLog.user_id == user_id,
        AccessLog.timestamp >= start_datetime
    ).order_by(AccessLog.timestamp.desc()).first()
    
    if not last_access or last_access.access_type == AccessType.EXIT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario no tiene una entrada registrada hoy"
        )
    
    # Obtener QR actual para el registro
    current_qr = get_or_create_current_qr(db)
    
    # Crear registro de salida manual
    exit_log = AccessLog(
        user_id=user_id,
        qr_code_id=current_qr.id,
        access_type=AccessType.EXIT,
        timestamp=datetime.now(),
        notes=exit_request.notes or "Salida registrada manualmente por administrador",
        is_manual=True,
        manual_by_admin_id=admin_user.id
    )
    
    db.add(exit_log)
    db.commit()
    db.refresh(exit_log)
    
    return {
        "message": f"Salida registrada manualmente para {user.nombre_completo} {user.apellidos}",
        "access_log": {
            "id": exit_log.id,
            "user_name": f"{user.nombre_completo} {user.apellidos}",
            "access_type": exit_log.access_type.value,
            "timestamp": exit_log.timestamp.isoformat(),
            "is_manual": exit_log.is_manual,
            "notes": exit_log.notes
        }
    }

@app.get("/admin/users/search", response_model=UserSearchResponse)
async def search_users(
    category: Optional[str] = None,  # Filtro por rol/categoría
    search: Optional[str] = None,    # Búsqueda por nombre o email
    page: int = 1,
    per_page: int = 20,
    include_pending: bool = True,    # Incluir usuarios pendientes de autorización
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Buscar y listar usuarios con filtros avanzados
    
    - category: Filtrar por rol específico (admin, voluntarios, personal, etc.)
    - search: Buscar por nombre completo, apellidos o email (búsqueda parcial)
    - include_pending: Si incluir usuarios no autorizados (por defecto True)
    """
    # Limitar per_page máximo
    per_page = min(per_page, 100)
    
    # Construir query base
    query = db.query(User)
    
    # Filtro por categoría/rol
    if category:
        valid_categories = ['admin', 'voluntarios', 'personal', 'servicio_social', 
                           'visitas', 'familiares', 'donantes', 'proveedores']
        if category in valid_categories:
            query = query.filter(User.role == category)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Categoría inválida. Categorías válidas: {', '.join(valid_categories)}"
            )
    
    # Filtro por texto (nombre, apellidos o email)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (User.nombre_completo.ilike(search_term)) |
            (User.apellidos.ilike(search_term)) |
            (User.email.ilike(search_term))
        )
    
    # Filtro por estado de autorización
    if not include_pending:
        query = query.filter(User.is_authorized == True)
    
    # Ordenar por fecha de creación (más recientes primero)
    query = query.order_by(User.created_at.desc())
    
    # Calcular total antes de paginación
    total = query.count()
    
    # Aplicar paginación
    offset = (page - 1) * per_page
    users = query.offset(offset).limit(per_page).all()
    
    # Construir respuesta con datos detallados
    user_responses = []
    for user in users:
        # Obtener información del admin que autorizó y desautorizó (si aplica)
        authorized_by_name = None
        if user.authorized_by_id:
            authorized_by = db.query(User).filter(User.id == user.authorized_by_id).first()
            if authorized_by:
                authorized_by_name = f"{authorized_by.nombre_completo} {authorized_by.apellidos}"
        
        unauthorized_by_name = None
        if user.unauthorized_by_id:
            unauthorized_by = db.query(User).filter(User.id == user.unauthorized_by_id).first()
            if unauthorized_by:
                unauthorized_by_name = f"{unauthorized_by.nombre_completo} {unauthorized_by.apellidos}"
        
        user_responses.append(UserDetailedResponse(
            id=user.id,
            email=user.email,
            nombre_completo=user.nombre_completo,
            apellidos=user.apellidos,
            direccion=user.direccion,
            edad=user.edad,
            telefono=user.telefono,
            role=user.role,
            is_authorized=user.is_authorized,
            authorization_status=user.authorization_status,
            authorization_info=user.authorization_info,
            foto_identificacion_path=user.foto_identificacion_path,
            created_at=user.created_at,
            authorized_at=user.authorized_at,
            unauthorized_at=user.unauthorized_at,
            authorized_by_id=user.authorized_by_id,
            authorized_by_name=authorized_by_name,
            unauthorized_by_id=user.unauthorized_by_id,
            unauthorized_by_name=unauthorized_by_name
        ))
    
    total_pages = (total + per_page - 1) // per_page
    
    return UserSearchResponse(
        users=user_responses,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages
    )

@app.get('/admin/users/{user_id}/identification-file')
async def get_user_identification_file(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Obtener el archivo de identificación de un usuario específico
    Devuelve la imagen directamente para mostrar en navegador
    """
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
        # Determinar el tipo MIME basado en la extensión
        file_extension = user.foto_identificacion_path.lower().split('.')[-1]
        media_type_map = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp'
        }
        media_type = media_type_map.get(file_extension, 'image/jpeg')
        
        return FileResponse(
            user.foto_identificacion_path,
            media_type=media_type,
            filename=f"identificacion_usuario_{user_id}_{user.nombre_completo.replace(' ', '_')}.{file_extension}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al acceder al archivo de identificación."
        )

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)