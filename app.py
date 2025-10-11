import os
import re
import ipaddress
from datetime import timedelta, datetime
from email_validator import validate_email, EmailNotValidError
from functools import wraps
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt_identity, jwt_required, verify_jwt_in_request, get_jwt
)
from models import db, User
from dotenv import load_dotenv

load_dotenv()

jwt = JWTManager()
app = Flask(__name__)

# Configuración CORS
allowed_origins = [
    # Desarrollo local
    'http://localhost:3000', 
    'http://localhost:5173', 
    'http://127.0.0.1:3000', 
    'http://127.0.0.1:5173',
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

CORS(app, 
     origins=allowed_origins,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     supports_credentials=True
)

# Redes CIDR adicionales permitidas
allowed_cidrs = [
    '74.220.48.0/24',
    '74.220.56.0/24'
]

def is_origin_allowed(origin):
    """Verifica si un origin está permitido por IP exacta o CIDR"""
    if not origin:
        return False
    
    try:
        parsed = urlparse(origin)
        host = parsed.hostname
        if not host:
            return False
        
        # Verificar si es una IP y está en las redes CIDR
        try:
            ip = ipaddress.ip_address(host)
            for cidr in allowed_cidrs:
                if ip in ipaddress.ip_network(cidr):
                    return True
        except ValueError:
            # No es una IP válida
            pass
            
    except Exception:
        pass
    
    return False

@app.after_request
def after_request(response):
    """Manejo adicional de CORS para redes CIDR"""
    origin = request.headers.get('Origin')
    
    if origin and (origin in allowed_origins or is_origin_allowed(origin)):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    
    return response

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de archivos
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'data/identificaciones')
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 5242880))  # 5MB por defecto
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Crear directorio de uploads si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Expiraciones
access_minutes = int(os.getenv('ACCESS_TOKEN_EXPIRES', 15))
refresh_days = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 7))

app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'super-secret')  # Cambia esto en producción
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=access_minutes)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=refresh_days)

db.init_app(app)
migrate = Migrate(app, db)
jwt.init_app(app)

with app.app_context():
    db.create_all()

# --------------------------
# Validaciones y utilidades
# --------------------------
def _normalize_email(email: str) -> str:
    try:
        valid = validate_email(email, check_deliverability=False)
        return valid.normalized
    except EmailNotValidError as e:
        raise ValueError(str(e))

def _require_json(keys):
    data = request.get_json()
    if not data:
        return None, (jsonify({"error": "Se requiere JSON en el cuerpo de la petición."}), 400)
    missing = [key for key in keys if key not in data or data[key] in [None, ""]]
    if missing:
        return None, (jsonify({"error": f"Campos faltantes: {', '.join(missing)}"}), 400)
    return data, None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_phone(phone):
    # Valida formato de teléfono (10-15 dígitos, puede tener +)
    pattern = r'^\+?[0-9]{10,15}$'
    return re.match(pattern, phone) is not None

def validate_user_data(form_data):
    errors = []
    
    # Validar campos requeridos
    required_fields = ['email', 'password', 'nombre_completo', 'apellidos', 
                      'direccion', 'edad', 'telefono', 'role']
    
    for field in required_fields:
        if field not in form_data or form_data[field] in [None, '', ' ']:
            errors.append(f"Campo requerido: {field}")
    
    if errors:
        return errors
    
    # Validar email
    try:
        _normalize_email(form_data['email'])
    except ValueError as e:
        errors.append(f"Email inválido: {e}")
    
    # Validar contraseña
    if len(form_data['password']) < 6:
        errors.append("La contraseña debe tener al menos 6 caracteres.")
    
    # Validar edad
    try:
        edad = int(form_data['edad'])
        if edad < 18 or edad > 120:
            errors.append("Debe ser mayor de edad (18 años o más).")
    except (ValueError, TypeError):
        errors.append("Edad debe ser un número válido.")
    
    # Validar teléfono
    if not validate_phone(form_data['telefono']):
        errors.append("Formato de teléfono inválido (debe tener 10-15 dígitos).")
    
    # Validar rol
    valid_roles = ['voluntarios', 'personal', 'servicio_social', 'visitas', 
                   'familiares', 'donantes', 'proveedores']
    if form_data['role'] not in valid_roles:
        errors.append(f"Rol inválido. Roles válidos: {', '.join(valid_roles)}")
    
    return errors

def role_required(*roles):
    # Decorador para forzar rol en el JWT
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt() or {}
            role = claims.get('role')
            is_authorized = claims.get('is_authorized', False)
            
            # Verificar que el usuario esté autorizado (excepto admins)
            if role != 'admin' and not is_authorized:
                return jsonify({
                    "error": "Tu cuenta no está autorizada."
                }), 403
            
            if role not in roles:
                return jsonify({
                    "error": "Forbidden",
                    "detail": "Rol insuficiente para acceder a este recurso.",
                    "required_roles": list(roles),
                    "current_role": role
                }), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper

# --------------------------
# Endpoints públicos
# --------------------------
@app.get('/health')
def health():
    return jsonify({
        "status": "ok",
        "time": datetime.now().isoformat()
    }), 200

# --------------------------
# Rutas de autenticación
# --------------------------
@app.post('/auth/register')
def register():
    # Validar que sea multipart/form-data
    if 'foto_identificacion' not in request.files:
        return jsonify({"error": "Se requiere fotografía de identificación."}), 400
    
    file = request.files['foto_identificacion']
    if file.filename == '':
        return jsonify({"error": "No se seleccionó ningún archivo."}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "Formato de archivo no válido. Solo se permiten PNG, JPG, JPEG."}), 400
    
    # Validar datos del formulario
    form_data = request.form.to_dict()
    validation_errors = validate_user_data(form_data)
    
    if validation_errors:
        return jsonify({"error": ", ".join(validation_errors)}), 400
    
    # Normalizar email
    try:
        email = _normalize_email(form_data['email'])
    except ValueError as e:
        return jsonify({"error": f"Email inválido: {str(e)}"}), 400
    
    # Verificar si el email ya existe
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "El email ya está registrado."}), 409
    
    # Guardar archivo de identificación
    filename = secure_filename(file.filename)
    file_extension = filename.rsplit('.', 1)[1].lower()
    
    # Crear nombre único para el archivo
    unique_filename = f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(file_path)
    except Exception as e:
        return jsonify({"error": "Error al guardar el archivo de identificación."}), 500
    
    # Crear usuario
    try:
        user = User(
            email=email,
            nombre_completo=form_data['nombre_completo'].strip(),
            apellidos=form_data['apellidos'].strip(),
            direccion=form_data['direccion'].strip(),
            edad=int(form_data['edad']),
            telefono=form_data['telefono'].strip(),
            role=form_data['role'],
            is_authorized=False,  # Requiere autorización de admin
            foto_identificacion_path=file_path
        )
        user.set_password(form_data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        # Renombrar archivo con ID del usuario
        new_filename = f"user_{user.id}_id.{file_extension}"
        new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        
        os.rename(file_path, new_file_path)
        user.foto_identificacion_path = new_file_path
        db.session.commit()
        
        return jsonify({
            "message": "Usuario registrado exitosamente. Pendiente de autorización por un administrador.",
            "user": user.to_dict()
        }), 201
        
    except Exception as e:
        # Limpiar archivo si hay error
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.rollback()
        return jsonify({"error": "Error interno del servidor."}), 500

@app.post("/auth/login")
def login():
    data, error_response = _require_json(["email", "password"])
    if error_response:
        return error_response

    try:
        email = _normalize_email(data["email"])
    except ValueError as ve:
        return jsonify({"error": f"Email inválido: {ve}"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(data["password"]):
        # No revelar si el email existe
        return jsonify({"error": "Credenciales inválidas."}), 401
    
    # Verificar si el usuario está autorizado (excepto para admins)
    if user.role != 'admin' and not user.is_authorized:
        return jsonify({
            "error": "Tu cuenta está pendiente de autorización. Por favor espera a que un administrador apruebe tu registro."
        }), 403

    claims = {"email": user.email, "role": user.role, "is_authorized": user.is_authorized}
    access_token = create_access_token(identity=str(user.id), additional_claims=claims)
    refresh_token = create_refresh_token(identity=str(user.id))
    return jsonify({
        "message": "Login exitoso.",
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

@app.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    # Reconstituimos claims actuales (por si el rol cambió desde la emisión anterior)
    user = User.query.get(int(uid)) if uid is not None else None
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    
    # Verificar que el usuario siga autorizado (excepto admins)
    if user.role != 'admin' and not user.is_authorized:
        return jsonify({
            "error": "Tu cuenta ya no está autorizada."
        }), 401
    
    claims = {"email": user.email, "role": user.role, "is_authorized": user.is_authorized}
    access_token = create_access_token(identity=str(uid), additional_claims=claims)
    return jsonify({"access_token": access_token}), 200

# --------------------------
# Endpoints protegidos y públicos
# --------------------------
@app.get("/profile")
@jwt_required()
def profile():
    uid = get_jwt_identity()
    user = User.query.get(int(uid))
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    return jsonify({"user": user.to_dict()}), 200

# --------------------------
# Endpoints administrativos
# --------------------------
@app.get('/admin/users/pending')
@role_required('admin')
def get_pending_users():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100
    role_filter = request.args.get('role', None)
    
    query = User.query.filter_by(is_authorized=False)
    
    if role_filter and role_filter in ['voluntarios', 'personal', 'servicio_social', 
                                       'visitas', 'familiares', 'donantes', 'proveedores']:
        query = query.filter_by(role=role_filter)
    
    paginated = query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    users = [user.to_dict() for user in paginated.items]
    
    return jsonify({
        "users": users,
        "total": paginated.total,
        "page": page,
        "per_page": per_page,
        "total_pages": paginated.pages
    }), 200

@app.post('/admin/users/<int:user_id>/authorize')
@role_required('admin')
def authorize_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    
    if user.is_authorized:
        return jsonify({"error": "El usuario ya está autorizado."}), 400
    
    # Obtener ID del admin que autoriza
    admin_id = int(get_jwt_identity())
    
    # Autorizar usuario
    user.is_authorized = True
    user.authorized_at = datetime.now()
    user.authorized_by_id = admin_id
    
    db.session.commit()
    
    return jsonify({
        "message": "Usuario autorizado exitosamente.",
        "user": user.to_dict()
    }), 200

@app.post('/admin/users/<int:user_id>/reject')
@role_required('admin')
def reject_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    
    if user.is_authorized:
        return jsonify({"error": "No se puede rechazar un usuario ya autorizado."}), 400
    
    # Eliminar archivo de identificación si existe
    if user.foto_identificacion_path and os.path.exists(user.foto_identificacion_path):
        try:
            os.remove(user.foto_identificacion_path)
        except Exception:
            pass  # No fallar si no se puede eliminar el archivo
    
    # Eliminar usuario
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({
        "message": "Usuario rechazado y eliminado exitosamente."
    }), 200

@app.get('/admin/users/<int:user_id>/identification')
@role_required('admin')
def get_user_identification(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    
    if not user.foto_identificacion_path or not os.path.exists(user.foto_identificacion_path):
        return jsonify({"error": "Fotografía de identificación no encontrada."}), 404
    
    try:
        return send_file(user.foto_identificacion_path)
    except Exception as e:
        return jsonify({"error": "Error al acceder al archivo de identificación."}), 500

@app.get("/admin/stats")
@role_required('admin')  # Solo ADMIN
def admin_stats():
    total_users = User.query.count()
    total_authorized = User.query.filter_by(is_authorized=True).count()
    total_pending = User.query.filter_by(is_authorized=False).count()
    
    # Contar por roles
    roles_count = {}
    all_roles = ['admin', 'voluntarios', 'personal', 'servicio_social', 
                 'visitas', 'familiares', 'donantes', 'proveedores']
    
    for role in all_roles:
        roles_count[role] = User.query.filter_by(role=role).count()
    
    return jsonify({
        "users_total": total_users,
        "users_authorized": total_authorized,
        "users_pending": total_pending,
        "users_by_role": roles_count
    }), 200


if __name__ == '__main__':
    app.run(debug=True, port=8000)
