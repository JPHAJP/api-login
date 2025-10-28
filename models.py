from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import bcrypt
import enum

Base = declarative_base()

ROLE_CHOICES = ("admin", "voluntarios", "personal", "servicio_social", "visitas", "familiares", "donantes", "proveedores")

class AccessType(enum.Enum):
    ENTRY = "entry"
    EXIT = "exit"

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    nombre_completo = Column(String(100), nullable=False)
    apellidos = Column(String(100), nullable=False)
    direccion = Column(String(255), nullable=False)
    edad = Column(Integer, nullable=False)
    telefono = Column(String(20), nullable=False)
    role = Column(String(20), nullable=False, default="voluntarios", index=True)
    is_authorized = Column(Boolean, nullable=False, default=False, index=True)
    authorization_status = Column(String(20), nullable=False, default="pending", index=True)  # pending, authorized, unauthorized
    authorization_info = Column(Text, nullable=False, default="Pendiente de autorización")
    foto_identificacion_path = Column(String(255), nullable=True)  # Mantener para compatibilidad
    foto_identificacion_drive_id = Column(String(255), nullable=True)  # ID de Google Drive
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    authorized_at = Column(DateTime, nullable=True)
    unauthorized_at = Column(DateTime, nullable=True)  # Nueva fecha de desautorización
    authorized_by_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    unauthorized_by_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # Admin que desautorizó
    
    # Relación para saber qué admin autorizó al usuario
    authorized_by = relationship('User', remote_side=[id], back_populates='authorized_users', foreign_keys=[authorized_by_id])
    authorized_users = relationship('User', remote_side=[authorized_by_id], foreign_keys=[authorized_by_id])
    
    # Relación para saber qué admin desautorizó al usuario
    unauthorized_by = relationship('User', remote_side=[id], foreign_keys=[unauthorized_by_id])
    
    # Relación con los logs de acceso
    access_logs = relationship('AccessLog', foreign_keys='AccessLog.user_id', back_populates='user')

    def set_password(self, raw_password: str):
        # Convertir la contraseña a bytes y generar hash
        password_bytes = raw_password.encode('utf-8')
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')

    def check_password(self, raw_password: str) -> bool:
        # Verificar la contraseña
        try:
            # Validar que el hash existe y no está vacío
            if not self.password_hash:
                return False
            
            # Validar que el hash tiene el formato correcto de bcrypt
            if not (self.password_hash.startswith('$2a$') or 
                    self.password_hash.startswith('$2b$') or 
                    self.password_hash.startswith('$2y$')):
                return False
            
            # Validar que el hash tiene la longitud correcta (60 caracteres)
            if len(self.password_hash) != 60:
                return False
                
            password_bytes = raw_password.encode('utf-8')
            hash_bytes = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hash_bytes)
            
        except ValueError as e:
            # Log del error para debugging
            print(f"Error de validación de contraseña para usuario {self.email}: {e}")
            return False
        except Exception as e:
            # Log de cualquier otro error
            print(f"Error inesperado al validar contraseña para usuario {self.email}: {e}")
            return False
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'nombre_completo': self.nombre_completo,
            'apellidos': self.apellidos,
            'direccion': self.direccion,
            'edad': self.edad,
            'telefono': self.telefono,
            'role': self.role,
            'is_authorized': self.is_authorized,
            'authorization_status': self.authorization_status,
            'authorization_info': self.authorization_info,
            'foto_identificacion_path': self.foto_identificacion_path,
            'foto_identificacion_drive_id': self.foto_identificacion_drive_id,
            "created_at": self.created_at.isoformat() if hasattr(self, 'created_at') else None,
            "authorized_at": self.authorized_at.isoformat() if hasattr(self, 'authorized_at') and self.authorized_at else None,
            "unauthorized_at": self.unauthorized_at.isoformat() if hasattr(self, 'unauthorized_at') and self.unauthorized_at else None
        }

    def __repr__(self):
        return f"User('{self.nombre_completo} {self.apellidos}', '{self.email}'), role='{self.role}', authorized={self.is_authorized})"


class QRCode(Base):
    __tablename__ = 'qr_codes'
    
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Relaciones
    access_logs = relationship('AccessLog', back_populates='qr_code')
    
    def is_expired(self):
        return datetime.now() > self.expires_at
    
    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'is_active': self.is_active,
            'is_expired': self.is_expired()
        }
    
    def __repr__(self):
        return f"QRCode(code='{self.code}', expires_at='{self.expires_at}', active={self.is_active})"


class AccessLog(Base):
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    qr_code_id = Column(Integer, ForeignKey('qr_codes.id'), nullable=False)
    access_type = Column(Enum(AccessType), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)
    notes = Column(Text, nullable=True)  # Para notas del admin en caso de registro manual
    is_manual = Column(Boolean, default=False, nullable=False)  # Si fue registrado manualmente por admin
    manual_by_admin_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # Admin que hizo el registro manual
    
    # Relaciones
    user = relationship('User', foreign_keys=[user_id], back_populates='access_logs')
    qr_code = relationship('QRCode', back_populates='access_logs')
    manual_by_admin = relationship('User', foreign_keys=[manual_by_admin_id])
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_name': f"{self.user.nombre_completo} {self.user.apellidos}" if self.user else None,
            'user_email': self.user.email if self.user else None,
            'qr_code_id': self.qr_code_id,
            'access_type': self.access_type.value,
            'timestamp': self.timestamp.isoformat(),
            'notes': self.notes,
            'is_manual': self.is_manual,
            'manual_by_admin_id': self.manual_by_admin_id,
            'manual_by_admin_name': f"{self.manual_by_admin.nombre_completo} {self.manual_by_admin.apellidos}" if self.manual_by_admin else None
        }
    
    def __repr__(self):
        return f"AccessLog(user_id={self.user_id}, type='{self.access_type.value}', timestamp='{self.timestamp}')"