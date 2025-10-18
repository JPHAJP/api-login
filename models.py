from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import bcrypt

Base = declarative_base()

ROLE_CHOICES = ("admin", "voluntarios", "personal", "servicio_social", "visitas", "familiares", "donantes", "proveedores")

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
    foto_identificacion_path = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    authorized_at = Column(DateTime, nullable=True)
    authorized_by_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # Relación para saber qué admin autorizó al usuario
    authorized_by = relationship('User', remote_side=[id], back_populates='authorized_users')
    authorized_users = relationship('User', remote_side=[authorized_by_id])

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
            'foto_identificacion_path': self.foto_identificacion_path,
            "created_at": self.created_at.isoformat() if hasattr(self, 'created_at') else None,
            "authorized_at": self.authorized_at.isoformat() if hasattr(self, 'authorized_at') and self.authorized_at else None
        }

    def __repr__(self):
        return f"User('{self.nombre_completo} {self.apellidos}', '{self.email}'), role='{self.role}', authorized={self.is_authorized})"