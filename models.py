from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
ROLE_CHOICES = ("admin", "voluntarios", "personal", "servicio_social", "visitas", "familiares", "donantes", "proveedores")

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nombre_completo = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=False)
    direccion = db.Column(db.String(255), nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    telefono = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="voluntarios", server_default="voluntarios", index=True)
    is_authorized = db.Column(db.Boolean, nullable=False, default=False, server_default='0', index=True)
    foto_identificacion_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    authorized_at = db.Column(db.DateTime, nullable=True)
    authorized_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relación para saber qué admin autorizó al usuario
    authorized_by = db.relationship('User', remote_side=[id], backref='authorized_users')

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)
    
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