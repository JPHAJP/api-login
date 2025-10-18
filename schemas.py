from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr, field_validator, Field
import re

class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    nombre_completo: str = Field(..., min_length=1, max_length=100)
    apellidos: str = Field(..., min_length=1, max_length=100)
    direccion: str = Field(..., min_length=1, max_length=255)
    edad: int = Field(..., ge=18, le=120)
    telefono: str = Field(..., min_length=10, max_length=20)
    role: str = Field(..., pattern="^(voluntarios|personal|servicio_social|visitas|familiares|donantes|proveedores)$")
    
    @field_validator('telefono')
    @classmethod
    def validate_phone(cls, v):
        pattern = r'^\+?[0-9]{10,15}$'
        if not re.match(pattern, v):
            raise ValueError('Formato de teléfono inválido (debe tener 10-15 dígitos)')
        return v
    
    @field_validator('nombre_completo', 'apellidos', 'direccion')
    @classmethod
    def validate_strings(cls, v):
        if not v.strip():
            raise ValueError('El campo no puede estar vacío')
        return v.strip()

class UserResponse(BaseModel):
    id: int
    email: str
    nombre_completo: str
    apellidos: str
    direccion: str
    edad: int
    telefono: str
    role: str
    is_authorized: bool
    created_at: datetime
    authorized_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class UserPendingResponse(BaseModel):
    id: int
    email: str
    nombre_completo: str
    apellidos: str
    direccion: str
    edad: int
    telefono: str
    role: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    nombre_completo: Optional[str] = Field(None, min_length=1, max_length=100)
    apellidos: Optional[str] = Field(None, min_length=1, max_length=100)
    direccion: Optional[str] = Field(None, min_length=1, max_length=255)
    edad: Optional[int] = Field(None, ge=18, le=120)
    telefono: Optional[str] = Field(None, min_length=10, max_length=20)
    
    @field_validator('telefono')
    @classmethod
    def validate_phone(cls, v):
        if v is not None:
            pattern = r'^\+?[0-9]{10,15}$'
            if not re.match(pattern, v):
                raise ValueError('Formato de teléfono inválido (debe tener 10-15 dígitos)')
        return v
    
    @field_validator('nombre_completo', 'apellidos', 'direccion')
    @classmethod
    def validate_strings(cls, v):
        if v is not None and not v.strip():
            raise ValueError('El campo no puede estar vacío')
        return v.strip() if v else v

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenRefresh(BaseModel):
    access_token: str

class AdminStats(BaseModel):
    users_total: int
    users_authorized: int
    users_pending: int
    users_by_role: Dict[str, int]

class MessageResponse(BaseModel):
    message: str
    
class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None