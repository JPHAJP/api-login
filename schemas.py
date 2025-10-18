from datetime import datetime
from typing import Optional, Dict, Any, List
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
    authorization_status: str  # pending, authorized, unauthorized
    authorization_info: Optional[str] = None  # Información adicional opcional
    created_at: datetime
    authorized_at: Optional[datetime] = None
    unauthorized_at: Optional[datetime] = None
    
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

# Esquemas para QR Code
class QRCodeResponse(BaseModel):
    code: str
    created_at: datetime
    expires_at: datetime
    is_active: bool
    is_expired: bool
    
    class Config:
        from_attributes = True

class QRCodeGenerate(BaseModel):
    qr_image: str  # Base64 encoded image
    code: str
    expires_at: datetime

# Esquemas para Access Log
class AccessLogCreate(BaseModel):
    user_id: int
    access_type: str = Field(..., pattern="^(entry|exit)$")
    notes: Optional[str] = None

class AccessLogResponse(BaseModel):
    id: int
    user_id: int
    user_name: str
    user_email: str
    qr_code_id: int
    access_type: str
    timestamp: datetime
    notes: Optional[str] = None
    is_manual: bool
    manual_by_admin_id: Optional[int] = None
    manual_by_admin_name: Optional[str] = None
    
    class Config:
        from_attributes = True

class AccessLogStats(BaseModel):
    total_entries: int
    total_exits: int
    currently_inside: int
    logs: List[AccessLogResponse]

class UserCurrentlyInside(BaseModel):
    id: int
    email: str
    nombre_completo: str
    apellidos: str
    role: str
    entry_time: datetime
    entry_id: int
    
    class Config:
        from_attributes = True

class ManualExitRequest(BaseModel):
    notes: Optional[str] = None

# QR Scanner request
class QRScanRequest(BaseModel):
    qr_code: str
    access_type: str = Field(..., pattern="^(entry|exit)$")

# Admin user search and listing
class UserDetailedResponse(BaseModel):
    id: int
    email: str
    nombre_completo: str
    apellidos: str
    direccion: str
    edad: int
    telefono: str
    role: str
    is_authorized: bool
    authorization_status: str  # 'pending', 'authorized', 'unauthorized'
    authorization_info: Optional[str] = None  # Razón o información adicional
    foto_identificacion_path: Optional[str] = None
    created_at: datetime
    authorized_at: Optional[datetime] = None
    unauthorized_at: Optional[datetime] = None
    authorized_by_id: Optional[int] = None
    authorized_by_name: Optional[str] = None
    unauthorized_by_id: Optional[int] = None
    unauthorized_by_name: Optional[str] = None

class UserSearchResponse(BaseModel):
    users: List[UserDetailedResponse]
    total: int
    page: int
    per_page: int
    total_pages: int

# Admin user authorization management
class UnauthorizeUserRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=500)

class UserAuthorizationResponse(BaseModel):
    message: str
    user: UserDetailedResponse
    action_by: str
    reason: Optional[str] = None

# User deletion check
class UserDeletionCheckResponse(BaseModel):
    can_delete: bool
    user_id: int
    user_name: str
    reasons_cannot_delete: List[str]
    recommended_action: str

# User authorization status check
class UserAuthStatusResponse(BaseModel):
    user_id: int
    email: str
    nombre_completo: str
    authorization_status: str  # pending, authorized, unauthorized
    authorization_info: Optional[str] = None
    can_login: bool
    can_access_qr: bool
    authorized_at: Optional[datetime] = None
    unauthorized_at: Optional[datetime] = None
    authorized_by_name: Optional[str] = None
    unauthorized_by_name: Optional[str] = None
    message: str