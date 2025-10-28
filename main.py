import ipaddress
from datetime import datetime
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from database import engine
from models import Base
from routes.auth import router as auth_router
from routes.user import router as user_router
from routes.admin import router as admin_router
from routes.images import router as images_router

load_dotenv()

# Crear las tablas
Base.metadata.create_all(bind=engine)

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

# Incluir las rutas
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(admin_router)
app.include_router(images_router)

# Endpoints públicos
@app.get('/health')
async def health():
    return {
        "status": "ok",
        "time": datetime.now().isoformat(),
        "version": "2.0.0"
    }

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)