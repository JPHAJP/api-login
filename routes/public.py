from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from database import get_db
from utils.qr import get_or_create_current_qr, create_qr_image, QR_EXPIRY_MINUTES
from utils.websocket import manager

router = APIRouter(prefix="/public", tags=["Public"])

@router.get("/qr/current")
async def get_current_qr(db: Session = Depends(get_db)):
    """
    Obtiene el código QR actual para el modo Kiosko.
    No requiere autenticación.
    """
    qr_code = get_or_create_current_qr(db)
    
    # Generar imagen base64
    qr_image = create_qr_image(qr_code.code)
    
    # Calcular segundos restantes
    now = datetime.now()
    remaining_seconds = (qr_code.expires_at - now).total_seconds()
    
    return {
        "code": qr_code.code,
        "image": f"data:image/png;base64,{qr_image}",
        "expires_at": qr_code.expires_at.isoformat(),
        "expires_in_seconds": max(0, int(remaining_seconds)),
        "refresh_interval": QR_EXPIRY_MINUTES * 60  
    }

@router.websocket("/ws/kiosk")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Mantener la conexión viva
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
