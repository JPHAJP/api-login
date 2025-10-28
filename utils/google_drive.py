"""
Utilidades para integración con Google Drive
Permite subir, descargar y gestionar archivos en Google Drive
"""
import os
import io
from typing import Optional, Dict, Any
from datetime import datetime

from google.oauth2.credentials import Credentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

# Scopes necesarios para Drive
SCOPES = ['https://www.googleapis.com/auth/drive.file']

class GoogleDriveManager:
    """Clase para manejar operaciones con Google Drive"""
    
    def __init__(self, credentials_path: str = None, token_path: str = None, service_account_path: str = None):
        """
        Inicializar el manager de Google Drive
        
        Args:
            credentials_path: Ruta al archivo credentials.json (OAuth)
            token_path: Ruta al archivo token.json (OAuth)
            service_account_path: Ruta al archivo de service account (recomendado para producción)
        """
        self.credentials_path = credentials_path or os.getenv('GOOGLE_CREDENTIALS_PATH', 'credentials.json')
        self.token_path = token_path or os.getenv('GOOGLE_TOKEN_PATH', 'token.json')
        self.service_account_path = service_account_path or os.getenv('GOOGLE_SERVICE_ACCOUNT_PATH')
        self.service = None
        self.folder_id = os.getenv('GOOGLE_DRIVE_FOLDER_ID')  # Carpeta específica para las imágenes
        
    def _authenticate(self):
        """Autenticar con Google Drive API"""
        creds = None
        
        # Intentar usar service account primero (recomendado para producción)
        if self.service_account_path and os.path.exists(self.service_account_path):
            try:
                creds = ServiceAccountCredentials.from_service_account_file(
                    self.service_account_path, scopes=SCOPES
                )
            except Exception as e:
                print(f"Error con service account: {e}")
        
        # Si no hay service account, usar OAuth
        if not creds:
            # Verificar si ya existe token
            if os.path.exists(self.token_path):
                try:
                    creds = Credentials.from_authorized_user_file(self.token_path, SCOPES)
                except Exception as e:
                    print(f"Error cargando token: {e}")
                    os.remove(self.token_path)  # Eliminar token corrupto
            
            # Si no hay credenciales válidas, hacer flujo de autorización
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    try:
                        creds.refresh(Request())
                    except Exception as e:
                        print(f"Error refrescando token: {e}")
                        creds = None
                
                if not creds:
                    if not os.path.exists(self.credentials_path):
                        raise FileNotFoundError(
                            f"Archivo de credenciales no encontrado: {self.credentials_path}. "
                            "Descárgalo desde Google Cloud Console."
                        )
                    
                    flow = InstalledAppFlow.from_client_secrets_file(self.credentials_path, SCOPES)
                    creds = flow.run_local_server(port=0)
                
                # Guardar las credenciales para la próxima ejecución
                with open(self.token_path, 'w') as token:
                    token.write(creds.to_json())
        
        self.service = build('drive', 'v3', credentials=creds)
        return self.service
    
    def upload_file(self, file_content: bytes, filename: str, mime_type: str = None) -> Dict[str, Any]:
        """
        Subir un archivo a Google Drive
        
        Args:
            file_content: Contenido del archivo en bytes
            filename: Nombre del archivo
            mime_type: Tipo MIME del archivo
            
        Returns:
            Diccionario con información del archivo subido
        """
        if not self.service:
            self._authenticate()
        
        try:
            # Configurar metadata del archivo
            file_metadata = {
                'name': filename
            }
            
            # Si hay una carpeta específica, colocar el archivo ahí
            if self.folder_id:
                file_metadata['parents'] = [self.folder_id]
            
            # Crear upload desde bytes
            media = MediaIoBaseUpload(
                io.BytesIO(file_content),
                mimetype=mime_type or 'application/octet-stream',
                resumable=True
            )
            
            # Subir archivo
            uploaded_file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id,name,size,createdTime,mimeType'
            ).execute()
            
            # Hacer el archivo accesible (opcional, según tus necesidades)
            # self._make_file_public(uploaded_file.get('id'))
            
            return {
                'success': True,
                'file_id': uploaded_file.get('id'),
                'name': uploaded_file.get('name'),
                'size': uploaded_file.get('size'),
                'created_time': uploaded_file.get('createdTime'),
                'mime_type': uploaded_file.get('mimeType'),
                'drive_url': f"https://drive.google.com/file/d/{uploaded_file.get('id')}/view"
            }
            
        except HttpError as error:
            return {
                'success': False,
                'error': f'Error HTTP: {error}',
                'error_code': error.resp.status
            }
        except Exception as error:
            return {
                'success': False,
                'error': f'Error inesperado: {str(error)}'
            }
    
    def download_file(self, file_id: str) -> Dict[str, Any]:
        """
        Descargar un archivo de Google Drive
        
        Args:
            file_id: ID del archivo en Google Drive
            
        Returns:
            Diccionario con el contenido del archivo y metadatos
        """
        if not self.service:
            self._authenticate()
        
        try:
            # Obtener metadata del archivo
            file_metadata = self.service.files().get(fileId=file_id).execute()
            
            # Descargar contenido
            request = self.service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            
            done = False
            while not done:
                status, done = downloader.next_chunk()
            
            fh.seek(0)
            content = fh.read()
            
            return {
                'success': True,
                'content': content,
                'metadata': file_metadata
            }
            
        except HttpError as error:
            return {
                'success': False,
                'error': f'Error HTTP: {error}',
                'error_code': error.resp.status
            }
        except Exception as error:
            return {
                'success': False,
                'error': f'Error inesperado: {str(error)}'
            }
    
    def delete_file(self, file_id: str) -> Dict[str, Any]:
        """
        Eliminar un archivo de Google Drive
        
        Args:
            file_id: ID del archivo en Google Drive
            
        Returns:
            Diccionario con el resultado de la operación
        """
        if not self.service:
            self._authenticate()
        
        try:
            self.service.files().delete(fileId=file_id).execute()
            return {
                'success': True,
                'message': 'Archivo eliminado correctamente'
            }
            
        except HttpError as error:
            return {
                'success': False,
                'error': f'Error HTTP: {error}',
                'error_code': error.resp.status
            }
        except Exception as error:
            return {
                'success': False,
                'error': f'Error inesperado: {str(error)}'
            }
    
    def _make_file_public(self, file_id: str):
        """Hacer un archivo público (opcional)"""
        try:
            permission = {
                'type': 'anyone',
                'role': 'reader'
            }
            self.service.permissions().create(
                fileId=file_id,
                body=permission
            ).execute()
        except Exception as e:
            print(f"No se pudo hacer público el archivo: {e}")
    
    def create_folder(self, folder_name: str) -> Dict[str, Any]:
        """
        Crear una carpeta en Google Drive
        
        Args:
            folder_name: Nombre de la carpeta
            
        Returns:
            Diccionario con información de la carpeta creada
        """
        if not self.service:
            self._authenticate()
        
        try:
            file_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            folder = self.service.files().create(body=file_metadata, fields='id').execute()
            
            return {
                'success': True,
                'folder_id': folder.get('id'),
                'message': f'Carpeta "{folder_name}" creada correctamente'
            }
            
        except HttpError as error:
            return {
                'success': False,
                'error': f'Error HTTP: {error}',
                'error_code': error.resp.status
            }
        except Exception as error:
            return {
                'success': False,
                'error': f'Error inesperado: {str(error)}'
            }

# Instancia global del manager
drive_manager = GoogleDriveManager()

def upload_identification_image(content: bytes, user_id: int, file_extension: str) -> Dict[str, Any]:
    """
    Función específica para subir imágenes de identificación
    
    Args:
        content: Contenido del archivo en bytes
        user_id: ID del usuario
        file_extension: Extensión del archivo
        
    Returns:
        Diccionario con información del archivo subido
    """
    # Crear nombre único para el archivo
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"user_{user_id}_identification_{timestamp}.{file_extension}"
    
    # Determinar tipo MIME
    mime_types = {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png'
    }
    mime_type = mime_types.get(file_extension.lower(), 'image/jpeg')
    
    return drive_manager.upload_file(content, filename, mime_type)

def download_identification_image(file_id: str) -> Dict[str, Any]:
    """
    Función específica para descargar imágenes de identificación
    
    Args:
        file_id: ID del archivo en Google Drive
        
    Returns:
        Diccionario con el contenido del archivo
    """
    return drive_manager.download_file(file_id)

def delete_identification_image(file_id: str) -> Dict[str, Any]:
    """
    Función específica para eliminar imágenes de identificación
    
    Args:
        file_id: ID del archivo en Google Drive
        
    Returns:
        Diccionario con el resultado de la operación
    """
    return drive_manager.delete_file(file_id)