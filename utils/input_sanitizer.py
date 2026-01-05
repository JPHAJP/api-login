"""
Input Sanitizer
===============

Sistema de sanitización de inputs para prevenir:
- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- Command Injection
- HTML Injection

Uso:
    from utils.input_sanitizer import sanitize_string, sanitize_html
    
    clean_name = sanitize_string("Juan<script>alert('xss')</script>")
    # Output: "Juan"
"""

import re
import html
import unicodedata
from typing import Optional


class InputSanitizer:
    """Clase para sanitización de diferentes tipos de inputs"""
    
    # Patrones peligrosos SQL
    SQL_PATTERNS = [
        r"'",           # Comillas simples
        r'"',           # Comillas dobles
        r';',           # Punto y coma
        r'--',          # Comentarios SQL
        r'/\*',         # Comentarios multilínea
        r'\*/',         # Fin comentarios
        r'xp_',         # Stored procedures
        r'sp_',         # Stored procedures
        r'\bOR\b',      # OR lógico
        r'\bAND\b',     # AND lógico
        r'\bUNION\b',   # UNION
        r'\bSELECT\b',  # SELECT
        r'\bINSERT\b',  # INSERT
        r'\bUPDATE\b',  # UPDATE
        r'\bDELETE\b',  # DELETE
        r'\bDROP\b',    # DROP
        r'\bEXEC\b',    # EXEC
    ]
    
    # Patrones path traversal
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.',        # ..
        r'\./',         # ./
        r'\.\.',        # ..
        r'%2e%2e',      # URL encoded ..
        r'%252e%252e',  # Double URL encoded ..
    ]
    
    # Caracteres de control
    CONTROL_CHARS = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
                     '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f']
    
    @staticmethod
    def sanitize_string(
        text: str,
        allow_html: bool = False,
        max_length: Optional[int] = None,
        allow_special_chars: bool = False
    ) -> str:
        """
        Sanitiza un string general removiendo caracteres peligrosos
        
        Args:
            text: Texto a sanitizar
            allow_html: Si permite HTML (default: False)
            max_length: Longitud máxima (default: None)
            allow_special_chars: Permite caracteres especiales adicionales
            
        Returns:
            String sanitizado
        """
        if not text:
            return ""
        
        # Normalizar unicode
        text = unicodedata.normalize('NFKC', text)
        
        # Remover caracteres de control
        for char in InputSanitizer.CONTROL_CHARS:
            text = text.replace(char, '')
        
        # Remover caracteres de control adicionales
        text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        
        # Remover HTML tags si no están permitidos
        if not allow_html:
            text = InputSanitizer.sanitize_html(text)
        
        # Remover patrones SQL peligrosos
        text = InputSanitizer._remove_sql_patterns(text)
        
        # Remover espacios múltiples
        text = re.sub(r'\s+', ' ', text)
        
        # Trim
        text = text.strip()
        
        # Aplicar longitud máxima
        if max_length and len(text) > max_length:
            text = text[:max_length]
        
        return text
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """
        Remueve todos los tags HTML y JavaScript
        
        Args:
            text: Texto con posible HTML
            
        Returns:
            Texto sin HTML
        """
        if not text:
            return ""
        
        # Remover tags HTML
        text = re.sub(r'<[^>]+>', '', text)
        
        # Escapar entidades HTML restantes
        text = html.escape(text)
        
        # Remover eventos JavaScript
        text = re.sub(r'on\w+\s*=\s*["\'].*?["\']', '', text, flags=re.IGNORECASE)
        
        # Remover javascript: URLs
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        
        return text
    
    @staticmethod
    def sanitize_name(name: str) -> str:
        """
        Sanitiza nombres de personas (nombre_completo, apellidos)
        
        Permite:
        - Letras (incluido ñ, tildes)
        - Espacios
        - Guiones
        - Apóstrofes
        
        Args:
            name: Nombre a sanitizar
            
        Returns:
            Nombre sanitizado
        """
        if not name:
            return ""
        
        # Normalizar unicode
        name = unicodedata.normalize('NFKC', name)
        
        # Remover HTML
        name = InputSanitizer.sanitize_html(name)
        
        # Permitir solo letras, espacios, guiones y apóstrofes
        # Incluye letras con tildes, ñ, etc.
        name = re.sub(r"[^a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s\-']", '', name)
        
        # Remover espacios múltiples
        name = re.sub(r'\s+', ' ', name)
        
        # Remover guiones/apóstrofes múltiples
        name = re.sub(r"[-']+", lambda m: m.group()[0], name)
        
        # Trim
        name = name.strip()
        
        return name
    
    @staticmethod
    def sanitize_address(address: str) -> str:
        """
        Sanitiza direcciones
        
        Permite:
        - Letras y números
        - Espacios, comas, puntos
        - #, -, °
        
        Args:
            address: Dirección a sanitizar
            
        Returns:
            Dirección sanitizada
        """
        if not address:
            return ""
        
        # Normalizar unicode
        address = unicodedata.normalize('NFKC', address)
        
        # Remover HTML
        address = InputSanitizer.sanitize_html(address)
        
        # Remover path traversal
        for pattern in InputSanitizer.PATH_TRAVERSAL_PATTERNS:
            address = re.sub(pattern, '', address, flags=re.IGNORECASE)
        
        # Permitir letras, números, espacios y ciertos caracteres
        address = re.sub(r"[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s,.\-#°]", '', address)
        
        # Remover espacios múltiples
        address = re.sub(r'\s+', ' ', address)
        
        # Trim
        address = address.strip()
        
        return address
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitiza nombres de archivo
        
        Args:
            filename: Nombre de archivo a sanitizar
            
        Returns:
            Nombre de archivo seguro
        """
        if not filename:
            return ""
        
        # Normalizar unicode
        filename = unicodedata.normalize('NFKC', filename)
        
        # Remover path traversal
        for pattern in InputSanitizer.PATH_TRAVERSAL_PATTERNS:
            filename = re.sub(pattern, '', filename, flags=re.IGNORECASE)
        
        # Remover caracteres peligrosos
        filename = re.sub(r'[<>:"|?*\x00-\x1f]', '', filename)
        
        # Remover espacios al inicio/fin
        filename = filename.strip()
        
        # Reemplazar espacios múltiples con uno solo
        filename = re.sub(r'\s+', '_', filename)
        
        # Limitar longitud
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            name = name[:250]
            filename = f"{name}.{ext}" if ext else name
        
        return filename
    
    @staticmethod
    def _remove_sql_patterns(text: str) -> str:
        """
        Remueve patrones SQL peligrosos
        
        Args:
            text: Texto a limpiar
            
        Returns:
            Texto sin patrones SQL
        """
        for pattern in InputSanitizer.SQL_PATTERNS:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        return text
    
    @staticmethod
    def is_safe_string(text: str, max_length: int = 1000) -> bool:
        """
        Verifica si un string es seguro
        
        Args:
            text: Texto a verificar
            max_length: Longitud máxima permitida
            
        Returns:
            True si es seguro, False en caso contrario
        """
        if not text:
            return True
        
        # Verificar longitud
        if len(text) > max_length:
            return False
        
        # Verificar patrones SQL
        for pattern in InputSanitizer.SQL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return False
        
        # Verificar HTML tags
        if re.search(r'<[^>]+>', text):
            return False
        
        # Verificar path traversal
        for pattern in InputSanitizer.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return False
        
        return True


# Funciones helper para uso rápido
def sanitize_string(text: str, max_length: Optional[int] = None) -> str:
    """Helper function para sanitizar strings"""
    return InputSanitizer.sanitize_string(text, max_length=max_length)


def sanitize_html(text: str) -> str:
    """Helper function para remover HTML"""
    return InputSanitizer.sanitize_html(text)


def sanitize_name(name: str) -> str:
    """Helper function para sanitizar nombres"""
    return InputSanitizer.sanitize_name(name)


def sanitize_address(address: str) -> str:
    """Helper function para sanitizar direcciones"""
    return InputSanitizer.sanitize_address(address)


def sanitize_filename(filename: str) -> str:
    """Helper function para sanitizar nombres de archivo"""
    return InputSanitizer.sanitize_filename(filename)
