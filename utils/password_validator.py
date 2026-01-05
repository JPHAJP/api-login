"""
Validador de contraseñas fuertes
=================================

Valida que las contraseñas cumplan con los requisitos de seguridad:
- Mínimo 8 caracteres
- Al menos una mayúscula
- Al menos una minúscula
- Al menos un número
- Al menos un carácter especial
- No estar en la lista de contraseñas comunes
"""

import re
from typing import Dict, List
from .common_passwords import COMMON_PASSWORDS


class PasswordStrength:
    """Resultado de la validación de contraseña"""
    
    def __init__(self, is_valid: bool, score: int, errors: List[str], suggestions: List[str]):
        self.is_valid = is_valid
        self.score = score  # 0-100
        self.errors = errors
        self.suggestions = suggestions
        self.strength = self._get_strength_label(score)
    
    def _get_strength_label(self, score: int) -> str:
        """Retorna etiqueta de fortaleza"""
        if score < 25:
            return "muy_débil"
        elif score < 50:
            return "débil"
        elif score < 75:
            return "media"
        elif score < 90:
            return "fuerte"
        else:
            return "muy_fuerte"
    
    def to_dict(self) -> Dict:
        """Convierte a diccionario"""
        return {
            "is_valid": self.is_valid,
            "score": self.score,
            "strength": self.strength,
            "errors": self.errors,
            "suggestions": self.suggestions
        }


class PasswordValidator:
    """Validador de contraseñas con múltiples criterios"""
    
    # Requisitos mínimos
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    # Patrones regex
    UPPERCASE_PATTERN = re.compile(r'[A-Z]')
    LOWERCASE_PATTERN = re.compile(r'[a-z]')
    DIGIT_PATTERN = re.compile(r'\d')
    SPECIAL_PATTERN = re.compile(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;\'`~]')
    
    @classmethod
    def validate(cls, password: str) -> PasswordStrength:
        """
        Valida una contraseña y retorna el resultado completo
        
        Args:
            password: Contraseña a validar
            
        Returns:
            PasswordStrength con detalles de la validación
        """
        errors = []
        suggestions = []
        score = 0
        
        # 1. Validar longitud mínima (obligatorio)
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"La contraseña debe tener al menos {cls.MIN_LENGTH} caracteres")
            suggestions.append(f"Agrega {cls.MIN_LENGTH - len(password)} caracteres más")
        else:
            score += 20
            
        # 2. Validar longitud máxima
        if len(password) > cls.MAX_LENGTH:
            errors.append(f"La contraseña no puede exceder {cls.MAX_LENGTH} caracteres")
        
        # 3. Validar mayúsculas (obligatorio)
        if not cls.UPPERCASE_PATTERN.search(password):
            errors.append("La contraseña debe contener al menos una letra mayúscula")
            suggestions.append("Agrega una letra mayúscula (A-Z)")
        else:
            score += 20
        
        # 4. Validar minúsculas (obligatorio)
        if not cls.LOWERCASE_PATTERN.search(password):
            errors.append("La contraseña debe contener al menos una letra minúscula")
            suggestions.append("Agrega una letra minúscula (a-z)")
        else:
            score += 20
        
        # 5. Validar números (obligatorio)
        if not cls.DIGIT_PATTERN.search(password):
            errors.append("La contraseña debe contener al menos un número")
            suggestions.append("Agrega un número (0-9)")
        else:
            score += 20
        
        # 6. Validar caracteres especiales (obligatorio)
        if not cls.SPECIAL_PATTERN.search(password):
            errors.append("La contraseña debe contener al menos un carácter especial (!@#$%^&*...)")
            suggestions.append("Agrega un carácter especial (!@#$%^&*)")
        else:
            score += 20
        
        # 7. Validar contra contraseñas comunes (obligatorio)
        password_lower = password.lower()
        
        # Verificar contraseña completa
        if password_lower in COMMON_PASSWORDS:
            errors.append("Esta contraseña es demasiado común y fácil de adivinar")
            suggestions.append("Usa una combinación única y menos predecible")
            score = min(score, 30)  # Limita el score si es común
        else:
            # Verificar si contiene palabras comunes como substrings
            for common_pwd in COMMON_PASSWORDS:
                if len(common_pwd) >= 5 and common_pwd in password_lower:
                    errors.append(f"La contraseña contiene una palabra común: '{common_pwd}'")
                    suggestions.append("Evita usar palabras comunes o predecibles")
                    score = min(score, 40)  # Penalizar pero menos que si es idéntica
                    break
        
        # 8. Bonificaciones adicionales
        if len(password) >= 12:
            score += 10  # Bonus por longitud extra
        
        if len(set(password)) >= len(password) * 0.7:
            score += 10  # Bonus por diversidad de caracteres
        
        # Asegurar que score esté en rango 0-100
        score = min(100, max(0, score))
        
        # Determinar si es válida
        is_valid = len(errors) == 0
        
        return PasswordStrength(
            is_valid=is_valid,
            score=score,
            errors=errors,
            suggestions=suggestions
        )
    
    @classmethod
    def validate_simple(cls, password: str) -> bool:
        """
        Validación simple que solo retorna True/False
        
        Args:
            password: Contraseña a validar
            
        Returns:
            True si la contraseña es válida, False en caso contrario
        """
        result = cls.validate(password)
        return result.is_valid
    
    @classmethod
    def get_errors(cls, password: str) -> List[str]:
        """
        Obtiene solo los errores de validación
        
        Args:
            password: Contraseña a validar
            
        Returns:
            Lista de errores encontrados
        """
        result = cls.validate(password)
        return result.errors


# Función helper para uso rápido
def validate_password(password: str) -> PasswordStrength:
    """
    Función helper para validar una contraseña
    
    Args:
        password: Contraseña a validar
        
    Returns:
        PasswordStrength con detalles de la validación
        
    Example:
        >>> result = validate_password("MiPassword123!")
        >>> if result.is_valid:
        >>>     print(f"Contraseña válida con fortaleza: {result.strength}")
        >>> else:
        >>>     print(f"Errores: {result.errors}")
    """
    return PasswordValidator.validate(password)
