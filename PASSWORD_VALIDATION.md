# 🔐 Validación de Contraseñas Fuertes

## 📋 Descripción

Sistema completo de validación de contraseñas que garantiza que los usuarios creen contraseñas seguras que cumplan con los estándares de la industria.

## ✅ Requisitos de Contraseña

Todas las contraseñas deben cumplir con los siguientes criterios:

### Requisitos Obligatorios

1. **Longitud Mínima**: 8 caracteres (máximo 128)
2. **Letra Mayúscula**: Al menos una letra mayúscula (A-Z)
3. **Letra Minúscula**: Al menos una letra minúscula (a-z)
4. **Número**: Al menos un dígito (0-9)
5. **Carácter Especial**: Al menos un carácter especial (!@#$%^&*(),.?":{}|<>_-+=[]\/;'`~)
6. **No Común**: No debe estar en la lista de contraseñas comunes ni contener palabras comunes

### Sistema de Puntuación

Las contraseñas reciben una puntuación de 0-100 basada en:

- **20 puntos**: Longitud mínima (8+ caracteres)
- **20 puntos**: Contiene mayúsculas
- **20 puntos**: Contiene minúsculas
- **20 puntos**: Contiene números
- **20 puntos**: Contiene caracteres especiales
- **+10 puntos**: Longitud >= 12 caracteres
- **+10 puntos**: Alta diversidad de caracteres (70%+ únicos)
- **Penalización**: Contraseña común o contiene palabra común

### Niveles de Fortaleza

| Puntuación | Nivel | Descripción |
|------------|-------|-------------|
| 0-24 | Muy Débil | Insegura, fácil de adivinar |
| 25-49 | Débil | Vulnerable a ataques |
| 50-74 | Media | Aceptable pero mejorable |
| 75-89 | Fuerte | Buena seguridad |
| 90-100 | Muy Fuerte | Excelente seguridad |

## 📝 Ejemplos

### ❌ Contraseñas Rechazadas

```python
# Muy corta
"Pass1!" 
# Error: La contraseña debe tener al menos 8 caracteres

# Contraseña común
"password"
# Error: Esta contraseña es demasiado común y fácil de adivinar

# Sin mayúscula
"secur3p@ss!"
# Error: La contraseña debe contener al menos una letra mayúscula

# Sin número
"SecurePass!"
# Error: La contraseña debe contener al menos un número

# Sin carácter especial
"SecurePass123"
# Error: La contraseña debe contener al menos un carácter especial

# Contiene palabra común
"Admin123!"
# Error: La contraseña contiene una palabra común: 'admin'
```

### ✅ Contraseñas Aceptadas

```python
"S3gur0T0t@l!"          # Score: 100 - Muy Fuerte
"C0ntr@señ@Segur@2024"  # Score: 100 - Muy Fuerte
"MyS3cur3P@ssw0rd!"     # Score: 100 - Muy Fuerte
"Pr0t3cc10n#2024"       # Score: 100 - Muy Fuerte
"M!Cl@v3F0rt3*"         # Score: 100 - Muy Fuerte
```

## 🛠️ Uso en el Código

### Validación Programática

```python
from utils.password_validator import validate_password, PasswordValidator

# Validación completa con detalles
result = validate_password("MyP@ssw0rd123")

if result.is_valid:
    print(f"✅ Contraseña válida")
    print(f"   Fortaleza: {result.strength}")
    print(f"   Puntuación: {result.score}/100")
else:
    print(f"❌ Contraseña inválida")
    print(f"   Errores:")
    for error in result.errors:
        print(f"   • {error}")
    print(f"   Sugerencias:")
    for suggestion in result.suggestions:
        print(f"   • {suggestion}")

# Validación simple (solo True/False)
is_valid = PasswordValidator.validate_simple("MyP@ssw0rd123")

# Obtener solo errores
errors = PasswordValidator.get_errors("weak")
```

### Integración con Pydantic

```python
from pydantic import BaseModel, field_validator
from utils.password_validator import PasswordValidator

class UserCreate(BaseModel):
    email: str
    password: str
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        result = PasswordValidator.validate(v)
        if not result.is_valid:
            error_msg = "La contraseña no cumple con los requisitos:\n"
            error_msg += "\n".join(f"• {e}" for e in result.errors)
            raise ValueError(error_msg)
        return v
```

### Integración con FastAPI

```python
from fastapi import HTTPException, status
from utils.password_validator import PasswordValidator

@router.post('/register')
async def register(password: str = Form(...)):
    # Validar contraseña
    password_validation = PasswordValidator.validate(password)
    
    if not password_validation.is_valid:
        error_msg = "Contraseña inválida:\n"
        error_msg += "\n".join(f"• {e}" for e in password_validation.errors)
        
        if password_validation.suggestions:
            error_msg += "\n\nSugerencias:\n"
            error_msg += "\n".join(f"• {s}" for s in password_validation.suggestions)
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )
    
    # Continuar con el registro...
```

## 🧪 Testing

### Ejecutar Tests Unitarios

```bash
# Test del validador de contraseñas
python test_password_validation.py

# Modo interactivo
python test_password_validation.py --interactive
```

### Probar Registro de Usuario

```bash
# Test de integración con la API
python test_registration_passwords.py
```

### Ejemplo de Respuesta de Error

```json
{
  "detail": "La contraseña no cumple con los requisitos de seguridad:\n• La contraseña debe tener al menos 8 caracteres\n• La contraseña debe contener al menos una letra mayúscula\n• Esta contraseña es demasiado común y fácil de adivinar\n\nSugerencias:\n• Agrega 2 caracteres más\n• Agrega una letra mayúscula (A-Z)\n• Usa una combinación única y menos predecible"
}
```

## 📊 Lista de Contraseñas Comunes

El sistema valida contra una lista de 100+ contraseñas comunes, incluyendo:

### Contraseñas Numéricas
- 123456, 12345678, 123456789, 111111, 000000, etc.

### Contraseñas Alfabéticas
- password, qwerty, admin, welcome, login, etc.

### Contraseñas en Español
- contraseña, contrasena, administrador, clave, prueba, etc.

### Patrones Comunes
- password123, admin123, qwerty123, etc.

Ver lista completa en: `utils/common_passwords.py`

## 🔧 Configuración

### Personalizar Requisitos

Edita `utils/password_validator.py` para ajustar:

```python
class PasswordValidator:
    # Longitud mínima y máxima
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    # Patrones regex para validación
    UPPERCASE_PATTERN = re.compile(r'[A-Z]')
    LOWERCASE_PATTERN = re.compile(r'[a-z]')
    DIGIT_PATTERN = re.compile(r'\d')
    SPECIAL_PATTERN = re.compile(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;\'`~]')
```

### Agregar Contraseñas Comunes

Edita `utils/common_passwords.py`:

```python
COMMON_PASSWORDS = {
    # Agrega tus contraseñas comunes aquí
    "nueva_contraseña_comun",
    "otra_contraseña",
    # ...
}
```

## 📈 Mejores Prácticas

### Para Usuarios

1. **No uses información personal**: nombres, fechas de nacimiento, etc.
2. **Evita patrones de teclado**: qwerty, asdfgh, 12345, etc.
3. **Usa frases de contraseña**: Combina palabras aleatorias con números y símbolos
4. **Usa un gestor de contraseñas**: Para generar y almacenar contraseñas fuertes

### Para Desarrolladores

1. **Nunca almacenes contraseñas en texto plano**: Siempre usa hashing (bcrypt, argon2, etc.)
2. **Valida en el backend**: No confíes solo en validación del frontend
3. **Proporciona feedback útil**: Muestra errores específicos y sugerencias
4. **Considera MFA**: La validación de contraseñas es solo una capa de seguridad

## 🔄 Integración Completa

El sistema está integrado en los siguientes endpoints:

### POST `/auth/register`
- ✅ Valida contraseña en el registro
- ✅ Retorna errores detallados
- ✅ Proporciona sugerencias de mejora

### Schema `UserCreate`
- ✅ Validación Pydantic automática
- ✅ Mensajes de error personalizados

## 📚 Referencias

- [OWASP Password Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

## 🎯 Próximos Pasos

Considera implementar:

1. **Historial de contraseñas**: Evitar reutilización de contraseñas anteriores
2. **Expiración de contraseñas**: Forzar cambio periódico (opcional según NIST)
3. **Detección de brechas**: Validar contra bases de datos de contraseñas filtradas (Have I Been Pwned)
4. **Generador de contraseñas**: Ayudar a usuarios a crear contraseñas seguras
5. **Medidor de fortaleza en UI**: Feedback visual en tiempo real

## ⏱️ Tiempo de Implementación

**Total: ~20 minutos** ✅

- Creación del validador: 5 min
- Lista de contraseñas comunes: 3 min
- Integración con schemas/endpoints: 5 min
- Testing y validación: 5 min
- Documentación: 2 min

---

**Estado**: ✅ Implementado y probado
**Fecha**: Enero 2026
**Versión**: 1.0.0
