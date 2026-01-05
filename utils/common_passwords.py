"""
Lista de contraseñas comunes
============================

Lista de las 100 contraseñas más comunes en español e inglés.
Estas contraseñas NO deben ser aceptadas por el sistema.

Fuentes:
- NordPass Most Common Passwords List
- SplashData Worst Passwords
- Contraseñas comunes en español
"""

# Las 100 contraseñas más comunes (en minúsculas para comparación)
COMMON_PASSWORDS = {
    # Top passwords en inglés
    "password",
    "123456",
    "123456789",
    "12345678",
    "12345",
    "1234567",
    "password1",
    "12345678910",
    "qwerty",
    "abc123",
    "1234567890",
    "senha",
    "qwerty123",
    "1q2w3e4r",
    "123123",
    "1q2w3e4r5t",
    "iloveyou",
    "qwertyuiop",
    "monkey",
    "dragon",
    "123321",
    "666666",
    "654321",
    "a123456",
    "123456a",
    "111111",
    "987654321",
    "1qaz2wsx",
    "qazwsx",
    "password123",
    "admin",
    "letmein",
    "welcome",
    "login",
    "princess",
    "solo",
    "sunshine",
    "master",
    "passw0rd",
    "hello123",
    "freedom",
    "whatever",
    "qazwsxedc",
    "trustno1",
    "jordan23",
    "harley",
    "robert",
    "matthew",
    "liverpool",
    "maverick",
    
    # Contraseñas comunes en español
    "contraseña",
    "contrasena",
    "administrador",
    "password",
    "clave",
    "clave123",
    "usuario",
    "prueba",
    "temporal",
    "test",
    "demo",
    "invitado",
    "guest",
    "root",
    "toor",
    "admin123",
    "admin1234",
    "administrador123",
    "bienvenido",
    "hola123",
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "123abc",
    "abc123",
    "pass123",
    "pass1234",
    "sistema",
    "default",
    "cambiar",
    "changeme",
    
    # Patrones numéricos comunes
    "000000",
    "111111",
    "222222",
    "333333",
    "444444",
    "555555",
    "666666",
    "777777",
    "888888",
    "999999",
    "121212",
    "131313",
    "112233",
    "123123123",
    
    # Nombres y palabras comunes
    "maria",
    "carlos",
    "jose",
    "jesus",
    "fernando",
    "miguel",
    "manuel",
    "alejandro",
    "antonio",
    "francisco",
}

# Función helper para verificar si una contraseña es común
def is_common_password(password: str) -> bool:
    """
    Verifica si una contraseña está en la lista de contraseñas comunes
    
    Args:
        password: Contraseña a verificar
        
    Returns:
        True si la contraseña es común, False en caso contrario
    """
    return password.lower() in COMMON_PASSWORDS
