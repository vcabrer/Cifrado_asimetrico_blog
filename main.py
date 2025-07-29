# Importamos los módulos necesarios de la biblioteca 'cryptography'
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# --- PASO 1: Generación de Pares de Claves para Alice y Bob ---
# En un escenario real, cada uno generaría su clave en su propia máquina.
# Aquí lo simulamos en un solo script por simplicidad.

print("Generando pares de claves para Alice y Bob...")

# Generar claves para Alice
private_key_alice = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key_alice = private_key_alice.public_key()

# Generar claves para Bob
private_key_bob = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key_bob = private_key_bob.public_key()

print("Claves generadas.\n")

# --- PASO 2: Alice prepara y firma el mensaje ---
# Este es el reporte secreto que Alice quiere enviar.
reporte_secreto = b"Reporte de vulnerabilidad critica en servidor DB-01. Acceso no autorizado detectado."

print(f"Reporte original de Alice: {reporte_secreto.decode()}")

# Alice FIRMA el hash del reporte con su CLAVE PRIVADA.
# Esto garantiza AUTENTICIDAD (fue Alice) e INTEGRIDAD (no fue modificado).
print("\n Alice firma el reporte con su clave PRIVADA...")
signature = private_key_alice.sign(
    reporte_secreto,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Reporte firmado.\n")


# --- PASO 3: Alice cifra el mensaje para Bob ---
# Alice cifra el reporte usando la CLAVE PÚBLICA de Bob.
# Esto garantiza CONFIDENCIALIDAD (solo Bob podrá leerlo).
print(f"Alice cifra el reporte con la clave PUBLICA de Bob...")
reporte_cifrado = public_key_bob.encrypt(
    reporte_secreto,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Reporte cifrado.\n")
# print(f"Ciphertext: {reporte_cifrado.hex()}") # Descomentar para ver el texto cifrado


# --- "TRANSMISIÓN" ---
# Alice ahora envía el 'reporte_cifrado' y la 'firma' a Bob.
# Imaginemos que estos datos viajan por un canal inseguro como el email.
print("Alice envia el reporte cifrado y la firma a Bob...\n")


# --- PASO 4: Bob recibe y verifica la firma ---
# Bob usa la CLAVE PÚBLICA de Alice para verificar la firma.
# Si la verificación es exitosa, sabe que el mensaje es auténtico de Alice.
print("Bob verifica la firma usando la clave PUBLICA de Alice...")
try:
    public_key_alice.verify(
        signature,
        reporte_cifrado, # OJO: Aquí hay un error conceptual intencionado para la explicación.
                         # La verificación se hace sobre el MENSAJE ORIGINAL, no el cifrado.
                         # Lo corregimos en el siguiente bloque.
    )
    print("ERROR en la logica de verificacion. ¡Esto no deberia pasar!")
except Exception:
    print("La verificacion sobre el texto cifrado FALLA (lo cual es correcto).")


# La forma correcta: Bob necesita el mensaje original para verificar,
# pero no puede tenerlo hasta que lo descifre.
# Este es el orden correcto: 1. Descifrar, 2. Verificar.
print("\n Corrigiendo el flujo: Bob primero debe descifrar.\n")


# --- PASO 5: Bob descifra el mensaje ---
# Bob usa su CLAVE PRIVADA para descifrar el reporte.
# Nadie más en el mundo puede hacer esto.
print(f"Bob descifra el reporte con su clave PRIVADA...")
reporte_descifrado = private_key_bob.decrypt(
    reporte_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Reporte descifrado.")
print(f"Reporte recibido por Bob: {reporte_descifrado.decode()}\n")


# --- PASO 6: Bob ahora SÍ verifica la firma ---
# Con el mensaje ya descifrado, Bob puede verificar la firma
# usando el texto en claro y la CLAVE PÚBLICA de Alice.
print("Bob realiza la verificacion de la firma sobre el mensaje descifrado...")
try:
    public_key_alice.verify(
        signature,
        reporte_descifrado, # Se verifica sobre el contenido original
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("EXITO! La firma es valida. El reporte es autentico de Alice y no fue modificado.\n")
    print("Bob puede confiar plenamente en el reporte.")
except Exception as e:
    print(f" ¡FALLO DE VERIFICACION! El mensaje fue alterado o no es de Alice. Error: {e}")