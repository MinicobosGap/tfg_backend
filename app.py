import hashlib
import base64
import bcrypt
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES

app = Flask(__name__)
CORS(app)

@app.route('/encriptar256', methods=['POST'])
def encriptar_aes256():
    datos = request.json.get('datos')  # Se espera un diccionario de datos
    if datos:
        # Combinar todos los valores de los datos en una cadena para encriptarlos juntos
        data_to_encrypt = ','.join(datos.values())

        # Generar una clave secreta aleatoria
        clave_secreta = os.urandom(32)

        # Generar un vector de inicialización (IV) aleatorio
        iv = os.urandom(16)

        # Crear un objeto AES para cifrado
        cipher = AES.new(clave_secreta, AES.MODE_CBC, iv)

        # Añadir padding al dato para que tenga una longitud múltiplo de 16 bytes
        if len(data_to_encrypt) % 16 != 0:
            data_to_encrypt += ' ' * (16 - len(data_to_encrypt) % 16)

        # Encriptar los datos
        datos_encriptados = cipher.encrypt(data_to_encrypt.encode())

        # Concatenar el IV al principio de los datos encriptados
        datos_encriptados_con_iv = iv + datos_encriptados

        # Codificar los datos encriptados en base64
        datos_encriptados_base64 = base64.b64encode(datos_encriptados_con_iv).decode()

        return datos_encriptados_base64, 200
    else:
        return jsonify({'error': 'No se proporcionaron datos para encriptar'}), 400

@app.route('/hashear256', methods=['POST'])
def hashear_sha256():
    data = request.json.get('data')
    if data is not None:
        # Hashear los datos usando SHA-256
        hashed_data = hashlib.sha256(data.encode()).hexdigest()
        return hashed_data, 200  # Devuelve solo el hash
    else:
        return jsonify({'error': 'No se proporcionaron datos para hashear'}), 400
    
@app.route('/hashear256Dos', methods=['POST'])
def hashear_sha256_dos():
    datos = request.json.get('datos')
    if datos is not None:
        # Combinar todos los valores de los datos en una cadena para hashearlos juntos
        data_to_hash = ','.join(datos.values())

        # Hashear los datos usando SHA-256
        hashed_data = hashlib.sha256(data_to_hash.encode()).hexdigest()
        
        return hashed_data, 200  # Devuelve solo el hash
    else:
        return jsonify({'error': 'No se proporcionaron datos para hashear'}), 400

        

    
@app.route('/hashearbcrypt', methods=['POST'])
def hashear_bcrypt():
    # Obtener la contraseña enviada desde el frontend
    contrasena = request.json.get('data')
    # Verificar que la contraseña no esté vacía
    if contrasena is not None and contrasena.strip() != '':
        # Generar el hash de la contraseña usando bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(contrasena.encode(), salt)
        # Devolver el hash de la contraseña al frontend
        return hashed_password, 200
    else:
        # Si la contraseña está vacía, devolver un mensaje de error
        return jsonify({'error': 'La contraseña no puede estar vacía'}), 400


if __name__ == '__main__':
    app.run(debug=True)

