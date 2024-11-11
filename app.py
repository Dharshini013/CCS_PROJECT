from flask import Flask, request, send_file, jsonify, render_template
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import io
import os

app = Flask(__name__)

# Encryption and decryption functions (as defined in previous code)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

def encrypt_file(content, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    encrypted_content = public_key.encrypt(
        content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_content

def decrypt_file(encrypted_content, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    decrypted_content = private_key.decrypt(
        encrypted_content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_content

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_file():
    action = request.form.get("action")
    file = request.files.get("file")
    
    if file and action:
        file_content = file.read()
        
        if action == "encrypt":
            encrypted_content = encrypt_file(file_content, "public_key.pem")
            return send_file(
                io.BytesIO(encrypted_content),
                as_attachment=True,
                download_name="encrypted_output.bin"
            )
        
        elif action == "decrypt":
            decrypted_content = decrypt_file(file_content, "private_key.pem")
            return send_file(
                io.BytesIO(decrypted_content),
                as_attachment=True,
                download_name="decrypted_output.txt"
            )

    return jsonify({"error": "Invalid request"}), 400

# Generate keys if they don’t exist
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    generate_keys()

if __name__ == "__main__":
    app.run(debug=True)
