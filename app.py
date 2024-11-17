from flask import Flask, render_template, request, send_file, jsonify
import io
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)

# Encrypt file content
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

# Decrypt file content
def decrypt_file(content, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    decrypted_content = private_key.decrypt(
        content,
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
                download_name="encrypted_output.bin",
                mimetype="application/octet-stream"
            )

        elif action == "decrypt":
            decrypted_content = decrypt_file(file_content, "private_key.pem")
            return send_file(
                io.BytesIO(decrypted_content),
                as_attachment=True,
                download_name="decrypted_output.txt",
                mimetype="text/plain"
            )

    return jsonify({"error": "Invalid request"}), 400

if __name__ == "__main__":
    app.run(debug=True)
