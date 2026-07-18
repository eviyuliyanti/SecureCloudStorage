from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import os
import requests  # Ditambahkan untuk mengunduh berkas terenkripsi dari Cloudinary

app = Flask(__name__)

# =========================
# FOLDER SYSTEM
# =========================
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# =========================
# HOME
# =========================
@app.route("/")
def home():
    return render_template("index.html")

# =========================
# UPLOAD + ENCRYPT
# =========================
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")

    if not file or file.filename == "":
        return "Tidak ada file yang dipilih"

    filename = secure_filename(file.filename)

    # Simpan file asli sementara di server lokal
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(original_path)

    # =====================
    # AES ENCRYPTION
    # =====================
    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    # Mengenkripsi file sebelum diunggah ke cloud
    encrypt_file(original_path, encrypted_path)

    # =====================
    # CLOUDINARY UPLOAD
    # =====================
    # Mengunggah berkas biner terenkripsi (resource_type="raw") ke Cloudinary
    result = cloudinary.uploader.upload(
        encrypted_path,
        resource_type="raw"
    )

    cloud_url = result["secure_url"]

    # =====================
    # CREATE JWT TOKEN
    # =====================
    # Menyimpan cloud_url dan filename asli ke dalam payload JWT
    token = generate_token(cloud_url, filename)

    return render_template(
        "result.html",
        token=token,
        cloud_url=cloud_url,
        filename=filename
    )

# =========================
# SECURE DOWNLOAD
# =========================
@app.route("/secure-download")
def secure_download():
    token = request.args.get("token")

    if not token:
        return "Token tidak ditemukan"

    # Memverifikasi validitas dan masa kedaluwarsa JWT
    data = verify_token(token)

    if not data:
        return "Token tidak valid atau expired"

    filename = data["filename"]
    cloud_url = data["cloud_url"]  # Mengambil URL Cloudinary dari payload token

    # Menentukan jalur unduhan file terenkripsi dari cloud
    encrypted_file = os.path.join(ENCRYPTED_FOLDER, filename + ".enc")

    # -------------------------------------------------------------
    # PROSES AMBIL FILE DARI CLOUDINARY (Integrasi Cloud Aktif)
    # -------------------------------------------------------------
    try:
        response = requests.get(cloud_url, stream=True)
        if response.status_code == 200:
            with open(encrypted_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        else:
            return "Gagal mengambil file terenkripsi dari Cloudinary"
    except Exception as e:
        return f"Error koneksi Cloudinary: {str(e)}"

    # Jalur untuk menaruh hasil dekripsi
    decrypted_file = os.path.join(UPLOAD_FOLDER, filename)

    # Mendekripsi berkas biner yang baru saja ditarik dari Cloudinary
    decrypt_file(encrypted_file, decrypted_file)

    # Mengirim berkas asli yang sudah bersih kepada pengguna sebagai lampiran unduhan
    return send_file(decrypted_file, as_attachment=True)

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True)