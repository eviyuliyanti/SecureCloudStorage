from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import os
import requests
import io  # Ditambahkan untuk menangani konversi biner langsung di memori (RAM)

app = Flask(__name__)

# Folder temporary tetap dibuat jika library enkripsi lama kamu membutuhkannya
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
        return "Tidak ada file yang dipilih", 400

    filename = secure_filename(file.filename)

    # 1. Simpan file asli sementara di server lokal untuk dienkripsi
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(original_path)

    # 2. PROSES ENKRIPSI AES
    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
    encrypt_file(original_path, encrypted_path)

    # 3. UNGGAH KE CLOUD (Cloudinary Object Storage)
    result = cloudinary.uploader.upload(
        encrypted_path,
        resource_type="raw"
    )
    cloud_url = result["secure_url"]

    # 4. HAPUS FILE SEMENTARA (Sesuai konsep cloud storage aman, lokal server harus bersih)
    if os.path.exists(original_path):
        os.remove(original_path)
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    # 5. PEMBUATAN TOKEN AKSES (JWT)
    token = generate_token(cloud_url, filename)

    return render_template(
        "result.html",
        token=token,
        cloud_url=cloud_url,
        filename=filename
    )

# =========================
# SECURE DOWNLOAD VIA TOKEN AKSES
# =========================
@app.route("/secure-download")
def secure_download():
    # Ambil token akses dari URL
    token = request.args.get("token")

    if not token:
        return "Token tidak ditemukan", 400

    # VALIDASI TOKEN AKSES (Memeriksa masa kedaluwarsa & keaslian token)
    data = verify_token(token)

    if not data:
        return "Token tidak valid atau expired", 401

    filename = data["filename"]
    cloud_url = data["cloud_url"]  # URL rahasia cloud diekstrak dari token

    # -----------------------------------------------------------------
    # PROSES AMBIL FILE DARI CLOUDINARY DAN DEKRIPSI (IN-MEMORY PROXY)
    # -----------------------------------------------------------------
    try:
        # Ambil file terenkripsi dari Cloud secara streaming langsung ke RAM
        response = requests.get(cloud_url, stream=True)
        if response.status_code != 200:
            return "Gagal mengambil file terenkripsi dari Cloudinary", 404
            
        # Tampung byte terenkripsi ke RAM
        encrypted_bytes = response.content 
        
    except Exception as e:
        return f"Error koneksi Cloudinary: {str(e)}", 500

    # Menyiapkan file temporer lokal hanya untuk proses dekripsi instan
    temp_encrypted_path = os.path.join(ENCRYPTED_FOLDER, "temp_" + filename + ".enc")
    temp_decrypted_path = os.path.join(UPLOAD_FOLDER, "temp_" + filename)

    try:
        # Tulis byte terenkripsi ke file temp untuk didekripsi oleh modul AES
        with open(temp_encrypted_path, 'wb') as f:
            f.write(encrypted_bytes)

        # PROSES DEKRIPSI AES
        decrypt_file(temp_encrypted_path, temp_decrypted_path)

        # Baca file yang sudah bersih ke memori agar file fisiknya bisa langsung dihapus
        with open(temp_decrypted_path, 'rb') as f:
            file_data = f.read()

        # Hapus semua file sisa di server lokal (Menjaga sifat server Ephemeral tetap bersih)
        if os.path.exists(temp_encrypted_path):
            os.remove(temp_encrypted_path)
        if os.path.exists(temp_decrypted_path):
            os.remove(temp_decrypted_path)

        # Kirim data biner bersih dari memori langsung ke browser pengguna
        return send_file(
            io.BytesIO(file_data),
            download_name=filename,
            as_attachment=True
        )

    except Exception as e:
        # Pastikan file temp terhapus jika terjadi error di tengah jalan
        if os.path.exists(temp_encrypted_path):
            os.remove(temp_encrypted_path)
        if os.path.exists(temp_decrypted_path):
            os.remove(temp_decrypted_path)
        return f"Gagal memproses dekripsi berkas: {str(e)}", 500

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True)