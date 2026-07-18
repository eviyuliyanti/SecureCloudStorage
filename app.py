from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import os
import requests
import io

app = Flask(__name__)

# =================================================================
# DETEKSI SISTEM OPERASI OTOMATIS (Hybrid Folder System)
# =================================================================
# Jika dijalankan di cloud (Railway/Linux), gunakan folder /tmp agar tidak di-crash.
# Jika dijalankan di lokal (Windows), gunakan folder project biasa agar tidak eror.
if os.name == 'nt':  # 'nt' artinya Windows
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted")
else:  # Linux / Environment Cloud Railway
    UPLOAD_FOLDER = "/tmp/uploads"
    ENCRYPTED_FOLDER = "/tmp/encrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER

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
    original_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(original_path)

    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], encrypted_filename)

    try:
        # Mengenkripsi file menggunakan fungsi asli dari encryption.py
        encrypt_file(original_path, encrypted_path)

        # Mengunggah berkas biner terenkripsi ke Cloudinary
        result = cloudinary.uploader.upload(
            encrypted_path,
            resource_type="raw"
        )
        cloud_url = result["secure_url"]

        # HAPUS INSTAN DARI DISK SERVER LOKAL
        # Menjaga server tetap bersih dan mematuhi batas ephemeral storage cloud
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        # Pembuatan Token Akses JWT
        token = generate_token(cloud_url, filename)

        return render_template(
            "result.html",
            token=token,
            cloud_url=cloud_url,
            filename=filename
        )
    except Exception as e:
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        return f"Error saat upload: {str(e)}", 500

# =========================
# SECURE DOWNLOAD
# =========================
@app.route("/secure-download")
def secure_download():
    token = request.args.get("token")
    if not token:
        return "Token tidak ditemukan", 400

    # Validasi masa aktif dan integritas kunci token akses JWT
    data = verify_token(token)
    if not data:
        return "Token tidak valid atau expired", 401

    filename = data["filename"]
    cloud_url = data["cloud_url"]  

    # Menentukan jalur unduhan file sementara di isolasi direktori
    encrypted_file = os.path.join(app.config["ENCRYPTED_FOLDER"], "dl_" + filename + ".enc")
    decrypted_file = os.path.join(app.config["UPLOAD_FOLDER"], "dec_" + filename)

    # 1. UNDUH DATA CIPHERTEXT DARI CLOUDINARY
    try:
        response = requests.get(cloud_url, stream=True)
        if response.status_code == 200:
            with open(encrypted_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        else:
            return "Gagal mengambil file terenkripsi dari Cloudinary", 404
    except Exception as e:
        return f"Error koneksi Cloudinary: {str(e)}", 500

    # 2. PROSES DEKRIPSI KEMBALI KE RAW BYTES (IN-MEMORY)
    try:
        # Jalankan fungsi dekripsi bawaan dari encryption.py milikmu
        decrypt_file(encrypted_file, decrypted_file)

        # Hapus berkas terenkripsi (.enc) di server secepat mungkin
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)

        # STRATEGI IN-MEMORY BUFFER: Ekstrak file bersih langsung ke RAM internal
        with open(decrypted_file, 'rb') as f:
            file_memory_buffer = io.BytesIO(f.read())

        # Hapus berkas mentah hasil dekripsi dari disk server fisik
        # Menjamin keamanan data-at-rest dan kebersihan server Railway
        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)

        # Reset pointer posisi pembacaan RAM ke letak awal
        file_memory_buffer.seek(0)

        # Salurkan data bersih langsung sebagai lampiran unduhan ke browser
        return send_file(
            file_memory_buffer, 
            as_attachment=True, 
            download_name=filename
        )

    except Exception as e:
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)
        return f"Gagal mendekripsi berkas: {str(e)}", 500

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True)