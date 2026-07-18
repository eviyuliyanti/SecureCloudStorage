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
# FOLDER SYSTEM (Menggunakan /tmp untuk kompatibilitas penuh Cloud Railway)
# =================================================================
# Di server Linux/Railway, folder /tmp adalah satu-satunya tempat yang
# diizinkan untuk membuat file temporary secara dinamis.
UPLOAD_FOLDER = "/tmp/uploads"
ENCRYPTED_FOLDER = "/tmp/encrypted"

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
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(original_path)

    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    try:
        # Mengenkripsi file sebelum diunggah
        encrypt_file(original_path, encrypted_path)

        # Mengunggah berkas terenkripsi ke Cloudinary
        result = cloudinary.uploader.upload(
            encrypted_path,
            resource_type="raw"
        )
        cloud_url = result["secure_url"]

        # Langsung sapu bersih dari folder /tmp setelah berhasil upload
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
# SECURE DOWNLOAD VIA CLOUD
# =========================
@app.route("/secure-download")
def secure_download():
    token = request.args.get("token")
    if not token:
        return "Token tidak ditemukan", 400

    # Validasi Token Akses
    data = verify_token(token)
    if not data:
        return "Token tidak valid atau expired", 401

    filename = data["filename"]
    cloud_url = data["cloud_url"]  

    # File ditarik dan diolah di dalam isolation directory (/tmp)
    encrypted_file = os.path.join(ENCRYPTED_FOLDER, "dl_" + filename + ".enc")
    decrypted_file = os.path.join(UPLOAD_FOLDER, "dec_" + filename)

    # 1. UNDUH DATA TERENKRIPSI DARI CLOUDINARY
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

    # 2. DEKRIPSI & AMANKAN KE MEMORI RAM
    try:
        # Panggil fungsi dekripsi bawaan aslimu dengan aman di folder /tmp
        decrypt_file(encrypted_file, decrypted_file)

        # Hapus segera file terenkripsi agar tidak memenuhi kuota space
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)

        # AMANKAN KE RAM: Baca isi berkas asli yang bersih langsung ke memori internal
        with open(decrypted_file, 'rb') as f:
            file_memory_buffer = io.BytesIO(f.read())

        # Hapus berkas fisik asli dari folder /tmp server
        # Sekarang folder server 100% bersih total sebelum file dikirim ke browser!
        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)

        # Set pointer RAM kembali ke awal byte stream
        file_memory_buffer.seek(0)

        # Kirim berkas langsung dari memori internal ke browser pengguna
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
    # Gunicorn pada Railway akan menggunakan port default, 
    # namun baris ini tetap dipertahankan untuk kebutuhan local testing.
    app.run(debug=True)