from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import os
import requests
import io  # Diperlukan untuk menjembatani pengiriman file dari RAM agar tidak eror

app = Flask(__name__)

# =========================
# CONFIGURATION & SYSTEM FOLDERS
# =========================
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# =========================
# 1. HOME ROUTE
# =========================
@app.route("/")
def home():
    return render_template("index.html")

# =========================
# 2. UPLOAD + ENCRYPT ROUTE
# =========================
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")

    if not file or file.filename == "":
        return "Tidak ada file yang dipilih", 400

    filename = secure_filename(file.filename)

    # Simpan file asli sementara di server lokal untuk diproses
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(original_path)

    # Tentukan jalur output untuk file terenkripsi (.enc)
    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    try:
        # Mengenkripsi file menggunakan fungsi asli dari encryption.py
        encrypt_file(original_path, encrypted_path)

        # Mengunggah berkas biner terenkripsi ke Cloudinary
        result = cloudinary.uploader.upload(
            encrypted_path,
            resource_type="raw"
        )
        cloud_url = result["secure_url"]

        # HAPUS FILE SEMENTARA DI DISK LOKAL
        # Langkah wajib agar sesuai dengan desain "Penyimpanan Aman di Cloud" 
        # sehingga tidak meninggalkan jejak file mentah/terenkripsi di server Railway
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        # Menyimpan cloud_url dan filename asli ke dalam payload JWT
        token = generate_token(cloud_url, filename)

        return render_template(
            "result.html",
            token=token,
            cloud_url=cloud_url,
            filename=filename
        )

    except Exception as e:
        # Jika terjadi kegagalan sistem, pastikan file temporary tetap dibersihkan
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        return f"Terjadi kesalahan saat upload/enkripsi: {str(e)}", 500

# =========================
# 3. SECURE DOWNLOAD VIA TOKEN ROUTE
# =========================
@app.route("/secure-download")
def secure_download():
    token = request.args.get("token")

    if not token:
        return "Token tidak ditemukan", 400

    # Memverifikasi validitas dan masa kedaluwarsa JWT
    data = verify_token(token)

    if not data:
        return "Token tidak valid atau expired", 401

    filename = data["filename"]
    cloud_url = data["cloud_url"]  # Mengambil URL Cloudinary dari payload token

    # Menentukan jalur unduhan file terenkripsi dan dekripsi sementara di lokal
    temp_encrypted_file = os.path.join(ENCRYPTED_FOLDER, "download_" + filename + ".enc")
    temp_decrypted_file = os.path.join(UPLOAD_FOLDER, "clean_" + filename)

    # -------------------------------------------------------------
    # FASE 1: TARIK CIPHERTEXT DARI CLOUD VIA HTTP STREAM
    # -------------------------------------------------------------
    try:
        response = requests.get(cloud_url, stream=True)
        if response.status_code == 200:
            with open(temp_encrypted_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        else:
            return "Gagal mengambil file terenkripsi dari Cloudinary", 404
    except Exception as e:
        return f"Error koneksi Cloudinary: {str(e)}", 500

    # -------------------------------------------------------------
    # FASE 2: DEKRIPSI DAN AMANKAN DI RAM SEBELUM PENGIRIMAN
    # -------------------------------------------------------------
    try:
        # Mendekripsi berkas biner menggunakan fungsi asli dari encryption.py
        decrypt_file(temp_encrypted_file, temp_decrypted_file)

        # Segera hapus file biner terenkripsi (.enc) karena proses dekripsi sudah selesai
        if os.path.exists(temp_encrypted_file):
            os.remove(temp_encrypted_file)

        # TRIK ANTI-EROR: Membaca file asli yang bersih langsung ke memori internal (RAM)
        # Dengan memindahkan biner ke RAM, file fisik di disk server bisa langsung kita hapus 
        # tanpa memicu eror "File Not Found" pada fungsi send_file() milik Flask.
        with open(temp_decrypted_file, 'rb') as f:
            file_buffer = io.BytesIO(f.read())

        # Hapus file mentah hasil dekripsi dari disk lokal server
        if os.path.exists(temp_decrypted_file):
            os.remove(temp_decrypted_file)

        # Kembalikan pointer buffer ke posisi awal sebelum dikirim
        file_buffer.seek(0)

        # Mengirim berkas asli yang sudah bersih sebagai lampiran unduhan
        return send_file(
            file_buffer,
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        # Bersihkan sisa file di server jika proses di tengah jalan mengalami crash
        if os.path.exists(temp_encrypted_file):
            os.remove(temp_encrypted_file)
        if os.path.exists(temp_decrypted_file):
            os.remove(temp_decrypted_file)
        return f"Gagal memproses dekripsi berkas: {str(e)}", 500

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True)