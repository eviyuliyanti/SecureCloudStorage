from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import os
import requests

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
        return "Tidak ada file yang dipilih", 400

    filename = secure_filename(file.filename)

    # Simpan file asli sementara di server lokal
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(original_path)

    # =====================
    # AES ENCRYPTION
    # =====================
    encrypted_filename = filename + ".enc"
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    try:
        # Mengenkripsi file sebelum diunggah ke cloud
        encrypt_file(original_path, encrypted_path)

        # =====================
        # CLOUDINARY UPLOAD
        # =====================
        result = cloudinary.uploader.upload(
            encrypted_path,
            resource_type="raw"
        )
        cloud_url = result["secure_url"]

        # Bersihkan berkas setelah sukses dienkripsi & upload
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        # =====================
        # CREATE JWT TOKEN
        # =====================
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

    # Memverifikasi validitas dan masa kedaluwarsa JWT
    data = verify_token(token)

    if not data:
        return "Token tidak valid atau expired", 401

    filename = data["filename"]
    cloud_url = data["cloud_url"]  

    # Menentukan jalur unduhan berkas terenkripsi dan hasil dekripsi
    encrypted_file = os.path.join(ENCRYPTED_FOLDER, "dl_" + filename + ".enc")
    decrypted_file = os.path.join(UPLOAD_FOLDER, "dec_" + filename)

    # -------------------------------------------------------------
    # 1. AMBIL FILE DARI CLOUDINARY
    # -------------------------------------------------------------
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

    # -------------------------------------------------------------
    # 2. DEKRIPSI DAN PENGIRIMAN FILE AMAN
    # -------------------------------------------------------------
    try:
        # Jalankan fungsi dekripsi asli bawaanmu
        decrypt_file(encrypted_file, decrypted_file)

        # Hapus segera file terenkripsi (.enc) biar gak menumpuk di server
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)

        # FUNGSI GENERATOR: Membaca file untuk dikirim, lalu menghapusnya setelah selesai
        def generate_and_cleanup():
            with open(decrypted_file, 'rb') as f:
                yield from f
            # Blok ini dieksekusi setelah browser selesai mendownload file sepenuhnya
            try:
                if os.path.exists(decrypted_file):
                    os.remove(decrypted_file)
            except Exception as e:
                pass

        # Kirim stream data bersih menggunakan generator aman
        return app.response_class(
            generate_and_cleanup(),
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/octet-stream"
            }
        )

    except Exception as e:
        # Bersihkan file sisa jika terjadi crash di tengah jalan
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