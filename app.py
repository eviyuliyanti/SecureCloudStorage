from flask import (
    Flask,
    render_template,
    request,
    send_file,
    after_this_request
)

from werkzeug.utils import secure_filename

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import requests
import os


app = Flask(__name__)

# =========================
# CONFIG
# =========================

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER

# Maksimal upload 20 MB
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# =========================
# VALIDASI FILE
# =========================

ALLOWED_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "jpg",
    "jpeg",
    "png",
    "txt"
}


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# =========================
# HOME
# =========================

@app.route("/")
def home():
    return render_template("index.html")


# =========================
# UPLOAD
# =========================

@app.route("/upload", methods=["POST"])
def upload():

    file = request.files.get("file")

    if not file or file.filename == "":
        return "Tidak ada file dipilih."

    filename = secure_filename(file.filename)

    if not allowed_file(filename):
        return "Format file tidak diizinkan."

    original_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    encrypted_filename = filename + ".enc"

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        encrypted_filename
    )

    file.save(original_path)

    # =========================
    # ENCRYPT
    # =========================

    encrypt_file(
        original_path,
        encrypted_path
    )

    # Hapus file asli
    if os.path.exists(original_path):
        os.remove(original_path)

    # =========================
    # CLOUDINARY
    # =========================

    try:

        result = cloudinary.uploader.upload(
            encrypted_path,
            resource_type="raw"
        )

    except Exception as e:

        return f"Gagal upload ke Cloudinary : {e}"

    cloud_url = result["secure_url"]
    public_id = result["public_id"]

    # Hapus file terenkripsi lokal
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    # =========================
    # JWT
    # =========================

    token = generate_token(
        cloud_url,
        filename,
        public_id
    )

    return render_template(
        "result.html",
        token=token,
        filename=filename,
        cloud_url=cloud_url
    )


# =========================
# DOWNLOAD
# =========================

@app.route("/secure-download")
def secure_download():

    token = request.args.get("token")

    if not token:
        return "Token tidak ditemukan."

    data = verify_token(token)

    if not data:
        return "Token tidak valid atau sudah expired."

    filename = data["filename"]
    cloud_url = data["cloud_url"]

    encrypted_file = os.path.join(
        ENCRYPTED_FOLDER,
        filename + ".enc"
    )

    decrypted_file = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    # =========================
    # DOWNLOAD DARI CLOUDINARY
    # =========================

    try:

        response = requests.get(cloud_url)

        if response.status_code != 200:
            return "Gagal mengambil file dari Cloudinary."

        with open(encrypted_file, "wb") as f:
            f.write(response.content)

    except Exception as e:

        return f"Gagal download file : {e}"

    # =========================
    # DECRYPT
    # =========================

    decrypt_file(
        encrypted_file,
        decrypted_file
    )

    # =========================
    # HAPUS FILE SEMENTARA
    # =========================

    @after_this_request
    def cleanup(response):

        try:
            if os.path.exists(encrypted_file):
                os.remove(encrypted_file)
        except Exception:
            pass

        try:
            if os.path.exists(decrypted_file):
                os.remove(decrypted_file)
        except Exception:
            pass

        return response

    return send_file(
        decrypted_file,
        as_attachment=True
    )


# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(debug=True)