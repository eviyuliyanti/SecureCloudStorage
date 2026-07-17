from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

from encryption import encrypt_file, decrypt_file
from cloudinary_config import cloudinary
from token_manager import generate_token, verify_token

import cloudinary.uploader
import os

print("TEST:", os.getenv("TEST_VAR"))
print("CLOUDINARY:", os.getenv("CLOUDINARY_API_KEY"))
print("CLOUDINARY KEY:", os.getenv("CLOUDINARY_API_KEY"))


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")


# =========================
# FOLDER SYSTEM
# =========================

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"


app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER



os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


os.makedirs(
    ENCRYPTED_FOLDER,
    exist_ok=True
)





# =========================
# HOME
# =========================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )







# =========================
# UPLOAD + ENCRYPT
# =========================

@app.route("/upload", methods=["POST"])
def upload():


    file = request.files.get("file")



    if not file or file.filename == "":

        return "Tidak ada file yang dipilih"




    filename = secure_filename(
        file.filename
    )



    # simpan file asli sementara

    original_path = os.path.join(

        UPLOAD_FOLDER,

        filename

    )


    file.save(
        original_path
    )





    # =====================
    # AES ENCRYPTION
    # =====================


    encrypted_filename = filename + ".enc"



    encrypted_path = os.path.join(

        ENCRYPTED_FOLDER,

        encrypted_filename

    )



    encrypt_file(

        original_path,

        encrypted_path

    )







    # =====================
    # CLOUDINARY UPLOAD
    # =====================


    result = cloudinary.uploader.upload(

        encrypted_path,

        resource_type="raw"

    )



    cloud_url = result["secure_url"]







    # =====================
    # CREATE JWT TOKEN
    # =====================


    token = generate_token(

        cloud_url,

        filename

    )







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


    token = request.args.get(
        "token"
    )



    if not token:

        return "Token tidak ditemukan"





    data = verify_token(

        token

    )



    if not data:

        return "Token tidak valid atau expired"





    filename = data["filename"]






    # lokasi file terenkripsi


    encrypted_file = os.path.join(

        ENCRYPTED_FOLDER,

        filename + ".enc"

    )





    if not os.path.exists(encrypted_file):

        return "File terenkripsi tidak ditemukan"







    # lokasi file hasil decrypt


    decrypted_file = os.path.join(

        UPLOAD_FOLDER,

        filename

    )







    decrypt_file(

        encrypted_file,

        decrypted_file

    )







    return send_file(

        decrypted_file,

        as_attachment=True

    )









# =========================
# RUN SERVER
# =========================


if __name__ == "__main__":


    app.run(

        debug=True

    )