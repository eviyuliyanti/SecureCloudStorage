import jwt

from datetime import datetime, timedelta, timezone

# Sebaiknya SECRET_KEY disimpan di Environment Variable
SECRET_KEY = "SecureCloudStorage2026"

# Algoritma JWT
ALGORITHM = "HS256"

# Masa berlaku token (menit)
TOKEN_EXPIRE_MINUTES = 5


def generate_token(cloud_url, filename, public_id):
    """
    Membuat JWT token untuk proses download file.
    """

    payload = {
        "cloud_url": cloud_url,
        "filename": filename,
        "public_id": public_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token


def verify_token(token):
    """
    Memverifikasi JWT token.
    Mengembalikan payload jika token valid.
    """

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload

    except jwt.ExpiredSignatureError:

        print("Token telah kedaluwarsa.")

        return None

    except jwt.InvalidTokenError:

        print("Token tidak valid.")

        return None

    except Exception as e:

        print(f"Terjadi kesalahan: {e}")

        return None