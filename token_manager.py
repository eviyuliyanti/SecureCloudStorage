import os
import jwt

from datetime import datetime, timedelta

SECRET_KEY = os.getenv("JWT_SECRET_KEY")


def generate_token(url, filename):

    payload = {
        "url": url,
        "filename": filename,
        "exp": datetime.utcnow() + timedelta(minutes=5)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    return token


def verify_token(token):

    try:

        data = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return data

    except Exception:

        return None