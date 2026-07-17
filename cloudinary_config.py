from flask import Flask, render_template, request
from encryption import encrypt_file
from cloudinary_config import *
import cloudinary.uploader
import os

cloudinary.config(
    cloud_name="aqtxv7qh",
    api_key="844934769222634",
    api_secret="TmxXvDr_6vvL91GOdqV5sgDYLsY",
    secure=True
)