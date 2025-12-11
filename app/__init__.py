from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import *
from config import Config
from argon2 import *
from cryptography.fernet import Fernet
import logging
import os
from logging.handlers import *

db = SQLAlchemy()
# creates a new csrf object
csrf = CSRFProtect()
# argon2 password hasher
ph = PasswordHasher()
# this is for the bio encryption
fernet = Fernet(Config.BIO_ENCRYPTION_KEY)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    #ednables csrf for this app
    csrf.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for user in users:
            # peppers the password and hashes it (argon2 salts internally )
            pepperedUserPassword = user["password"] + Config.PASSWORD_PEPPER
            hashed_password = ph.hash(pepperedUserPassword)

            #encrypts the bio so the database never stores it as plain text
            encryptedBio = fernet.encrypt(user["bio"].encode("utf-8")).decode("utf-8")

            seededUser = User(username=user["username"], password=hashed_password, role=user["role"], bio=encryptedBio)

            db.session.add(seededUser)
            db.session.commit()

    #this function adds https security headers to helpe prevent clickjacking, mime sniffing, and xss vectors
    @app.after_request
    def security_headers(response):
        # browser wont load page inside an iframe
        response.headers["X-Frame-Options"] = "DENY"
        # stops malicious file uploads and downloads being interpreted as scropts
        response.headers["X-Content-Type-Options"] = "nosniff"
        # makes it so sensitive urls arent leaked to external sites
        response.headers["Referrer-Policy"] = "no-referrer"
        # limits access to sensors and browser APIs
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"

        return response

    # Sets up logging only if no handlers already exists to avoid duplicates
    if not app.logger.handlers:
        logDir = "logs"

        # checks that the logs directory exists
        os.makedirs(logDir, exist_ok=True)
        logFile = os.path.join(logDir, "registration.log")

        # logs to a file which rotates when gets too big
        fileHandler = RotatingFileHandler(logFile, maxBytes=1024 * 1024, backupCount=5)

        # sets the format which is timestamp, level and message
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        fileHandler.setFormatter(formatter)

        # adds this handler to the logger
        app.logger.addHandler(fileHandler)
        app.logger.setLevel(logging.INFO)

    return app

