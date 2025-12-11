from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import *
from config import Config

db = SQLAlchemy()
# creates a new csrf object
csrf = CSRFProtect()

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
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"])
            db.session.add(user)
            db.session.commit()

    #this function adds https security headers to helpe prevent clickjacking, mime sniffing, and xss vectors
    @app.after_request
    def security_headers(response):
        # browser wont load page inside an iframe
        response.headers["X-Frame-Options"] = "DENY"
        # stops malicious file uplads and downloads being interpreted as scropts
        response.headers["X-Content-Type-Options"] = "nosniff"
        # makes it so sensitive urls arent leaked to external sites
        response.headers["Referrer-Policy"] = "no-referrer"
        # limits access to sensors and browser APIs
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"

        return response
    return app

