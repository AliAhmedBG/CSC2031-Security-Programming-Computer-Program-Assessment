class Config:
    DEBUG = True
    SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # below are the session cookie security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False

    # hardcoded pepper for password hashing
    PASSWORD_PEPPER = "password_pepper"
    # generetes the fernet key which is also hardcoded for now
    BIO_ENCRYPTION_KEY = b'LuvgNUtSkU-12VAUI4zaqDiP-er_LQxzQBj3CX9scC4='

