import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
    SQLALCHEMY_DATABASE_URI = "postgresql://username:password@localhost:5432/your_database_name"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
