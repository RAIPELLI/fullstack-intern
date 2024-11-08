from flask import Flask
from config import Config
from models import db, bcrypt
from routes import main

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)

# Register blueprints
app.register_blueprint(main)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
