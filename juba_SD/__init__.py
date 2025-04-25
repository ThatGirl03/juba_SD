import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()  # Initialize db here

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads') # Define the upload folder

    db.init_app(app)

    from . import main  # Import the routes (main.py)
    from . import models # Import the models module
    from . import profile # Import the profile blueprint
    app.register_blueprint(profile.profile_bp) # Register the profile blueprint

    with app.app_context():
        db.create_all()

    return app