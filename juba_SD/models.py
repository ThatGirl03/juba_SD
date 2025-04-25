from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    surname = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(50), nullable=False) #Intern, Virtual-Student, Inperson-Student, Facilitator
    number = db.Column(db.String(20))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    company_host = db.Column(db.String(120), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    pass_mark = db.Column(db.Integer, nullable=False)
    facilitator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    duration_months = db.Column(db.Integer)
    files = db.relationship('ModuleFile', backref='module', lazy=True)
    students = db.relationship('User', secondary='enrollment', backref=db.backref('modules', lazy='dynamic'))

    def __repr__(self):
        return f'<Module {self.module_name}>'

class ModuleFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False) # Store the path to the file

enrollment = db.Table('enrollment',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('module_id', db.Integer, db.ForeignKey('module.id'), primary_key=True)

    
)
