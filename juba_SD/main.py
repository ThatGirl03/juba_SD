from flask import Flask,  send_file, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
#from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from wtforms import StringField, SelectMultipleField, PasswordField, SelectField, SubmitField, TextAreaField, IntegerField, DateTimeLocalField, BooleanField
#from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField, IntegerField, DateTimeLocalField, BooleanField
#from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hack99slide_trojanhs32'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')  # Define the upload folder

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False  # Ensure SSL is disabled when using TLS
app.config['MAIL_USERNAME'] = 'm48209921@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'rufc leoy ymeb ywhm'  # Your Gmail app password
#app.config['MAIL_DEFAULT_SENDER'] = 'm48209921@gmail.com'


mail = Mail(app)
db = SQLAlchemy(app)  # Initialize db with the app




#application Models
#
#
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    surname = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    number = db.Column(db.String(20))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    company_host = db.Column(db.String(120))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SearchUserForm(FlaskForm):
    search_term = StringField('Search', render_kw={"placeholder": "Search by ID, Name, Surname"})
    role_filter = SelectField('Filter by Role', choices=[('', 'All Roles'), ('intern', 'Intern'), ('virtual_student', 'Virtual Student'), ('inperson_student', 'In-Person Student'), ('facilitator', 'Facilitator')], default='')
    submit = SubmitField('Search')

class EditUserForm(FlaskForm):
    user_id = StringField('User ID', validators=[DataRequired()], render_kw={'readonly': True})
    name = StringField('Name', validators=[DataRequired()])
    surname = StringField('Surname', validators=[DataRequired()])
    role = SelectField('Role', choices=[('intern', 'Intern'), ('virtual_student', 'Virtual Student'), ('inperson_student', 'In-Person Student'), ('facilitator', 'Facilitator')], validators=[DataRequired()])
    number = StringField('Number')
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    company_host = StringField('Company Host (Optional)')
    submit = SubmitField('Update User')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddUserForm(FlaskForm):
    user_id = StringField('User ID', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    surname = StringField('Surname', validators=[DataRequired()])
    role = SelectField('Role', choices=[('intern', 'Intern'), ('virtual_student', 'Virtual Student'), ('inperson_student', 'In-Person Student'), ('facilitator', 'Facilitator')], validators=[DataRequired()])
    number = StringField('Number')
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    company_host = StringField('Company Host (Optional)')
    submit = SubmitField('Add User')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    number = StringField('Number')
    submit = SubmitField('Update Profile')

class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Update Password')


class AddModuleForm(FlaskForm):
    module_name = StringField('Module Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    pass_mark = IntegerField('Pass Mark', validators=[DataRequired(), NumberRange(min=0, max=100)])
    facilitator_id = SelectField('Facilitator', coerce=int, validators=[DataRequired()])
    duration_months = IntegerField('Duration (Months)')
    submit = SubmitField('Add Module')

class EnrollStudentForm(FlaskForm):
    student_id = SelectField('Student to Enroll', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Enroll Student')

class UploadFileForm(FlaskForm):
    file = FileField('Upload File', validators=[FileRequired(), FileAllowed(['pdf'])])
    submit = SubmitField('Upload')

class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    pass_mark = db.Column(db.Integer, nullable=False)
    facilitator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    facilitator = db.relationship('User', backref='facilitated_modules', lazy=True)  # Add this relationship
    duration_months = db.Column(db.Integer)
    files = db.relationship('ModuleFile', backref='module', lazy=True)
    students = db.relationship('User', secondary='enrollment', backref=db.backref('modules', lazy='dynamic'))

class ModuleFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False) # Store the path to the file

enrollment = db.Table('enrollment',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('module_id', db.Integer, db.ForeignKey('module.id'), primary_key=True)
)


#for the tests

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    module = db.relationship('Module', backref=db.backref('tests', lazy=True))
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    duration_minutes = db.Column(db.Integer)
    is_open = db.Column(db.Boolean, default=False)
    questions = db.relationship('Question', backref='test', lazy=True)
    module = db.relationship('Module', backref='tests')  # Relationship

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255))
    option4 = db.Column(db.String(255))
    correct_answer = db.Column(db.String(1)) # 'A', 'B', 'C', or 'D'

class StudentTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    test = db.relationship('Test', backref=db.backref('student_attempts', lazy=True))
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student = db.relationship('User', backref=db.backref('test_attempts', lazy=True))
    start_attempt_time = db.Column(db.DateTime)
    submit_time = db.Column(db.DateTime)
    grade = db.Column(db.Integer) # Null initially, updated after grading
    answers = db.relationship('Answer', backref='student_test', lazy=True)
    attempted = db.Column(db.Boolean, default=False) # To ensure only one attempt

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_test_id = db.Column(db.Integer, db.ForeignKey('student_test.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    question = db.relationship('Question', backref=db.backref('student_answers', lazy=True))
    selected_option = db.Column(db.String(1))


#Test Forms
class CreateTestForm(FlaskForm):
    title = StringField('Test Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    start_time = DateTimeLocalField('Start Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    end_time = DateTimeLocalField('End Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    duration_minutes = IntegerField('Duration (Minutes)', validators=[DataRequired(), NumberRange(min=1)])
    is_open = BooleanField('Open for Students')
    submit = SubmitField('Create Test')

class AddQuestionForm(FlaskForm):
    question_text = TextAreaField('Question Text', validators=[DataRequired()])
    option1 = StringField('Option A', validators=[DataRequired()])
    option2 = StringField('Option B', validators=[DataRequired()])
    option3 = StringField('Option C')
    option4 = StringField('Option D')
    correct_answer = SelectField('Correct Answer', choices=[('A', 'A'), ('B', 'B'), ('C', 'C'), ('D', 'D')], validators=[DataRequired()])
    submit = SubmitField('Add Question')

class TakeTestForm(FlaskForm):
    submit = SubmitField('Submit Test') # The questions will be dynamically added

class Timesheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    intern_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    intern = db.relationship('User', backref='timesheets', lazy=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

class TimesheetUploadForm(FlaskForm):
    file = FileField('Upload Timesheet', validators=[FileRequired(), FileAllowed(['pdf'], 'PDF files only!')])
    submit = SubmitField('Upload')

class EmailToGroupForm(FlaskForm):
    send_to_students = BooleanField('Send to All Students')
    send_to_facilitators = BooleanField('Send to All Facilitators')
    subject = StringField('Subject', validators=[DataRequired(), Length(max=255)])
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Send Email')















##
##
##ROUTES
@app.before_request
def create_admin():
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(user_id='ADMIN001', name='Admin', surname='User', role='admin', username='admin', company_host=None)
            admin.set_password('admin123')  # Hardcoded admin password
            db.session.add(admin)
            db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', form=form, error='Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return render_template('admin_dashboard.html', user=user)
        elif user.role == 'intern':
            return render_template('intern_dashboard.html', user=user)
        elif user.role == 'virtual_student':
            return render_template('virtual_student_dashboard.html', user=user)
        elif user.role == 'inperson_student':
            return render_template('inperson_student_dashboard.html', user=user)
        elif user.role == 'facilitator':
            return render_template('facilitator_dashboard.html', user=user)
    return redirect(url_for('login'))

@app.route('/admin/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' in session and session['role'] == 'admin':
        form = AddUserForm()
        if form.validate_on_submit():
            # Check for duplicates
            if User.query.filter_by(user_id=form.user_id.data).first():
                flash('User ID already exists. Please use a different one.', 'danger')
            elif User.query.filter_by(username=form.username.data).first():
                flash('Username already taken. Please choose another.', 'danger')
            elif User.query.filter_by(number=form.number.data).first():
                flash('Phone number already in use.', 'danger')
            else:
                try:
                    new_user = User(
                        user_id=form.user_id.data,
                        name=form.name.data,
                        surname=form.surname.data,
                        role=form.role.data,
                        number=form.number.data,
                        username=form.username.data,
                        company_host=form.company_host.data if form.company_host.data else None
                    )
                    new_user.set_password(form.password.data)
                    db.session.add(new_user)
                    db.session.commit()
                    flash('User added successfully!', 'success')
                    return redirect(url_for('dashboard'))
                except Exception as e:
                    db.session.rollback()
                    flash('An error occurred while adding the user. Please try again.', 'danger')
        return render_template('add_user.html', form=form)
    return redirect(url_for('login'))

@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' in session and session['role'] == 'admin':
        search_form = SearchUserForm()
        users = User.query.all()

        if search_form.validate_on_submit():
            search_term = search_form.search_term.data.strip().lower()
            role_filter = search_form.role_filter.data

            query = User.query
            if search_term:
                query = query.filter(db.or_(
                    db.func.lower(User.user_id).contains(search_term),
                    db.func.lower(User.name).contains(search_term),
                    db.func.lower(User.surname).contains(search_term)
                ))
            if role_filter:
                query = query.filter_by(role=role_filter)

            users = query.all()

        return render_template('manage_users.html', users=users, search_form=search_form)
    return redirect(url_for('login'))

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' in session and session['role'] == 'admin':
        user_to_edit = User.query.get_or_404(user_id)
        form = EditUserForm(obj=user_to_edit)

        if form.validate_on_submit():
            # Check for duplicates (only if changed and not same user)
            existing_username = User.query.filter_by(username=form.username.data).first()
            existing_number = User.query.filter_by(number=form.number.data).first()
            existing_user_id = User.query.filter_by(user_id=form.user_id.data).first()

            if existing_user_id and existing_user_id.id != user_to_edit.id:
                flash('User ID is already taken by another user.', 'danger')
            elif existing_username and existing_username.id != user_to_edit.id:
                flash('Username is already taken.', 'danger')
            elif existing_number and existing_number.id != user_to_edit.id:
                flash('Phone number already in use.', 'danger')
            else:
                try:
                    user_to_edit.name = form.name.data
                    user_to_edit.surname = form.surname.data
                    user_to_edit.role = form.role.data
                    user_to_edit.number = form.number.data
                    user_to_edit.username = form.username.data
                    user_to_edit.company_host = form.company_host.data if form.company_host.data else None
                    db.session.commit()
                    flash('User updated successfully.', 'success')
                    return redirect(url_for('manage_users'))
                except Exception as e:
                    db.session.rollback()
                    flash('Error updating user. Please try again.', 'danger')

        return render_template('edit_user.html', form=form, user=user_to_edit)
    return redirect(url_for('login'))

@app.route('/admin/users/delete/<int:user_id>')
def delete_user(user_id):
    if 'user_id' in session and session['role'] == 'admin':
        user_to_delete = User.query.get_or_404(user_id)
        if user_to_delete.role != 'admin': # Prevent deleting the main admin
            db.session.delete(user_to_delete)
            db.session.commit()
        return redirect(url_for('manage_users'))
    return redirect(url_for('login'))

@app.route('/profile/')
def view_profile():
    if 'user_id' in session and session['role'] != 'admin':
        user = User.query.get_or_404(session['user_id'])
        return render_template('profile.html', user=user)
    elif 'user_id' in session and session['role'] == 'admin':
        return redirect(url_for('dashboard')) # Redirect admin to dashboard
    return redirect(url_for('login'))

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' in session and session['role'] != 'admin':
        user = User.query.get_or_404(session['user_id'])
        form = UpdateProfileForm(obj=user)
        if form.validate_on_submit():
            existing_username = User.query.filter_by(username=form.username.data).first()
            existing_number = User.query.filter_by(number=form.number.data).first()

            if existing_username and existing_username.id != user.id:
                flash('Username is already taken.', 'danger')
            elif existing_number and existing_number.id != user.id:
                flash('Phone number already in use.', 'danger')
            else:
                user.username = form.username.data
                user.number = form.number.data
                try:
                    db.session.commit()
                    flash('Profile updated successfully!', 'success')
                    return redirect(url_for('view_profile'))
                except Exception as e:
                    db.session.rollback()
                    flash('Error updating profile. Please try again.', 'danger')
        return render_template('profile_edit.html', form=form, user=user)
    elif 'user_id' in session and session['role'] == 'admin':
        return redirect(url_for('dashboard')) # Redirect admin to dashboard
    return redirect(url_for('login'))

@app.route('/profile/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' in session and session['role'] != 'admin':
        user = User.query.get_or_404(session['user_id'])
        form = UpdatePasswordForm()
        if form.validate_on_submit():
            if user.check_password(form.current_password.data):
                user.set_password(form.new_password.data)
                try:
                    db.session.commit()
                    flash('Password updated successfully!', 'success')
                    return redirect(url_for('view_profile'))
                except Exception as e:
                    db.session.rollback()
                    flash('Error updating password. Please try again.', 'danger')
            else:
                flash('Incorrect current password.', 'danger')
        return render_template('profile_change_password.html', form=form)
    elif 'user_id' in session and session['role'] == 'admin':
        return redirect(url_for('dashboard')) # Redirect admin to dashboard
    return redirect(url_for('login'))

###
#STUDY PART
@app.route('/admin/modules')
def manage_modules():
    if 'user_id' in session and session['role'] == 'admin':
        modules = Module.query.all()
        return render_template('admin/manage_modules.html', modules=modules)
    return redirect(url_for('login'))

@app.route('/admin/modules/add', methods=['GET', 'POST'])
def add_module():
    if 'user_id' in session and session['role'] == 'admin':
        form = AddModuleForm()
        form.facilitator_id.choices = [(f.id, f.name + ' ' + f.surname) for f in User.query.filter_by(role='facilitator').all()]
        if form.validate_on_submit():
            new_module = Module(
                module_name=form.module_name.data,
                description=form.description.data,
                pass_mark=form.pass_mark.data,
                facilitator_id=form.facilitator_id.data,
                duration_months=form.duration_months.data
            )
            db.session.add(new_module)
            db.session.commit()
            flash('Module added successfully!', 'success')
            return redirect(url_for('manage_modules'))
        return render_template('admin/add_module.html', form=form)
    return redirect(url_for('login'))

@app.route('/admin/modules/edit/<int:module_id>', methods=['GET', 'POST'])
def edit_module(module_id):
    if 'user_id' in session and session['role'] == 'admin':
        module = Module.query.get_or_404(module_id)
        form = AddModuleForm(obj=module)
        form.facilitator_id.choices = [(f.id, f.name + ' ' + f.surname) for f in User.query.filter_by(role='facilitator').all()]
        if form.validate_on_submit():
            module.module_name = form.module_name.data
            module.description = form.description.data
            module.pass_mark = form.pass_mark.data
            module.facilitator_id = form.facilitator_id.data
            module.duration_months = form.duration_months.data
            db.session.commit()
            flash('Module updated successfully!', 'success')
            return redirect(url_for('manage_modules'))
        return render_template('admin/edit_module.html', form=form, module=module)
    return redirect(url_for('login'))

@app.route('/admin/modules/delete/<int:module_id>')
def delete_module(module_id):
    if 'user_id' in session and session['role'] == 'admin':
        module = Module.query.get_or_404(module_id)
        db.session.delete(module)
        db.session.commit()
        flash('Module deleted successfully!', 'success')
        return redirect(url_for('manage_modules'))
    return redirect(url_for('login'))

# Facilitator Module Management
@app.route('/facilitator/modules')
def facilitator_modules():
    if 'user_id' in session and session['role'] == 'facilitator':
        user_id = session['user_id']
        modules = Module.query.filter_by(facilitator_id=user_id).all()
        return render_template('facilitator/my_modules.html', modules=modules)
    return redirect(url_for('login'))

@app.route('/facilitator/modules/enroll/<int:module_id>', methods=['GET', 'POST'])
def enroll_students(module_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        module = Module.query.get_or_404(module_id)
        if module.facilitator_id != session['user_id']:
            flash('You are not the facilitator for this module.', 'danger')
            return redirect(url_for('facilitator_modules'))

        form = EnrollStudentForm()
        form.student_id.choices = [(s.id, s.name + ' ' + s.surname + ' (' + s.user_id + ')') for s in User.query.filter(User.role.in_(['intern', 'virtual_student', 'inperson_student'])).all()]

        if form.validate_on_submit():
            student = User.query.get_or_404(form.student_id.data)
            if student not in module.students:
                module.students.append(student)
                db.session.commit()
                flash(f'{student.name} {student.surname} enrolled in {module.module_name}', 'success')
                return redirect(url_for('enroll_students', module_id=module_id))
            else:
                flash(f'{student.name} {student.surname} is already enrolled in {module.module_name}', 'warning')

        enrolled_students = module.students
        available_students = [s for s in User.query.filter(User.role.in_(['intern', 'virtual_student', 'inperson_student'])).all() if s not in enrolled_students]
        form.student_id.choices = [(s.id, s.name + ' ' + s.surname + ' (' + s.user_id + ')') for s in available_students]

        return render_template('facilitator/enroll_students.html', form=form, module=module, enrolled_students=enrolled_students)
    return redirect(url_for('login'))

@app.route('/facilitator/modules/upload/<int:module_id>', methods=['GET', 'POST'])
def upload_module_file(module_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        module = Module.query.get_or_404(module_id)
        if module.facilitator_id != session['user_id']:
            flash('You are not the facilitator for this module.', 'danger')
            return redirect(url_for('facilitator_modules'))

        form = UploadFileForm()
        if form.validate_on_submit():
            if form.file.data:
                file = form.file.data
                filename = secure_filename(file.filename)
                upload_folder = app.config['UPLOAD_FOLDER']

                # Ensure the upload folder exists
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)

                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)

                new_file = ModuleFile(module_id=module_id, file_name=filename, file_path=file_path)
                db.session.add(new_file)
                db.session.commit()
                flash(f'File "{filename}" uploaded successfully to {module.module_name}', 'success')
                return redirect(url_for('upload_module_file', module_id=module_id))
        files = ModuleFile.query.filter_by(module_id=module_id).all()
        return render_template('facilitator/upload_file.html', form=form, module=module, files=files)
    return redirect(url_for('login'))


@app.route('/student/modules/file/view/<int:file_id>')
def view_file(file_id):
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        file_to_view = ModuleFile.query.get_or_404(file_id)
        module = file_to_view.module
        user = User.query.get_or_404(session['user_id'])
        if module in user.modules:
            return send_file(file_to_view.file_path, mimetype='application/pdf')
        else:
            flash('You do not have access to this file.', 'warning')
            return redirect(url_for('student_modules'))
    return redirect(url_for('login'))


@app.route('/facilitator/modules/file/delete/<int:file_id>')
def delete_module_file(file_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        file_to_delete = ModuleFile.query.get_or_404(file_id)
        module = file_to_delete.module
        if module.facilitator_id == session['user_id']:
            try:
                os.remove(file_to_delete.file_path) # Delete the file from the server
                db.session.delete(file_to_delete)
                db.session.commit()
                flash(f'File "{file_to_delete.file_name}" deleted successfully.', 'success')
            except Exception as e:
                flash(f'Error deleting file: {e}', 'danger')
            return redirect(url_for('upload_module_file', module_id=module.id))
        else:
            flash('You do not have permission to delete this file.', 'danger')
            return redirect(url_for('facilitator_modules'))
    return redirect(url_for('login'))

# Student Module Access
@app.route('/student/modules')
def student_modules():
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        user = User.query.get_or_404(session['user_id'])
        enrolled_modules = user.modules.all()
        return render_template('student/my_modules.html', enrolled_modules=enrolled_modules)
    return redirect(url_for('login'))

@app.route('/student/modules/<int:module_id>')
def view_module(module_id):
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        user = User.query.get_or_404(session['user_id'])
        module = Module.query.get_or_404(module_id)
        if module in user.modules:
            files = ModuleFile.query.filter_by(module_id=module_id).all()
            return render_template('student/view_module.html', module=module, files=files)
        else:
            flash('You are not enrolled in this module.', 'warning')
            return redirect(url_for('student_modules'))
    return redirect(url_for('login'))

@app.route('/student/modules/file/<int:file_id>')
def download_file(file_id):
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        file_to_download = ModuleFile.query.get_or_404(file_id)
        module = file_to_download.module
        user = User.query.get_or_404(session['user_id'])
        if module in user.modules:
            return send_file(file_to_download.file_path, as_attachment=True, download_name=file_to_download.file_name)
        else:
            flash('You do not have access to this file.', 'warning')
            return redirect(url_for('student_modules'))
    return redirect(url_for('login'))

##Testt posting and writting 
# Facilitator Test Management
# Facilitator Test Management
@app.route('/facilitator/modules/<int:module_id>/tests')
def manage_tests(module_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        module = Module.query.get_or_404(module_id)
        if module.facilitator_id != session['user_id']:
            flash('You do not have permission to manage tests for this module.', 'danger')
            return redirect(url_for('facilitator_modules'))
        tests = Test.query.filter_by(module_id=module_id).all()
        return render_template('facilitator/manage_tests.html', module=module, tests=tests)
    return redirect(url_for('login'))

@app.route('/facilitator/modules/<int:module_id>/tests/create', methods=['GET', 'POST'])
def create_test(module_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        module = Module.query.get_or_404(module_id)
        if module.facilitator_id != session['user_id']:
            flash('You do not have permission to create tests for this module.', 'danger')
            return redirect(url_for('facilitator_modules'))
        form = CreateTestForm()
        if form.validate_on_submit():
            new_test = Test(
                module_id=module_id,
                title=form.title.data,
                description=form.description.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                duration_minutes=form.duration_minutes.data,
                is_open=form.is_open.data
            )
            db.session.add(new_test)
            db.session.commit()
            flash('Test created successfully! Now add questions.', 'success')
            return redirect(url_for('manage_tests', module_id=module_id))
        return render_template('facilitator/create_test.html', module=module, form=form)
    return redirect(url_for('login'))

@app.route('/facilitator/tests/<int:test_id>/questions', methods=['GET', 'POST'])
def manage_questions(test_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        test = Test.query.get_or_404(test_id)
        if test.module.facilitator_id != session['user_id']:
            flash('You do not have permission to manage questions for this test.', 'danger')
            return redirect(url_for('facilitator_modules'))
        form = AddQuestionForm()
        if form.validate_on_submit():
            new_question = Question(
                test_id=test_id,
                question_text=form.question_text.data,
                option1=form.option1.data,
                option2=form.option2.data,
                option3=form.option3.data,
                option4=form.option4.data,
                correct_answer=form.correct_answer.data
            )
            db.session.add(new_question)
            db.session.commit()
            flash('Question added successfully!', 'success')
            return redirect(url_for('manage_questions', test_id=test_id))
        questions = Question.query.filter_by(test_id=test_id).all()
        return render_template('facilitator/manage_questions.html', test=test, form=form, questions=questions)
    return redirect(url_for('login'))

@app.route('/facilitator/questions/edit/<int:question_id>', methods=['GET', 'POST'])
def edit_question(question_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        question = Question.query.get_or_404(question_id)
        if question.test.module.facilitator_id != session['user_id']:
            flash('You do not have permission to edit this question.', 'danger')
            return redirect(url_for('facilitator_modules'))
        form = AddQuestionForm(obj=question)
        if form.validate_on_submit():
            question.question_text = form.question_text.data
            question.option1 = form.option1.data
            question.option2 = form.option2.data
            question.option3 = form.option3.data
            question.option4 = form.option4.data
            question.correct_answer = form.correct_answer.data
            db.session.commit()
            flash('Question updated successfully!', 'success')
            return redirect(url_for('manage_questions', test_id=question.test_id))
        return render_template('facilitator/edit_question.html', form=form, question=question)
    return redirect(url_for('login'))

@app.route('/facilitator/questions/delete/<int:question_id>')
def delete_question(question_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        question = Question.query.get_or_404(question_id)
        if question.test.module.facilitator_id == session['user_id']:
            test_id = question.test_id
            db.session.delete(question)
            db.session.commit()
            flash('Question deleted successfully!', 'success')
            return redirect(url_for('manage_questions', test_id=test_id))
        else:
            flash('You do not have permission to delete this question.', 'danger')
            return redirect(url_for('facilitator_modules'))
    return redirect(url_for('login'))

@app.route('/facilitator/tests/toggle/<int:test_id>')
def toggle_test_status(test_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        test = Test.query.get_or_404(test_id)
        if test.module.facilitator_id == session['user_id']:
            test.is_open = not test.is_open
            db.session.commit()
            flash(f'Test "{test.title}" is now {"open" if test.is_open else "closed"}.', 'info')
            return redirect(url_for('manage_tests', module_id=test.module_id))
        else:
            flash('You do not have permission to toggle the status of this test.', 'danger')
            return redirect(url_for('facilitator_modules'))
    return redirect(url_for('login'))

# Student Test Taking
@app.route('/student/modules/<int:module_id>/tests')
def view_module_tests(module_id):
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        module = Module.query.get_or_404(module_id)
        # This line filters tests by module_id AND is_open=True
        tests = Test.query.filter_by(module_id=module_id, is_open=True).all()
        student = User.query.get_or_404(session['user_id'])
        student_attempts = {st.test_id: st for st in StudentTest.query.filter_by(student_id=student.id).all()}
        return render_template('student/view_module_tests.html', module=module, tests=tests, student_attempts=student_attempts)
    return redirect(url_for('login'))

@app.route('/student/tests/<int:test_id>/attempt', methods=['GET', 'POST'])
def attempt_test(test_id):
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        test = Test.query.get_or_404(test_id)
        student = User.query.get_or_404(session['user_id'])
        now = datetime.utcnow()

        if not test.is_open:
            flash('This test is currently closed.', 'warning')
            return redirect(url_for('student_modules'))

        if test.start_time and now < test.start_time:
            flash(f'This test will be available from {test.start_time.strftime("%Y-%m-%d %H:%M")}.', 'info')
            return redirect(url_for('student_modules'))

        if test.end_time and now > test.end_time:
            flash('The time for this test has expired.', 'warning')
            return redirect(url_for('student_modules'))

        student_test = StudentTest.query.filter_by(test_id=test_id, student_id=student.id).first()

        if student_test and student_test.attempted:
            flash('You have already attempted this test.', 'warning')
            return redirect(url_for('student_modules'))

        questions = Question.query.filter_by(test_id=test_id).all()

        class QuestionForm(FlaskForm):
            submit = SubmitField('Submit Test')

        for question in questions:
            choices = [('A', question.option1), ('B', question.option2)]
            if question.option3:
                choices.append(('C', question.option3))
            if question.option4:
                choices.append(('D', question.option4))
            setattr(QuestionForm, f'question_{question.id}', RadioField(question.question_text, choices=choices, validators=[DataRequired()]))

        form = QuestionForm()

        if form.validate_on_submit():
            if not student_test:
                student_test = StudentTest(test_id=test_id, student_id=student.id, start_attempt_time=now, attempted=True)
                db.session.add(student_test)
                db.session.commit()

            for question in questions:
                selected_option = form.data.get(f'question_{question.id}')
                if selected_option:
                    answer = Answer(student_test_id=student_test.id, question_id=question.id, selected_option=selected_option)
                    db.session.add(answer)

            student_test.submit_time = datetime.utcnow()
            db.session.commit()
            flash('Test submitted successfully! Your results are not yet graded.', 'success')
            return redirect(url_for('view_student_test_results', test_id=test_id))

        return render_template('student/attempt_test.html', test=test, form=form, questions=questions)
    return redirect(url_for('login'))

@app.route('/student/tests/<int:test_id>/results')
def view_student_test_results(test_id):
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        test = Test.query.get_or_404(test_id)
        student = User.query.get_or_404(session['user_id'])
        student_test = StudentTest.query.filter_by(test_id=test_id, student_id=student.id).first()

        if not student_test or not student_test.submit_time:
            flash('You have not submitted this test yet.', 'warning')
            return redirect(url_for('student_modules'))

        return render_template('student/view_student_test_results.html', test=test, student_test=student_test)
    return redirect(url_for('login'))

@app.route('/student/my_tests')
def view_my_tests():
    if 'user_id' in session and session['role'] in ['intern', 'virtual_student', 'inperson_student']:
        student = User.query.get_or_404(session['user_id'])
        student_tests = StudentTest.query.filter_by(student_id=student.id).order_by(StudentTest.submit_time.desc()).all()
        return render_template('student/my_tests.html', student_tests=student_tests)
    return redirect(url_for('login'))

# Grading (Facilitator)
@app.route('/facilitator/tests/<int:test_id>/grade')
def grade_test(test_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        test = Test.query.get_or_404(test_id)
        if test.module.facilitator_id != session['user_id']:
            flash('You do not have permission to grade this test.', 'danger')
            return redirect(url_for('facilitator_modules'))
        student_tests = StudentTest.query.filter_by(test_id=test_id, submit_time=db.not_(None)).all()
        return render_template('facilitator/grade_test.html', test=test, student_tests=student_tests)
    return redirect(url_for('login'))

@app.route('/facilitator/student_test/<int:student_test_id>/grade', methods=['GET', 'POST'])
def grade_student_test(student_test_id):
    if 'user_id' in session and session['role'] == 'facilitator':
        student_test = StudentTest.query.get_or_404(student_test_id)
        if student_test.test.module.facilitator_id != session['user_id']:
            flash('You do not have permission to grade this submission.', 'danger')
            return redirect(url_for('facilitator_modules'))

        questions = Question.query.filter_by(test_id=student_test.test_id).all()
        student_answers = {answer.question_id: answer.selected_option for answer in student_test.answers}
        correct_count = 0

        for question in questions:
            if question.id in student_answers and student_answers[question.id] == question.correct_answer:
                correct_count += 1

        total_questions = len(questions)
        if total_questions > 0:
            grade = int((correct_count / total_questions) * 100)
            student_test.grade = grade
            db.session.commit()
            flash(f'Student\'s test graded. Score: {grade}%', 'success')
        else:
            flash('This test has no questions to grade.', 'warning')

        return redirect(url_for('grade_test', test_id=student_test.test_id))
    return redirect(url_for('login'))


##TIMESHEETS
@app.route('/intern/timesheets/upload', methods=['GET', 'POST'])
def upload_timesheet():
    if 'user_id' in session and session['role'] == 'intern':
        form = TimesheetUploadForm()
        if form.validate_on_submit():
            file = form.file.data
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'timesheets')

            # Ensure the upload folder exists
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            new_timesheet = Timesheet(
                intern_id=session['user_id'],
                file_name=filename,
                file_path=file_path
            )
            db.session.add(new_timesheet)
            db.session.commit()
            flash('Timesheet uploaded successfully!', 'success')
            return redirect(url_for('upload_timesheet'))
        return render_template('intern/upload_timesheet.html', form=form)
    return redirect(url_for('login'))


@app.route('/admin/timesheets')
def view_timesheets():
    if 'user_id' in session and session['role'] == 'admin':
        timesheets = Timesheet.query.all()
        return render_template('admin/view_timesheets.html', timesheets=timesheets)
    return redirect(url_for('login'))

@app.route('/admin/timesheets/download/<int:timesheet_id>')
def download_timesheet(timesheet_id):
    if 'user_id' in session and session['role'] == 'admin':
        timesheet = Timesheet.query.get_or_404(timesheet_id)
        return send_file(timesheet.file_path, as_attachment=True, download_name=timesheet.file_name)
    return redirect(url_for('login'))


#EMAILING 
@app.route('/facilitator/email/group', methods=['GET', 'POST'])
def email_group():
    if 'user_id' in session and session['role'] == 'facilitator':
        form = EmailToGroupForm()

        if form.validate_on_submit():
            if form.send_to_students.data:
                # Send to all students
                recipients = [user.username for user in User.query.filter_by(role='virtual_student').all()]
            elif form.send_to_facilitators.data:
                # Send to all facilitators
                recipients = [user.username for user in User.query.filter_by(role='facilitator').all()]
            else:
                flash('Please select a group to send the email to.', 'danger')
                return redirect(url_for('email_group'))

            if not recipients:
                flash('No recipients found.', 'danger')
                return redirect(url_for('email_group'))

            # Send the email
            msg = Message(
                subject=form.subject.data,
                sender=app.config['MAIL_USERNAME'],
                recipients=recipients,
                body=form.body.data
            )
            mail.send(msg)
            flash('Email sent successfully!', 'success')
            return redirect(url_for('email_group'))

        return render_template('facilitator/email_students.html', form=form)
    return redirect(url_for('login'))












if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)