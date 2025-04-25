from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

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

