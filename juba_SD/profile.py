
from flask import Blueprint, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from .models import db, User

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    number = StringField('Number')
    submit = SubmitField('Update Profile')

class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Update Password')

@profile_bp.route('/')
def view_profile():
    if 'user_id' in session:
        user = User.query.get_or_404(session['user_id'])
        return render_template('profile/view_profile.html', user=user)
    return redirect(url_for('login'))

@profile_bp.route('/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' in session:
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
                    return redirect(url_for('profile.view_profile'))
                except Exception as e:
                    db.session.rollback()
                    flash('Error updating profile. Please try again.', 'danger')
        return render_template('profile/edit_profile.html', form=form, user=user)
    return redirect(url_for('login'))

@profile_bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' in session:
        user = User.query.get_or_404(session['user_id'])
        form = UpdatePasswordForm()
        if form.validate_on_submit():
            if user.check_password(form.current_password.data):
                user.set_password(form.new_password.data)
                try:
                    db.session.commit()
                    flash('Password updated successfully!', 'success')
                    return redirect(url_for('profile.view_profile'))
                except Exception as e:
                    db.session.rollback()
                    flash('Error updating password. Please try again.', 'danger')
            else:
                flash('Incorrect current password.', 'danger')
        return render_template('profile/change_password.html', form=form)
    return redirect(url_for('login'))