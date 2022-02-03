from unicodedata import category
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email = email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect Password!", category='error')
        else:
            flash("Email does not exist! Please Sign Up", category='error')
    return render_template("login.html", user = current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        lastName = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email = email).first()

        if user:
            flash("Email already exists! Please login", category='error')
        elif (len(email) < 4) or ('@' not in email):
            flash("Invalid Email", category='error')
        elif (len(firstName) < 2):
            flash("First name should be greater than 1 character", category='error')
        elif (len(password1) < 5):
            flash("Password should be of atleast 5 characters", category='error')
        elif (password1 != password2):
            flash("Passwords don't match", category='error')
        else:
            # add user to database
            new_user = User(email = email, first_name = firstName, last_name = lastName, password = generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            
            login_user(user, remember=True)
            flash("Account Created!", category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user = current_user)