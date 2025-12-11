import traceback
import re
from bleach.sanitizer import ALLOWED_TAGS
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from sqlalchemy import text
from wtforms.validators import *
from argon2 import *
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from config import Config

from app import db
from app.models import User
from .forms import RegisterForm, LoginForm, ChangePasswordForm
import bleach

main = Blueprint('main', __name__)

# variables that contains the html whitelist used to clear user bios before theyre stored
ALLOWED_TAGS = ["b", "i", "u", "em", "strong", "a", "p", "ul", "ol", "li", "br"]
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}
# this variable holds the blacklist for passwords that cant be the following
PASSWORD_BLACKLIST = {"Password123$", "Qwerty123!", "Adminadmin1@","weLcome123!"}

# variables used for encryption later on in the file
ph = PasswordHasher()
fernet = Fernet(Config.BIO_ENCRYPTION_KEY)


"""helper function which checks password against all of the required rules and raises an error for each
rule which is broken
"""
def validate_password(password, username):
    # raises error if password is too short
    if len(password) < 10:
        raise ValidationError("Password must be at least 10 characters long")

    # raises and error if there isnt atleast one uppercase character
    if not any(c.isupper() for c in password):
        raise ValidationError("Password must contain at least one uppercase character")

    # raises an error if password doesnt contain atleast one lowercase character
    if not any(c.islower() for c in password):
        raise ValidationError("Password must contain at least one lowercase character")

    # raises an error if there is no number in the password
    if not any(c.isdigit() for c in password):
        raise ValidationError("Password must contain at least one number")

    # error raised if password does not contain atleast 1 special character
    if not any(not c.isalnum() for c in password):
        raise ValidationError("Password must contain at least one special character")

    # raises an error if the password contains the username (email)
    # check if this works
    emailName = username.split('@')[0].lower()
    if emailName and emailName in password.lower():
        raise ValidationError("Password cannot contain parts of the email")

    # raises an error if password is in PASSWORD_BLACKLIST
    if password in PASSWORD_BLACKLIST:
        raise ValidationError("Password cannot contain a blacklisted password")

    #CHECK IF THIS WORKS
    # raises an error if the password contains 3 repeating characters
    if re.search(r"(.)\1\1", password):
        raise ValidationError("Password cannot contain 3 repeating character (aaa)")

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    # changed how the login page deals with username and password to match forms.py
    form = LoginForm()
    # only proceeds if validation passes
    if form.validate_on_submit():
        # safely accesses the username and password data
        username = form.username.data
        password = form.password.data

        # user input treated as a paremeter instead of being merged into the sql string to prevent sql injection
        user = User.query.filter_by(username=username).first()

        if user:
            try:
                # checks if the password is correct
                pepperedPassword = password + Config.PASSWORD_PEPPER
                ph.verify(user.password, pepperedPassword)

                # login continues since password check is correct
                session.clear() # resets the ession so old ids arent reused
                session['user'] = user.username
                session['role'] = user.role
                session['bio'] = user.bio

                # logs successful logins
                current_app.logger.info("login successful user=%s ip=%s", username, request.remote_addr)

                return redirect(url_for('main.dashboard'))
            except VerifyMismatchError:
                pass

        current_app.logger.warning("login failed user=%s ip=%s", username, request.remote_addr)

        flash('Login credentials are invalid, please try again')
        # now also passes form so the fields and errors will render
    return render_template('login.html', form=form)

@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']

        # gets the latest user data from the database
        user = User.query.filter_by(username=username).first()

        if user is None:
            session.clear()
            return redirect(url_for('main.login'))

        # this try statement decrypts the biography before rendering it so the user can see it
        try:
            decryptedBio = fernet.decrypt(user.bio.encode("utf-8")).decode("utf-8")
        except Exception:
            #acts as a fall back for if something doesnt work
            decryptedBio = user.bio

        # this return statement passes the decrypted bio to the template
        return render_template('dashboard.html', username=user.username, bio=decryptedBio)
    # return to the main page if not logged in
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    # instantitaes the registration form
    form = RegisterForm()

    # runs server side validation checks
    if form.validate_on_submit():
        username = form.userName.data
        password = form.password.data
        # this is the users biogrophy before santatisation
        rawBio = form.bio.data

        """sanatises biography using the whitelist above before storing in database.
        Removes any scripts so the bio can be safely rendered with |safe in html
        """

        safeBio = bleach.clean(rawBio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)

        try:
            # runs the password policy checker and raises a validation error if it fails
            validate_password(password, username)

        except ValidationError as e:
            # adds the error to the password field to show the user what is wrong
            form.password.errors.append(str(e))
            return render_template('register.html', form=form)

        # the default rose on registration is set to user
        role = 'user'

        # hashing and peppering
        pepperedPassword = password + Config.PASSWORD_PEPPER
        hashedPassword = ph.hash(pepperedPassword)

        encryptedBio = fernet.encrypt(safeBio.encode('utf-8'))

        # adds the new user using parameterised sql so the query cant be broken by user input or sql attacks
        # pick this or omr ma
        db.session.execute(text(
            "INSERT INTO user (username, password, role, bio) "
            "VALUES (:username, :password, :role, :bio)"),
            {"username": username, "password": hashedPassword, "role": role, "bio": encryptedBio.decode('utf-8')})

        db.session.commit()

        current_app.logger.info("registration successful user=%s ip=%s", username, request.remote_addr)

        # feedback message to user
        flash('Registration successful!')
        return redirect(url_for('main.login'))

    # form passes so the template can shoe fields and any errors
    return render_template('register.html', form=form)

@main.route('/admin-panel')
def admin():
    # checks if the user is logged in is they have to be to access this page
    if 'user' not in session:
        # if user is not logged in send them to the login page
        return redirect(url_for('main.login'))

    # this runs if the user is logged in but does not have the admin role so it gives an error
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
def moderator():
    # checks if the user is logged in is they have to be to access this page
    if 'user' not in session:
        # if user is not logged in send them to the login page
        return redirect(url_for('main.login'))

    # this runs if the user is logged in but does not have the moderator role so it gives an error
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
def user_dashboard():
    # checks if the user is logged in is they have to be to access this page
    if 'user' not in session:
        # if user is not logged in send them to the login page
        return redirect(url_for('main.login'))

    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    # instantiates the password change form with WTform
    form = ChangePasswordForm()

    # only handles the POST if the validation passes
    if form.validate_on_submit():
        currPassword = form.currPassword.data
        newPassword = form.newPassword.data

        # uses orm to find user instead of making sql string by hand so username and currpassword are passed manually
        user = User.query.filter_by(username=username).first()

        #checks the current password
        try:
            ph.verify(user.password, currPassword + Config.PASSWORD_PEPPER)
        except Exception:
            # logs the failed password change attempt
            current_app.logger.warning("password change failed user=%s ip=%s", username, request.remote_addr)

            # flashes an error and reloads the page for the user to try again
            flash("Entered password is invalid, try again", "error")
            return render_template("change_password.html", form=form)

        # makes sure the new password being set is not the same as the old password
        try:
            ph.verify(user.password, newPassword + Config.PASSWORD_PEPPER)
            # after verifying, the two passwords are checked and if theyre the same the request is rejected
            current_app.logger.warning("password is the same as current password user=%s ip=%s", username, request.remote_addr)

            flash("Entered password cannot be the same as the old password", "error")
            return render_template("change_password.html", form=form)

        except Exception:
            # if new password is different then dont reject
            # CHECK
            pass

        # validates password complexity
        try:
            validate_password(newPassword, username)
        except ValidationError as e:
            flash(str(e), "error")
            return render_template("change_password.html", form=form)

        # rehashes the new password
        user.password = ph.hash(newPassword + Config.PASSWORD_PEPPER)
        db.session.commit()

        # logs successful password change
        current_app.logger.info("password change successful user=%s ip=%s", username, request.remote_addr)

        # flashes a success messages and redirects the user
        flash('Password updated successfully', category='success')
        return redirect(url_for('main.dashboard'))

    # re renders the form for the first GET and if validation fails
    return render_template('change_password.html', form=form)

"""post request will include a csrf token from the logout button in the top of the screen.
Get is theres as a fallback"""
@main.route('/logout', methods=['GET', 'POST'])
def logout():
    # logs the logout event if there was a user
    username = session.get('user')
    current_app.logger.info("logout successful user=%s ip=%s", username, request.remote_addr)

    #clears out the session so the user gets logged out
    session.clear()
    return redirect(url_for('main.login'))
