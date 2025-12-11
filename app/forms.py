from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import Email, Length, DataRequired

#class for the registration form with validation for each field
class RegisterForm(FlaskForm):
    userName = StringField(
        "Email",
        #these validators are the rules which the entered email must abide by
        validators=[
            #doesnt allow the email field to be entered empty
            DataRequired(message="email is required"),
            # must be in a proper email format
            Email(message="email must be valid"),
            # stops the user from entering an email that is way too long
            Length(max=30, message="email cant be longer than 30 characters"),
        ])

    #validation for the password
    password = PasswordField(
        "Password",
        validators=[
            # doesnt allow the password field to be empty and it has to be between 10 and 30 characters
            DataRequired(message="password is required"),
            Length(min=10, max=30, message="password must between 10 and 30 characters"),
        ])

    #validation for the biography field
    bio = TextAreaField(
        "Biography",
        validators=[
            # doesnt allow it to be empty and it cant be longer than 300 characters
            DataRequired(message="biography is required"),
            Length(min=1, max=300, message="biography must between 1 and 300 characters"),
        ]
    )

    #submit button
    submit = SubmitField("Register")

# this class creates the login form and contains the validation for each field
class LoginForm(FlaskForm):
    username = StringField(
        "Email",
        validators=[
            # raises error if email box is empty
            DataRequired(message="email is required"),
            # raises error if the wrong format is used
            Email(message="email must be valid"),
            Length(max=30, message="email cant be longer than 30 characters"),
        ]
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="password is required"),
            Length(min=10, max=30, message="password must between 10 and 30 characters"),
        ]
    )

    submit = SubmitField("Login")

# class allows the user to change the password with validation
class ChangePasswordForm(FlaskForm):
    currPassword = PasswordField(
        "Current Password",
        validators=[
            DataRequired(message="current password is required"),
            Length(min=10, max=30)
        ]
    )

    newPassword = PasswordField(
        "New Password",
        validators=[
            DataRequired(message="new password is required"),
            Length(min=10, max=30, message="new password must between 10 and 30 characters"),
        ]
    )

    submit = SubmitField("Change Password")