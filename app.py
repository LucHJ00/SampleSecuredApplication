import os, base64, random
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, abort, current_app
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError, Email
import onetimepass
import pyqrcode
import logging
import re
import jwt
from time import time, sleep
from datetime import datetime, timedelta


#Enable Logging
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')


#Create server instance 
app = Flask(__name__)
app.config.from_object('config') #will pull the configurations from the config.py in this directory

#initialise extensions
bootstrap = Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL']=True

db = SQLAlchemy(app)
lm = LoginManager(app)
csrf = CSRFProtect(app)
Talisman(app)

#Session Timeout
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)

#Mail configuration for password reset
app.config['MAIL_SERVER']='smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

#Create User model here (combining into one python script) 
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), index=True, unique=True)
    otp_secret = db.Column(db.String(16))
    #Bruteforce Protection
    login_attempts = db.Column(db.Integer)
    lockout_timestamp = db.Column(db.Integer)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            #generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        self.login_attempts = 0

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo'.format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode({'reset_password': self.id, 'exp': time() + expires_in},
                app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)
       

@lm.user_loader


def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(1,64)])
    email = StringField('Email', validators=[InputRequired(), Length(1,120), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(1,64)])
    password_again = PasswordField('Password again', validators=[InputRequired(), Length(1,32), EqualTo('password')])

    submit = SubmitField('Register')

    def validate_username(self, username):
        allowed_characters = '^[a-zA-Z0-9.-]+$'
        usr_str = self.username.data

        result = re.match(allowed_characters, usr_str)

        if not result:
            raise ValidationError("Illegal Characters have been detected. Please try again.")

        elif len(usr_str)<=7:
            raise ValidationError("Your username should be at least 8 characters long.")

    def validate_password(self, password):
        pass_str = self.password.data
        if len(self.password.data)<=7:
            raise ValidationError("Your password should be at least 8 characters long.")
        elif not re.search("[a-z]", pass_str):
            raise ValidationError("Your password must contain at least 1 lowercase character.")
        elif not re.search("[A-Z]", pass_str):
            raise ValidationError("Your password must contain at least 1 uppercase character.")
        elif not re.search("[0-9]", pass_str):
            raise ValidationError("Your password must contain at least 1 digit.")
        elif not re.search("[^A-Za-z0-9]", pass_str):
            raise ValidationError("Your password must contain at least 1 special character.")
        with current_app.open_resource("common_passwords.txt", "r") as f: 
            common_values = [line.rstrip("\n") for line in f]

        if any(value == pass_str for value in common_values):
            raise ValidationError("Please do not use a common password.")       


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(1,64)])
    password = PasswordField('Password', validators=[InputRequired(), Length(1,64)])
    token = StringField('Token', validators=[InputRequired(), Length(6, 6)])
    submit = SubmitField('Login')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    password2 = PasswordField('Repeat Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Password Reset Now')

    def validate_password(self, password):
        pass_str = self.password.data
        if len(self.password.data)<=7:
            raise ValidationError("Your password should be at least 8 characters long.")
        elif not re.search("[a-z]", pass_str):
            raise ValidationError("Your password must contain at least 1 lowercase character.")
        elif not re.search("[A-Z]", pass_str):
            raise ValidationError("Your password must contain at least 1 uppercase character.")
        elif not re.search("[0-9]", pass_str):
            raise ValidationError("Your password must contain at least 1 digit.")
        with current_app.open_resource("common_passwords.txt", "r") as f:
            common_values = [line.rstrip("\n") for line in f]

        if any(value == pass_str for value in common_values):
            raise ValidationError("Please do not use a common password.")


class SelfResetForm(FlaskForm):
    oldpassword = PasswordField('Please enter your old password', validators=[InputRequired(), Length(1,64)])
    password = PasswordField('Password', validators=[InputRequired(), Length(1,64)])
    password2 = PasswordField('Repeat Password', validators=[InputRequired(), Length(1,64), EqualTo('password')])
    email = StringField('Email', validators=[InputRequired(), Length(1,120), Email()])
    submit = SubmitField('Password Reset Now')

    def validate_password(self, password):
        pass_str = self.password.data
        if len(self.password.data)<=7:
            raise ValidationError("Your password should be at least 8 characters long.")
        elif not re.search("[a-z]", pass_str):
            raise ValidationError("Your password must contain at least 1 lowercase character.")
        elif not re.search("[A-Z]", pass_str):
            raise ValidationError("Your password must contain at least 1 uppercase character.")
        elif not re.search("[0-9]", pass_str):
            raise ValidationError("Your password must contain at least 1 digit.")
        with current_app.open_resource("common_passwords.txt", "r") as f:
            common_values = [line.rstrip("\n") for line in f]
        if any(value == pass_str for value in common_values):
            raise ValidationError("Please do not use a common password.")



#Defining function to send an email
def send_email(subject, recipients, text_body, html_body):
    msg = Message(subject, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('Reset Your Password',
            recipients=[user.email],
            text_body=render_template('email/reset_password.txt', user=user, token=token),
            html_body=render_template('email/reset_password.html', user=user, token=token))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    #User Registration Route
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    #Instantiate the registration form

    form = RegisterForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('The address you have entered is blacklisted or has already been taken.')
            return redirect(url_for('register'))

        #add a new user to the database
        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        #redirect to the two-factor auth page, pass username into session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)

@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
        #this page contains sensitive information
        #ensure browser does not cache the info
    return render_template('two-factor-setup.html'), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}

@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    #remove username from session for added security
    del session ['username']
    
    #render qr code for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate', 
            'Pragma': 'no-cache',
            'Expires': '0'}

@app.route('/login', methods=['GET', 'POST'])
def login():
    #User login route
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or not user.verify_totp(form.token.data):
            try:
                user.login_attempts += 1
            except:
                #do not expose any information re: existence of accounts
                sleep(random.uniform(0,1))
                return redirect(url_for("login"))
            
            if user.login_attempts >= 5:
                flash('Too many login attempts. Your account has been locked for 15 minutes.')
                app.logger.warning("Account locked out: " +  user.username)
                user.lockout_timestamp = int(datetime.now().timestamp())
                db.session.commit()
                sleep(random.uniform(0, 1))
                return redirect(url_for("login"))
            else:
                flash('Invalid username, password or token.')
                db.session.commit()
                return redirect(url_for('login'))

        elif user:
            current_time = int(datetime.now().timestamp())
            if user.login_attempts >=5 and current_time - user.lockout_timestamp < 900:
                flash('Too many login attempts. Your account has been locked for 15 minutes.') 
                #identical message, do not volunteer information
            else:
                login_user(user, remember=False) #I do not want the session to be persistent. 
                user.login_attempts = 0 
                user.lockout_timestamp = 0
                db.session.commit()
                sleep(random.uniform(0,1))
                flash('You are now logged in!')
                return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        sleep(random.uniform(1,2))
        if user:
            send_password_reset_email(user)
        flash('Please check your email inbox/junk folder for password reset instructions')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect (url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect (url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data 
        db.session.add(user) 
        db.session.commit()
        flash('Your password has been reset')
        return redirect (url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/self-reset', methods = ['GET', 'POST'])
def self_reset():
    if not current_user.is_authenticated:
        return redirect (url_for('index'))
    form = SelfResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.oldpassword.data):
            flash("You have entered an invalid email address or password. Please try again.")
            return redirect (url_for('self_reset'))
        user.password = form.password.data
        db.session.add(user)
        db.session.commit()
        flash('Your password has been reset')
        return redirect (url_for('index'))
    return render_template('self_reset.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index')) 

db.drop_all()
db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port="7999", debug=True, ssl_context=('certs/cert.pem', 'certs/key.pem'))
