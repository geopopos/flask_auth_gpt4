from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_migrate import Migrate
from celery import Celery

import secrets
import os

load_dotenv()
SECRET_KEY = os.environ.get('SECRET_KEY')

app = Flask(__name__)
# secret key for signing cookies
app.config['SECRET_KEY'] = SECRET_KEY
# app.config['SERVER_NAME'] = '127.0.0.1:5001'
# Database set up
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
db = SQLAlchemy(app)
# when changing to postgres, uncomment the following line
# migrate = Migrate(app, db)

# Flask login set up
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# flask mail set up
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = os.environ.get('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# celery set up
def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

app.config['CELERY_BROKER_URL'] = os.environ.get('CELERY_BROKER_URL')
app.config['CELERY_RESULT_BACKEND'] = os.environ.get('CELERY_RESULT_BACKEND')
celery = make_celery(app)

# email sending celery task
@celery.task
def send_confirmation_email(user_id):
    user = User.query.get(user_id)
    if not user.confirmed:
        token = user.token
        confirm_url = ''
        with app.app_context():
            confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message("Please confirm your email", recipients=[user.email])
        msg.body = f"Click on this link to confirm your email: {confirm_url}"
        mail.send(msg)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False, nullable=False)
    token = db.Column(db.String(64), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_token(self):
        self.token = secrets.token_hex(32)


# create a root route that says hello world
@app.route('/')
def index():
    return "hello world"


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.generate_token()
        db.session.add(new_user)
        db.session.commit()

        send_confirmation_email.delay(new_user.id)

        flash('Registration successful. Please check your email and click the link to verify your account')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = request.form.get('remember', False)

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash('Login successful')
            return redirect(url_for('profile'))

        flash('Invalid email or password')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(token=token).first()

    if user is None:
        flash('Invalid or expired confirmation token')
        return redirect(url_for('login'))

    if user.confirmed:
        flash('Your email has already been confirmed')
        return redirect(url_for('login'))

    user.confirmed = True
    user.token = None
    db.session.commit()

    flash('Your email has been confirmed. You can now log in.')
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/profile')
@login_required
def profile():
    return f'Welcome, {current_user.username}!'


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500



if __name__ == '__main__':
    app.run(debug=True)
