from flask import Flask, abort, render_template, redirect, url_for, flash, request, session, send_file
from flask_bootstrap import Bootstrap4
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, LargeBinary
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from form import UploadingVideo, LoginForm, Register
import os
from io import BytesIO
from flask_mail import Mail, Message

class Base(DeclarativeBase):
    pass

login_manager = LoginManager()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL')

db = SQLAlchemy(app, model_class=Base)
login_manager.init_app(app)
bootstrap = Bootstrap4(app)

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column(String)

class Uploads(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    person: Mapped[str] = mapped_column(String)
    filename: Mapped[str] = mapped_column(String)
    data: Mapped[bytes] = mapped_column(LargeBinary, unique=True)

with app.app_context():
    db.create_all()

def is_admin():
    return current_user.username == 'Faceit'

@app.route("/", methods=['GET', 'POST'])
def home():
    if not current_user.is_authenticated:
        return render_template('error.html', error='You have to be logged in to use this page')

    if not is_admin():
        return render_template('error.html', error='You have to be logged in as admin to use this page')

    form = UploadingVideo()
    if request.method == 'POST':
        file_uploaded = request.files['video_file']
        person_name = request.form['name']
        upload = Uploads(
            filename=file_uploaded.filename,
            person=person_name,
            data=file_uploaded.read()
        )
        db.session.add(upload)
        db.session.commit()
        return f'Uploaded {file_uploaded.filename}'

    return render_template('index.html', form=form, current_user=current_user)

@app.route('/files', methods=['GET', 'POST'])
def files():
    if not current_user.is_authenticated:
        return render_template('error.html', error='You have to be logged in to use this page')

    if not is_admin():
        return render_template('error.html', error='You have to be logged in as admin to use this page')

    if request.method == 'POST':
        query = request.form.get('query').lower()
        specific_files = db.session.execute(db.select(Uploads).where(Uploads.person == query)).fetchall()
        files_list = [f[0] for f in specific_files]
        return render_template('files.html', files=files_list)

    files = db.session.execute(db.select(Uploads)).fetchall()
    files_list = [f[0] for f in files]
    return render_template('files.html', files=files_list)

@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return render_template('error.html', error='You have to be logged out to use this page')

    form = Register()
    if form.validate_on_submit():
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            password_hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(username=username, password=password_hashed)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        except IntegrityError:
            return render_template('error.html', error='This username is already registered. Please use another username.')

    return render_template('register.html', form=form)

@app.route('/download/<file_id>')
def download(file_id):
    if not current_user.is_authenticated or not is_admin():
        return render_template('error.html', error='You have to be logged in as admin to use this page')

    requested_file = db.session.execute(db.select(Uploads).where(Uploads.id == file_id)).scalar()
    if requested_file:
        return send_file(BytesIO(requested_file.data), download_name=requested_file.filename, as_attachment=True)

    return render_template('error.html', error='File not found')

@app.route('/preview/<file_id>')
def preview(file_id):
    if not current_user.is_authenticated or not is_admin():
        return render_template('error.html', error='You have to be logged in as admin to use this page')

    requested_file = db.session.execute(db.select(Uploads).where(Uploads.id == file_id)).scalar()
    if requested_file:
        return send_file(BytesIO(requested_file.data), as_attachment=False, download_name=requested_file.filename)

    return render_template('error.html', error='File not found')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return render_template('error.html', error='You are already logged in!')

    form = LoginForm()
    if form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        user_requested = db.session.execute(db.select(User).where(User.username == username)).scalar()
        if user_requested and check_password_hash(user_requested.password, password):
            login_user(user_requested)
            return redirect(url_for('home'))

        flash('Password or username is incorrect')
        return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    if not current_user.is_authenticated:
        return render_template('error.html', error='You have to be logged in to use this page')

    logout_user()
    return render_template('error.html', error='You have logged out!')

if __name__ == '__main__':
    app.run()
