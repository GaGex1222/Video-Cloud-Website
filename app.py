
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


SECRET_KEY = os.getenv('SECRET_KEY')
FACEIT_DATABASE_URL = os.getenv('DATABASE_URL')
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = FACEIT_DATABASE_URL
app.config
db = SQLAlchemy(model_class=Base)
login_manager.init_app(app)
db.init_app(app)
bootstrap = Bootstrap4(app)

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column(String)

class Uploads(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    person: Mapped[str] = mapped_column(String)
    filename: Mapped[str] = mapped_column(String)
    data: Mapped[bytes] = mapped_column(LargeBinary ,unique=True)


with app.app_context():
    db.create_all()




@app.route("/", methods=['GET', 'POST'])
def home():
    if not current_user.is_authenticated:
        error = 'You have to be logged in to use this page'
        return render_template('error.html', error=error)
    if current_user.username == 'Faceit':
        form = UploadingVideo()
    else:
        error = 'You have to be logged in as admin to use this page'
        return render_template('error.html', error=error)
    if request.method == 'POST':
        if current_user.is_authenticated:
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
        else:
            error = 'You have to be logged in to use this page'
            return render_template('error.html', error=error)
    return render_template('index.html', form=form, current_user=current_user)

@app.route('/files', methods=['GET', 'POST'])
def files():
    if not current_user.is_authenticated:
        error = 'You have to be logged in to use this page'
        return render_template('error.html', error=error)
    if current_user.username == 'Faceit':
        if request.method == 'POST':
            query = request.form.get('query').lower()
            specific_files = db.session.execute(db.select(Uploads).where(Uploads.person == query)).fetchall()
            files_list = [f[0] for f in specific_files]
            return render_template('files.html', files=files_list)
        files = db.session.execute(db.select(Uploads)).fetchall()
        files_list = []
        for f in files:
            f = f[0]
            files_list.append(f)
        return render_template('files.html', files=files_list)
    else:
        error = 'You have to be logged as Admin to use this page'
        return render_template('error.html', error=error)
    


@app.route('/register', methods=['POST', 'GET'])
def register():
    if not current_user.is_authenticated:
        form = Register()
    else:
        error = 'You have to be logged out to use this page'
        return render_template('error.html', error=error)
    if form.validate_on_submit():
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            password_hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                username=username,
                password=password_hashed
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        except IntegrityError as e:
            error = f'{e}--------------------- Basically means that this user is already registered you fucking baka use another user'
            return render_template('error.html', error=error)
    return render_template('register.html' ,form=form)

@app.route('/download/<file_id>')
def download(file_id):
    if not current_user.is_authenticated:
        error = 'You have to be logged in to use this page'
        return render_template('error.html', error=error)
    if current_user.username == 'Faceit':
        requested_file = db.session.execute(db.select(Uploads).where(Uploads.id == file_id)).scalar()
        return send_file(BytesIO(requested_file.data), download_name=requested_file.filename, as_attachment=True)
    else:
        error = 'You have to be logged in as admin to use this page'
        return render_template('error.html', error=error)
@app.route('/preview/<file_id>')
def preview(file_id):
    if current_user.username == 'Faceit' and current_user.is_authenticated:
        requested_file = db.session.execute(db.select(Uploads).where(Uploads.id == file_id)).scalar()
        if requested_file:
            return send_file(BytesIO(requested_file.data), as_attachment=False, download_name=requested_file.filename)
        else:
            error = 'Couldnt find video'
            return render_template('error.html', error=error)
    else:
        error = 'You have to be logged in to use this page'
        return render_template('error.html', error=error)

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        error = 'You Are Already Logged In Baka!'
        return render_template('error.html', error=error)
    if form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        user_requested = db.session.execute(db.select(User).where(User.username == username)).scalar()
        if user_requested.username == username and check_password_hash(user_requested.password, password):
            login_user(user_requested)
        else:
            flash('Password Or Username is incorrect')
            return redirect(url_for('login'))
        return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    if not current_user.is_authenticated:
        error = 'You have to be logged in to use this page'
        return render_template('error.html', error=error)

    if current_user.is_authenticated:
        logout_user()
        error = 'You Have Logged out baka!'
        return render_template('error.html', error=error)
    else:
        error = 'You are not logged in'
        return render_template('error.html', error=error)

if __name__ == '__main__':
    app.run(debug=True)