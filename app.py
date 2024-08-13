from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_bootstrap import Bootstrap4
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import  String
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from form import UploadingVideo, LoginForm, Register
import os


class Base(DeclarativeBase):
    pass

login_manager = LoginManager()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL_REAL')
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
 


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
    file_path: Mapped[str] = mapped_column(String)

with app.app_context():
    db.create_all()

def is_admin():
    return current_user.username == 'Faceit'

allowed_ext = ['mp4', 'mov', 'mkv', 'avi']

def check_for_video_file_extensions(filename):
    if '.' in filename:
        return filename.rsplit('.')[1] in allowed_ext
    return False

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
        if file_uploaded:
            filename = secure_filename(file_uploaded.filename)
            file_uploaded.save(os.path.join('static', filename))
            upload = Uploads(
                filename=filename,
                person=person_name.lower(),
                file_path=f'static/{filename}'
            )
            db.session.add(upload)
            db.session.commit()
            error = f'Successfully uploaded {filename} to faceit storage'
            return render_template('error.html', error=error)

    return render_template('index.html', form=form, current_user=current_user)

@app.route('/files', methods=['GET', 'POST'])
def files():
    if not current_user.is_authenticated:
        return render_template('error.html', error='You have to be logged in to use this page')

    if not is_admin():
        return render_template('error.html', error='You have to be logged in as admin to use this page')

    if request.method == 'POST':
        query = request.form.get('query').lower()
        print(query)
        specific_files = db.session.execute(db.select(Uploads).where(Uploads.person == query)).fetchall()
        print(specific_files)
        files_list = [f[0] for f in specific_files]
        return render_template('files.html', files=files_list)

    files = db.session.execute(db.select(Uploads)).fetchall()
    files_list = [f[0] for f in files]
    print(files_list)
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
        return send_file(requested_file.file_path)
    else:
        return render_template('error.html', error='Cant find file in database')



@app.route('/preview/<file_id>')
def preview(file_id):
    if not current_user.is_authenticated or not is_admin():
        return render_template('error.html', error='You have to be logged in as admin to use this page')

    requested_file = db.session.execute(db.select(Uploads).where(Uploads.id == file_id)).scalar()
    if check_for_video_file_extensions(requested_file.filename):
        if requested_file:
            print('previewing file')
            return render_template('preview.html', requested_file=requested_file)
        else:
            error = 'No File Detected, tell gal'
            return render_template('error.html', error=error)
    else:
        error = 'File selected is not a video'
        return render_template('error.html', error=error)


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

@app.route('/delete/<file_id>', methods=['POST', 'GET'])
def delete(file_id):
    requested_video_query = db.session.execute(db.select(Uploads).where(Uploads.id == file_id)).scalar()
    if requested_video_query:
        db.session.delete(requested_video_query)
        db.session.commit()
        os.remove(requested_video_query.file_path)
        current_query_params = request.args.to_dict()
        return redirect(url_for('files', **current_query_params))
    else:
        return render_template('error.html', error=f'Couldnt find file with id of {file_id}, talk to gal')


@app.route('/logout')
def logout():
    if not current_user.is_authenticated:
        return render_template('error.html', error='You have to be logged in to use this page')

    logout_user()
    return render_template('error.html', error='You have logged out!')

if __name__ == '__main__':
    app.run()
