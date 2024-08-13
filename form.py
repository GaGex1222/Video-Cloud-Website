from wtforms import StringField, SelectField, SubmitField, IntegerField, URLField, EmailField, PasswordField, FileField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class Register(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class UploadingVideo(FlaskForm):
    name = StringField('Name Of Person', validators=[DataRequired()], render_kw={'class':'form-control '})
    video_file = FileField('File:', validators=[DataRequired()], render_kw={'class':'form-control'})
    submit = SubmitField('Upload')