from flask import Flask, render_template, redirect, url_for, request, flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import os
from werkzeug.utils import secure_filename
from flask import current_app

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.config.from_object('config.Config')

mysql = MySQL(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, id_, username, email, profile_image):
        self.id = id_
        self.username = username
        self.email = email
        self.profile_image = profile_image

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user['id'], user['username'], user['email'], user['profile_image'])
    return None

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    profile_image = FileField('Profile Image', validators=[Optional()])
    submit = SubmitField('Save Changes')


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data)

        cursor = mysql.connection.cursor()
        try:
            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                           (username, email, password))
            mysql.connection.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except MySQLdb.IntegrityError as e:
            if "Duplicate entry" in str(e) and "email" in str(e):
                flash('This email is already registered. Please use a different one.', 'danger')
            else:
                flash('An error occurred while creating your account. Please try again.', 'danger')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (form.email.data,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], form.password.data):
            user_obj = User(user['id'], user['username'], user['email'], user['profile_image'])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('users/dashboard.html', username=current_user.username)


@app.route('/profile')
@login_required
def profile():
    return render_template('users/profile.html', user=current_user)


@app.route('/settings')
@login_required
def settings():
    return render_template('users/settings.html', user=current_user)


@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileForm()
    if request.method == 'POST':
        # Get uploaded file
        file = request.files.get('profile_image')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(current_app.root_path, 'static/uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)

            # Save filepath or filename in your DB (update user record)
            cursor = mysql.connection.cursor()
            cursor.execute('UPDATE users SET profile_image=%s WHERE id=%s', (filename, current_user.id))
            mysql.connection.commit()
            cursor.close()

            flash('Profile updated successfully', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type', 'danger')

    return render_template('users/edit_profile.html', form=form)





@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
