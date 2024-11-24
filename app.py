from flask import Flask, request, render_template, flash, redirect, url_for, session, abort,send_from_directory,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_uploads import UploadSet, configure_uploads, IMAGES
import random
import string
from authlib.integrations.flask_client import OAuth
import logging
from flask_session import Session
from werkzeug.utils import secure_filename
from it_quiz import it_quiz
from squiz import squiz
import os
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import time
import hashlib
import requests
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from sendgrid import SendGridAPIClient

app = Flask(__name__)


load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_BINDS'] = {'admins': os.getenv('SQLALCHEMY_BINDS_ADMIN')}
app.config['SECRET_KEY'] =os.getenv('SECRET_KEY')
app.config['UPLOADED_IMAGES_DEST'] = 'static/uploads'
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['WTF_CSRF_ENABLED'] = True


images = UploadSet('images', IMAGES)
configure_uploads(app, images)


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
oauth = OAuth(app)
csrf = CSRFProtect(app)
load_dotenv()


app.register_blueprint(it_quiz, url_prefix='/it-quiz')
app.register_blueprint(squiz, url_prefix='/squiz')

def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


def generate_csrf_token():
    """Generate a CSRF token using the session data."""
    csrf_token = hashlib.sha256(os.urandom(64)).hexdigest()  
    session['_csrf_token'] = csrf_token  
    return csrf_token

@app.route('/static/js/OneSignalSDKWorker.js')
def serve_worker():
    response = send_from_directory('static/js', 'OneSignalSDKWorker.js')
    response.headers['Service-Worker-Allowed'] = '/'  
    return response


google = oauth.register(
    name='google',
    
    
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)




linkedin = oauth.register(
    'linkedin',
    
    request_token_params={
        'scope': 'openid profile email',
    },
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth/authenticate'
)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    grade = db.Column(db.Integer, nullable=False)
    t_no = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False, unique=True)
    NIC = db.Column(db.String, nullable=True)
    pic = db.Column(db.String, nullable=True)
    status = db.Column(db.Integer, default=0, nullable=False)
    it_score = db.Column(db.Integer, default=0, nullable=True)
    science_score =db.Column(db.Integer, default=0, nullable=True)

    def __repr__(self):
        return f"<User {self.first_name} {self.last_name}>"


class Admin(db.Model, UserMixin):
    __bind_key__ = 'admins'
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}", "{self.id}")'


@app.route('/')
def main():
    return render_template('main.html')

def send_registration_email(user_email):
    message = Mail(
        from_email='nerosense124@gmail.com',  # Replace with your verified SendGrid sender email
        to_emails=user_email,
        subject='Welcome to Our Flask App!',
        plain_text_content=f"""
Hello and welcome to FutureLMS!

We are thrilled to have you join our community. Thank you for registering with us. 
You're now part of an exciting journey, and we can't wait to share all the amazing features we have in store.

Please feel free to explore, and don't hesitate to reach out if you have any questions. 
Our team is always here to help!

We recommend checking out the following:
- Explore the dashboard
- Check out your account settings
- Stay updated with our latest features and news

Once again, welcome aboard!

Best regards,
The FutureLMS Team
"""
    )

    sg = SendGridAPIClient(api_key=SENDGRID_API_KEY)
    response = sg.send(message)
    print(f"Registration email sent to {user_email}")



@app.route('/register', methods=['GET', 'POST'])
def reg():
    if request.method== 'GET':
        return render_template('register.html')
    if request.method == 'POST':
        first_name = request.form['f_name']
        last_name = request.form['l_name']
        grade = request.form['grade']
        t_no = request.form['t_no']
        email = request.form['email']
        password = request.form['password']
        c_password = request.form['password2']
        nic = request.form['NIC']
        
        hashed_password = bcrypt.generate_password_hash(password,rounds=12)

        if password != c_password:
            flash('Passwords do not match! Please try again.')
            return render_template('register.html')
        
        if  User.query.filter_by(email=email).first() :
            flash('email already exists')
            return render_template('register.html')
        
    user=User(
                password = hashed_password,
                email = email,
                NIC = nic,
                first_name = first_name,
                last_name = last_name,
                grade= grade,
                t_no = t_no
              )
    db.session.add(user)
    db.session.commit()
    send_registration_email(email)
    flash('registration successful.check your inbox for more details')
    return redirect(url_for('login'))
   
          
   


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ema = request.form['email']
        pas = request.form['password']

        if ema and pas:
            user = User.query.filter_by(email=ema).first()
            if user:
                if user.status == 1: 
                    if bcrypt.check_password_hash(user.password, pas):
                        login_user(user)
                        flash('Login successful')
                        return redirect(url_for('profile'))
                    else:
                        flash("Incorrect password")
                else:
                    flash("Account pending approval")
            else:
                flash("User does not exist")
        else:
            flash('Please fill in both fields')
    return render_template('login.html')





@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('main'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    return render_template('update.html')
@app.route('/backtoprofile', methods=['GET', 'POST'])

def backtoprofile():
    return redirect(url_for('profile'))

ALLOWED_EXTENSIONS ={'jpg', 'jpeg', 'png'}



@app.route('/updateprofile', methods=['POST', 'GET'])
@login_required
def updateprofile():
    if request.method == 'POST':
        
        pd = User.query.get(current_user.id)

        
        fn = request.form['first_name']
        ln = request.form['last_name']
        ga = request.form['grade']
        nic = request.form['nic']
        tn = request.form['t_no']
        em = request.form['email']
        pa = request.form['password']
        pic = request.files.get('reciept')

       
        if pa:
            hashed_password = bcrypt.generate_password_hash(pa).decode('utf-8')
            pd.password = hashed_password

        
        if pic and '.' in pic.filename:
            ext = pic.filename.rsplit('.', 1)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))
                pd.pic = filename
            else:
                flash('Only JPG, JPEG, and PNG files are allowed.')
                return redirect(url_for('update'))  # Return to update page if file is invalid

        
        pd.first_name = fn
        pd.last_name = ln
        pd.grade = ga
        pd.NIC = nic
        pd.t_no = tn
        pd.email = em

        try:
            db.session.commit()  
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))  
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            return render_template('update.html') 

   
    return render_template('update.html')  



@app.route('/adminlogin')
def adminlogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hpassword = bcrypt.check_password_hash()
        if bcrypt.check_password_hash(user.password, password):
            user = Admin.query.get(username=username).first()
            if user is not None:
                
                login_user(admin)
                return redirect('admin')
            else:
                flash('invalid admin username')
        else:
            flash('please fill in both field')
    return render_template('admin/adminlogin.html')


@app.route('/admin')
def admin():
    return render_template('admin/welcome.html')

@app.route('/logoutadmin')
def logoutadmin():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    total_user = User.query.count()
    total_approved = User.query.filter_by(status=1).count()
    total_pending = User.query.filter_by(status=0).count()
    return render_template('admin/admindashboard.html', title="Admin Dashboard", 
                           total_user=total_user, total_approved=total_approved, total_pending=total_pending)

@app.route('/admin/get-all-user', methods=["POST", "GET"])
def admin_get_all_user():
    search = request.form.get('search') if request.method == "POST" else None
    users = User.query.filter(User.first_name.like(f'%{search}%')).all() if search else User.query.all()
    return render_template('admin/all.html', title='Approve User', users=users)

@app.route('/admin/approve-user/<int:id>')
def admin_approve(id):
    user = User.query.get(id)
    if user:
        user.status = 1
        db.session.commit()
        flash('User approved successfully', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_get_all_user'))
#
@app.route('/login/google')
def login_google():
   
    nonce = generate_nonce()
    session['nonce'] = nonce 
    
    redirect_uri = url_for('auth', _external=True)
    
    
    return google.authorize_redirect(redirect_uri, nonce=nonce)
@app.route('/authorized/google')
def auth():
    try:
     
        nonce = session.get('nonce')
        
     
        token = google.authorize_access_token()
        

        user_info = google.parse_id_token(token, nonce=nonce)
        print(user_info)  
       
        user = User.query.filter_by(email=user_info['email']).first()
        if user :
            if user.status == 1:
                login_user(user)
                flash('successful')
                return redirect(url_for('profile'))
            else:
                flash('pending approval')
                return redirect(url_for('login'))
        else:
            return redirect(url_for('reg'))    
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('login'))
    




def create_db():
    with app.app_context():
        db.create_all()




if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)