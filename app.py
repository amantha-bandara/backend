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


import os
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import time
import hashlib
import requests
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from flask_migrate import Migrate


app = Flask(__name__)

 


load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_BINDS'] = {
    'admins': os.getenv('SQLALCHEMY_BINDS_ADMIN'),
    'teachers' :'sqlite:///teachers.db',
    'it_quiz' : 'sqlite:///it_quiz.db',
    'squiz' : 'sqlite:///squiz.db'
                        
}
app.config['SECRET_KEY'] =os.getenv('SECRET_KEY')
app.config['UPLOADED_IMAGES_DEST'] = 'static/uploads'
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['WTF_CSRF_ENABLED'] = True
SENDGRID_API_KEY =''
 
images = UploadSet('images', IMAGES)
configure_uploads(app, images)


# Initialize extensions

bcrypt = Bcrypt(app)
oauth = OAuth(app)
csrf = CSRFProtect(app)
load_dotenv()
db = SQLAlchemy(app)



def generate_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


def generate_csrf_token():
    """Generate a CSRF token using the session data."""
    csrf_token = hashlib.sha256(os.urandom(64)).hexdigest()  # Random token based on os.urandom
    session['_csrf_token'] = csrf_token  # Store token in session
    return csrf_token

@app.route('/static/js/OneSignalSDKWorker.js')
def serve_worker():
    response = send_from_directory('static/js', 'OneSignalSDKWorker.js')
    response.headers['Service-Worker-Allowed'] = '/'  # Ensure service worker can control the whole domain
    return response


google = oauth.register(
    name='google',
    
    
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)



# LinkedIn OAuth client setup
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

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    grade = db.Column(db.Integer, nullable=False)
    t_no = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=True, unique=True)
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



# Teacher Model
class Teacher(db.Model):
    __bind_key__ = 'teachers'

    __tablename__ = 'teachers'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    common_name = db.Column(db.String(100), nullable=True)
    grade = db.Column(db.String(50), nullable=True)
    status = db.Column(db.Integer, default=1)  # 1 = active, 0 = inactive
    pic = db.Column(db.String(200), nullable=True)  # Path to the profile picture
    NIC = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    fees = db.Column(db.String(100),nullable = False)


  

    def __repr__(self):
        return f'<Teacher {self.full_name}>'

# IT Quiz Model
class ItQuiz(db.Model):
    __tablename__ = 'it_quiz'
    __bind_key__ = 'it_quiz'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)
   




    

# Squiz Model
class Squiz(db.Model):
    __tablename__ = 'squiz'
    __bind_key__ = 'squiz'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)
    

    # Relationship with Teacher table to easily access the teacher object
    
   

 

    def __repr__(self):
        return f'<Squiz {self.question}>'








@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User model


# Routes
@app.route('/')
def main():
    return render_template('main.html')

def send_registration_email(user_email):
    message = Mail(
        from_email='nerosense124@gmail.com',  # Replace with your verified SendGrid sender email
        to_emails=user_email,
        subject='Welcome to Our Flask App',
        plain_text_content='Thank you for registering with our Flask app! We are excited to have you on board.'
    )

    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Registration email sent to {user_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Registration route
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
    return redirect(url_for('login'))
        

          
   

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ema = request.form['email']
        pas = request.form['password']

        if ema and pas:
            user = User.query.filter_by(email=ema).first()
            if user:
                if user.status == 1:  # Approved users only
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




# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('main'))

# Profile route
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Update route
@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    return render_template('update.html')
@app.route('/backtoprofile', methods=['GET', 'POST'])

def backtoprofile():
    return redirect(url_for('profile'))

ALLOWED_EXTENSIONS ={'jpg', 'jpeg', 'png'}

def get():
    return db,User

@app.route('/updateprofile', methods=['POST', 'GET'])
@login_required
def updateprofile():
    if request.method == 'POST':
        # Get the current user record
        pd = User.query.get(current_user.id)

        # Get form data
        fn = request.form['first_name']
        ln = request.form['last_name']
        ga = request.form['grade']
        nic = request.form['nic']
        tn = request.form['t_no']
        em = request.form['email']
        pa = request.form['password']
        pic = request.files.get('reciept')

        # Handle password update
        if pa:
            hashed_password = bcrypt.generate_password_hash(pa).decode('utf-8')
            pd.password = hashed_password

        # Handle picture upload
        if pic and '.' in pic.filename:
            ext = pic.filename.rsplit('.', 1)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename))
                pd.pic = filename
            else:
                flash('Only JPG, JPEG, and PNG files are allowed.')
                return redirect(url_for('update'))  # Return to update page if file is invalid

        # Update user information
        pd.first_name = fn
        pd.last_name = ln
        pd.grade = ga
        pd.NIC = nic
        pd.t_no = tn
        pd.email = em

        try:
            db.session.commit()  # Commit the changes to the database
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))  # Redirect to profile page after update
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            return render_template('update.html')  # Stay on the update page if there's an error

    # If GET request, just show the update form
    return render_template('update.html')  # Render update form for the user



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

# Admin section
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
    # Generate and store the nonce in the session
    nonce = generate_nonce()
    session['nonce'] = nonce  # Store the nonce in the session
    
    redirect_uri = url_for('auth', _external=True)
    
    # Pass the nonce in the authorization request
    return google.authorize_redirect(redirect_uri, nonce=nonce)
@app.route('/authorized/google')
def auth():
    try:
        # Retrieve the nonce from the session
        nonce = session.get('nonce')
        
        # Get the Google account info
        token = google.authorize_access_token()
        
        # Parse and validate the ID token using the nonce
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
    
from sqlalchemy import text

def create_db_without_foreign_keys():
    with app.app_context():
        db.create_all()
        

# Run the database creation
create_db_without_foreign_keys()











@app.route('/quiz')
def quizmain():
    return render_template('quiz/quizmain.html')
@app.route('/it quiz')
def it():
    itquiz = ItQuiz.query.all()
    return render_template('quiz/itquiz.html',itquiz=itquiz)

@app.route('/it_quiz/score', methods=['GET', 'POST'])
def itscore():
    if request.method == 'POST':
        print("Form submitted via POST!")
        score = 0
        it = ItQuiz.query.all()
        for index,question in enumerate(it,start = 1):
            answer = request.form.get(f'question{index}')
            if answer == question.correct_answer:
                score += 1
       
        user = User.query.filter_by(id = current_user.id).first()
        if user:
            user.it_score = score
            db.session.commit()

        print(f"Final score: {score}")
        return f'Your score is {score} out of 25.'
    else:
        print("Accessing form via GET request")
        return render_template('quiz/itquiz.html')  
    
    
@app.route('/it_quiz/back',methods = ['GET'])
def itback():
    return redirect(url_for('quizmain'))






@app.route('/squiz/main')
def sciequiz():
    squiz = Squiz.query.all()
    return render_template('squiz/squiz.html',squiz=squiz)

@app.route('/squiz/score', methods=['GET', 'POST'])
def scienscore():
    if request.method == 'POST':
        
        score = 0
        sa = Squiz.query.all()
        for index,question in enumerate(sa,start = 1):
            answer = request.form.get(f'question{index}')
            if answer == question.correct_answer:
                score += 1
       
        user = User.query.filter_by(id = current_user.id).first()
        if user:
            user.science_score = score
            db.session.commit()



        print(f"Final score: {score}")
        return f'Your score is {score} out of 25.'
    else:
        print("Accessing form via GET request")
        return render_template('squiz/squiz.html')  
# Run the database creation

@app.route('/added',methods =['GET','POST'])
@csrf.exempt
def add_teachers():
    if request.method == 'GET':
       return render_template('teachers/register.html')
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        grade = request.form['grade']
        t_no = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        fees = request.form['fees']
        nic = request.form['NIC']
        common = request.form['common_name']
        f_name = f'{first_name}{last_name}'
        
        
        hashed_password = bcrypt.generate_password_hash(password,rounds=12)
        
        teacher = Teacher.query.filter_by(email=email).first()
        if teacher is None:
            teacher = Teacher(
                first_name =first_name,
                last_name=last_name,
                grade=grade,
                NIC= nic,
                full_name = f_name,
                common_name = common,
                email = email,
                password = hashed_password,
                phone = t_no,
                fees = fees
                )
            db.session.add(teacher)
            db.session.commit()
            send_registration_email(email)
            flash('teacher registration successful')
            return redirect(url_for('add_teachers'))
        else:
            flash('email already taken')
            return redirect(url_for('add_teachers'))

@app.route('/addquiz' ,methods = ['GET','POST'])
@csrf.exempt
def addquiz():
    if request.method =='GET':
        return render_template('admin/addquiz.html')
    if request.method == 'POST':
        ques = request.form['question']
        op1 = request.form['option1']
        op2 = request.form['option2']
        op3 = request.form['option3']
        ca = request.form['correct_answer']

        itquiz= ItQuiz.query.filter_by(question = ques).first()
        if itquiz is None:
            itquiz = ItQuiz(question=ques,option1 =op1,option2=op2,option3 = op3,correct_answer = ca)
            db.session.add(itquiz)
            db.session.commit()
            return redirect(url_for('addquiz'))
        else:
            return 'hello'
        



   # For Squiz database
migrate = Migrate(app,db) # Print all IT quiz questions created by this teacher

        


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)