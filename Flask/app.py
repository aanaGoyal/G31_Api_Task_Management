from flask import Flask,session, render_template, request, redirect, url_for, flash,jsonify
from functools import wraps
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import os
import json
from flask_restful import Api
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager,jwt_required,get_jwt_identity
from datetime import datetime
from models.model import User,Task
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import re
from resources.api_resource import HelpRequestResource,TaskResource,TasksResource,UserLoginResource,RegisterAPI,UserProfileResource
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_bcrypt import check_password_hash, generate_password_hash
from datetime import date
from datetime import timedelta

app = Flask(__name__)
api = Api(app)
jwt = JWTManager(app)
CORS(app)
# Initialize Flask App
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "your_secret_key")  # Use env variable for production

# Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "database.db").replace("\\", "/")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)  # Example: Token expires in 24 hours

# Email Configuration (Use Environment Variables)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")  # Use environment variable
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")  # Use environment variable
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Initialize Extensions
# db = SQLAlchemy(app)
from models import db 
db.init_app(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "loginPage"
login_manager.init_app(app)
# Serializer for Token Generation
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
# ADMIN_EMAIL = "admin@gmail.com"
# ADMIN_PASSWORD = "SuperSecure123"
# User Model
# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(150), nullable=False)
#     email = db.Column(db.String(150), unique=True, nullable=False)
#     password = db.Column(db.String(150), nullable=False)
#     phone = db.Column(db.String(20), nullable=True)
#     role = db.Column(db.String(50), nullable=True)

#     def set_password(self, password):
#         self.password = bcrypt.generate_password_hash(password).decode("utf-8")

#     def check_password(self, password):
#         return bcrypt.check_password_hash(self.password, password)

# class Task(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     task= db.Column(db.String(255), nullable=False)
#     description = db.Column(db.Text(500), nullable=False)
#     priority = db.Column(db.String(50), nullable=True)  # Add priority
#     # date = db.Column(db.String(50), nullable=False)  # Store date as a string for simplicity
#     # user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     # user = db.relationship('User', backref=db.backref('tasks', lazy=True))
#     def _repr_(self):
#         return f"TaskId: {self.id} Task : {self.task} Description:  {self.description} Priority: {self.priority} "

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File is too large. Please upload a smaller file.", "error")
    return redirect(request.url)

with app.app_context():
    db.create_all()  
    
with app.app_context():
    admin_email = 'admin@gmail.com'
    existing_admin = User.query.filter_by(email=admin_email, role='admin').first()

    # Check if the admin exists
    if existing_admin:
        print(existing_admin.username)  # Make sure the username is correct
        print("⚠️ Admin already exists.")
    else:
        # Create the admin user and hash the password
        admin_user = User(
            username='Admin',
            email=admin_email,
            phone='0000000000',
            address='Admin Office',
            role='admin',
            gender='Other'
        )
        admin_user.set_password("Admin@123")  # Set the hashed password
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created.")

@app.route("/addTask", methods=["POST"])
@login_required
def addTask():
    if request.method=="POST":
        task_title = request.form.get("task_title")
        task_description = request.form.get("task_description")
        task_priority = request.form.get("task_priority")
        start_date = request.form.get("start_date")
        end_date=request.form.get("end_date")
        progress = request.form.get("progress")
        task_details = Task(task_title=task_title, task_description=task_description, task_priority=task_priority,start_date=start_date,end_date=end_date,progress=progress)
        db.session.add(task_details)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template("addTask.html")

@app.route("/editProgress/<int:task_id>", methods=["GET", "POST"])
def edit_progress(task_id):
    task = Task.query.get_or_404(task_id)
    if request.method == "POST":
        task.progress = request.form.get("progress")
        try:
            db.session.commit()
            flash(f"Task titled {task.task_title} progress updated successfully!", "success")
            return redirect(url_for("dashboard"))  
        except:
            db.session.rollback()
            flash("There was an issue updating the task progress.", "danger")
            return redirect(url_for("dashboard"))
    return render_template("edit_progress.html", task=task)





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Email Validation
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Password Validation
def is_valid_password(password):
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[@$!%*?&]', password))

def is_valid_phone(phone):
    return re.fullmatch(r'\d{10}', phone) is not None

with app.app_context():
    db.create_all()

    # if not User.query.filter_by(role="admin").first():
    #     admin_user = User(username="Admin", email="admin@gmail.com", phone="1234567890")
    #     admin_user.set_password("Admin123!")  # Set a default password
    #     db.session.add(admin_user)
    #     db.session.commit()
    #     print("Admin user created with email: admin@gmail.com and password: admin123")

@app.route('/calender')
@login_required
def calender():
    tasks = Task.query.all()
    is_admin = current_user.role == 'admin'
    task_end_dates = [{'date': task.end_date, 'title': task.task_title} for task in tasks]
    return render_template('calender.html', task_end_dates=task_end_dates,is_admin=is_admin)

@app.route('/completed_tasks')
@login_required
def completed_tasks():
    tasks = Task.query.filter_by(progress='100').all()
    is_admin = current_user.role == 'admin'

    task_data = [{"priority": task.task_priority} for task in tasks]

    return render_template("completed_tasks.html", tasks=tasks, task_data=json.dumps(task_data),is_admin=is_admin)



# Sign-Up Route
@app.route('/signUp', methods=["GET", "POST"])
def signUp():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email").strip().lower()
        phone = request.form.get("phone")
        address = request.form.get('address')
        gender = request.form.get('gender')
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        role = 'user'
        if not username or not email or not password or not confirm_password or not address or not gender:
            flash("All fields are required!", "danger")
            return redirect(url_for("signUp"))

        if not is_valid_email(email):
            flash("Invalid email format!", "danger")
            return redirect(url_for("signUp"))

        if not is_valid_phone(phone):
            flash("Phone number must be exactly 10 digits!", "danger")
            return redirect(url_for("signUp"))

        if not is_valid_password(password):
            flash("Password must contain at least 8 characters, uppercase, lowercase, numbers, and special characters!", "danger")
            return redirect(url_for("signUp"))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signUp"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for("signUp"))

        new_user = User(username=username, email=email, phone=phone, address=address, gender=gender, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("loginPage"))

    return render_template("sign_up_page.html")


@app.route('/login_page', methods=["GET", "POST"])
def loginPage():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role=request.form.get("role")
        user = User.query.filter_by(email=email, role=role).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("login_page.html")

    #     user = User.query.filter_by(email=email).first()

    #     if not user:
    #         flash("User not found", "danger")
    #         return redirect(url_for("loginPage"))

    #     # Secure Admin Check (only one allowed)
    #     if user.role == 'admin':
    #         if user.email != 'admin@gmail.com' or not user.check_password('Admin@123'):
    #             flash("Access Denied: Invalid admin credentials!", "danger")
    #             return redirect(url_for("loginPage"))

    #     # Password Check
    #     if user.check_password(password):
    #         login_user(user)
    #         flash(f"{user.role.capitalize()} login successful!", "success")
    #         return redirect(url_for("dashboard"))
    #     else:
    #         flash("Invalid password", "danger")
    #         return redirect(url_for("loginPage"))

    # return render_template("login_page.html")


# Forgot Password Route
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()

        if not email or not is_valid_email(email):
            flash("Invalid email format!", "danger")
            return redirect(url_for("forgot_password"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return redirect(url_for("forgot_password"))

        try:
            # Generate Reset Token
            token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)

            # Send Email
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}\n\nIf you did not request this, ignore this email."
            mail.send(msg)

            flash("Password reset instructions sent to your email!", "success")
        except Exception as e:
            flash("Error sending email. Please try again later.", "danger")
            print(f"Email sending error: {e}")

        return redirect(url_for("loginPage"))

    return render_template("forgot_password.html")

# Reset Password Route
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash("Invalid or expired token", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("reset_password", token=token))

        if not is_valid_password(new_password):
            flash("Password must be strong!", "danger")
            return redirect(url_for("reset_password", token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(new_password)
            db.session.commit()
            flash("Your password has been reset! You can now log in.", "success")
            return redirect(url_for("loginPage"))

    return render_template("reset_password.html")


def admin_required(func):
    @wraps(func)
    # Represents arguments and functions.
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            flash("Access denied!", "danger")
            return redirect(url_for('dashboard'))
        # Executes original function 
        return func(*args, **kwargs)
    return wrapper


@app.route("/admin")
@login_required
# It should after the route 
@admin_required
def admin():
    return "<h1>Welcome Admin </h1>"

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    title_query = request.args.get('title', '').strip()
    priority_filter = request.args.get('priority', '').strip()
    
    # Start with the base query to filter tasks based on progress
    query = Task.query.filter(Task.progress != 100, Task.user_id == current_user.id)

    if title_query:
        query = query.filter(Task.task_title.ilike(f"%{title_query}%"))
    if priority_filter:
        query = query.filter(Task.task_priority == priority_filter)

    # Execute the query to fetch tasks with the filters
    tasks = query.all()
    print(tasks)
    # Get all possible priorities for the dropdown
    all_priorities = ['Low', 'Medium', 'High', 'Urgent']  # for the select dropdown

    # Check if the current user is an admin
    is_admin = current_user.role == 'admin'

    # Render the dashboard template with the tasks and other context
    return render_template("dashboard.html", tasks=tasks, all_priorities=all_priorities, is_admin=is_admin)


@app.route("/allTasks",methods=["GET","POST"])
@login_required
def all_tasks():
    tasks = Task.query.all()
    print(tasks)
    title_query = request.args.get('title', '').strip()
    priority_filter = request.args.get('priority', '').strip()
    query = Task.query.filter(Task.progress != 100)
    is_admin = current_user.role == 'admin'
    if title_query:
        query = query.filter(Task.task_title.ilike(f"%{title_query}%"))
    if priority_filter:
        query = query.filter(Task.task_priority == priority_filter)
    all_priorities = ['Low', 'Medium', 'High', 'Urgent']  # for the select dropdown
    return render_template("allTask.html",tasks=tasks,all_priorities=all_priorities,is_admin=is_admin)

@app.route('/all_users')
@login_required
@admin_required
def all_users():
    is_admin = current_user.role == 'admin'
    users = User.query.all()
    return render_template('all_users.html', users=users,is_admin=is_admin)

@app.route("/delete/<int:task_id>")
@login_required
def delete_task(task_id):
    task_to_delete = db.session.get(Task,task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/update_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update_task(task_id):
    # Fetch the task by id
    task = Task.query.get_or_404(task_id)
    is_admin = current_user.role == 'admin'

    # Handle form submission (POST request)
    if request.method == 'POST':
        task.task_title = request.form['title']
        task.task_description = request.form['description']
        end_date_str = request.form['end_date']
        task.end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        task.task_priority = request.form['priority']
        
        # Commit changes to the database
        db.session.commit()
        flash("Task updated successfully.", 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_task.html', task=task,is_admin=is_admin)

@app.route('/edit_user', methods=['GET', 'POST'])
@login_required
def edit_user():
    is_admin = current_user.role == 'admin'

    if request.method == 'POST':
        # Get form data
        new_name = request.form.get('username')
        new_email = request.form.get('email')

        # Update the user's information in the database
        current_user.name = new_name
        current_user.email = new_email
        db.session.commit() 
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to prevent resubmission on refresh

    return render_template("edit_user.html", user=current_user, is_admin=is_admin)
@app.route('/profile')
@login_required
def profile():
    # Fetching profile data
    user = current_user  # Assuming you're using Flask-Login for the current logged-in user
    is_admin = current_user.role == 'admin'
    # Fetching tasks as per the status or time range
    completed_tasks = Task.query.filter_by(progress=100, user_id=current_user.id).all()
    in_progress_tasks = Task.query.filter_by(progress=0, user_id=current_user.id).all()

    # Optionally, if you want weekly tasks
    from datetime import datetime, timedelta
    one_week_ago = datetime.now() - timedelta(weeks=1)
    weekly_tasks = Task.query.filter(Task.start_date >= one_week_ago).all()
    tasks = Task.query.filter_by(user_id=user.id).all()
    
    # You can calculate weekly productivity (just an example)
    weekly_productivity = len(weekly_tasks) / len(completed_tasks) * 100 if len(completed_tasks) > 0 else 0

    return render_template("profile.html", 
                           user=user, 
                           completed_tasks_count=len(completed_tasks), 
                           in_progress_count=len(in_progress_tasks), 
                           weekly_productivity=weekly_productivity,
                           weekly_tasks=weekly_tasks,
                           is_admin=is_admin,tasks=tasks)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("loginPage"))

@app.route("/home")
def home():
    return render_template("home.html")



@app.route("/")
def hello_world():
    return render_template("index.html")


@app.route('/main')
def index():
    # tasks = Task.query.all()
    # return render_template('index.html', tasks=tasks)
    sections = [
        {"route":"get_started" ,"title": "Get Started", "description": "Learn how to set up our platform."},
        {"route": "features", "title": "Features", "description": "Explore all the features we offer."},
        {"route": "teams", "title": "Teams", "description": "Manage your team and collaborate efficiently."},
        {"route": "billing", "title": "Billing", "description": "Billing info, subscriptions, and payments."},
        {"route": "troubleshooting", "title": "Troubleshooting", "description": "Solutions to common issues."},
        {"route": "integrations", "title": "Integrations", "description": "Integrate with other tools seamlessly."}
    ]

    inspirations = [
        {"title": "Stay Focused", "description": "Tips to improve concentration.", "message": "Focus on one task at a time!"},
        {"title": "Boost Productivity", "description": "Small changes, big impact.", "message": "Take short breaks to stay fresh."},
        {"title": "Work Smarter", "description": "Time management hacks.", "message": "Prioritize tasks using the Eisenhower Matrix."},
    ]
    return render_template('index2.html', sections=sections,inspirations=inspirations )

    

@app.route('/get_started')
def get_started():
    return render_template('get_started.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/teams')
def teams():
    return render_template('teams.html')

@app.route('/billing')
def billing():
    return render_template("billing.html")

@app.route('/troubleshooting')
def troubleshooting():
    return render_template('troubleshooting.html')

@app.route('/integrations')
def integrations():
    return render_template('integrations.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/continue_without_login')
def continue_without_login():
    return render_template('continue_without_login.html')

@app.route('/help')
def help():
    return render_template('help.html')


@app.route("/feedback")
def feedback():
    return render_template("feedback.html")


@app.route('/inspiration_hub',methods=['GET','POST'])
def inspiration_hub():
    
    articles = [
        {"image": "article1.jpg", "title": "How to Organize Home", 
         "preview": "Simple hacks for a clutter-free space.", 
         "details_title": "Home Organization Tips", 
         "details": "Discover smart ways to keep your home organized effortlessly."},

        {"image": "article2.jpg", "title": "Why Teaching is the Key to Understanding", 
         "preview": "Learn more by teaching others.", 
         "details_title": "The Power of Teaching", 
         "details": "Teaching solidifies your understanding through active learning."},

        {"image": "article3.jpg", "title": "Working Long Hours is Bad for Health", 
         "preview": "The hidden risks of overworking.", 
         "details_title": "Health Risks of Overworking", 
         "details": "Discover why balance is key to productivity and well-being."},

        {"image": "article4.jpg", "title": "How to Keep Healthy", 
         "preview": "Daily habits for a healthier life.", 
         "details_title": "Healthy Living Tips", 
         "details": "Learn simple ways to maintain your health every day."},

        {"image": "article5.jpg", "title": "How Your Time Zone Affects Productivity", 
         "preview": "Does your time zone impact your work?", 
         "details_title": "Productivity & Time Zones", 
         "details": "Find out how time zones influence focus and efficiency."},

        {"image": "article6.jpg", "title": "How to Make Virtual Networking Less Cringe", 
         "preview": "Master the art of online connections.", 
         "details_title": "Virtual Networking Tips", 
         "details": "Learn how to network effectively without feeling awkward."},

        {"image": "article7.jpg", "title": "How to Agree with Your Coworkers Productively", 
         "preview": "Effective ways to handle disagreements.", 
         "details_title": "Productive Team Agreements", 
         "details": "Discover strategies for constructive workplace collaboration."},

        {"image": "article8.jpg", "title": "Don’t Worry, No One’s Taking Your Coffee Away", 
         "preview": "Debunking workplace myths.", 
         "details_title": "The Coffee Myth", 
         "details": "Relax—your productivity isn’t just about caffeine!"}
    ]
    return render_template('inspiration_hub.html', articles=articles )

@app.route('/index3')
def index2():
    return render_template('index3.html')

@app.route('/templates')
def templates():
    return render_template('templates.html')

@app.route('/suggest')
def suggest():
    return render_template('suggest.html')

@app.route('/about')
def about():
    return render_template("about_us.html")

api.add_resource(RegisterAPI, '/registerapi')
api.add_resource(TasksResource, "/api/tasks")
api.add_resource(TaskResource, "/api/tasks/<int:task_id>")
api.add_resource(UserLoginResource, "/loginapi")
api.add_resource(HelpRequestResource, '/api/help')
api.add_resource(UserProfileResource, '/api/profile')


if __name__=="__main__":
    app.run(debug=True, port=5000)