from flask import request
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_restful import Resource
from models.model import HelpRequest
from models.model import db,User,Task
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import request, current_app
from datetime import timedelta,date
class RegisterAPI(Resource):
    def post(self):
        data = request.get_json()

        # Validate input
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        phone = data.get('phone')
        address = data.get('address')
        gender = data.get('gender')
        role = 'user'
        if not username or not email or not password or not address or not gender:
            return {"message": "Username, email, phone , adress, gender and password are required."}, 400

        # Check if the email or username already exists
        if User.query.filter_by(email=email).first():
            return {"message": "Email already registered."}, 400
        if User.query.filter_by(username=username).first():
            return {"message": "Username already taken."}, 400

        # Create a new user instance
        new_user = User(
            username=username,
            email=email,
            phone=phone,
            gender=gender,
            address=address,
            role = role
        )
        new_user.set_password(password)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Generate an access token for the new user (optional, if you want the user to be logged in immediately)
        access_token = create_access_token(identity=str(new_user.id))

        return {
            "message": "User registered successfully.",
            "access_token": access_token  # You can include the token if you want the user to be logged in automatically
        }, 201
        
        
class HelpRequestResource(Resource):
    def get(self):
        help_requests = HelpRequest.query.all()
        return [{
            'id': h.id,
            'email': h.email,
            'description': h.description
        } for h in help_requests], 200

    def post(self):
        data = request.get_json()

        email = data.get('email')
        description = data.get('description')

        if not email or not description:
            return {'message': 'Email and description are required'}, 400

        new_entry = HelpRequest(email=email, description=description)
        db.session.add(new_entry)
        db.session.commit()

        return {'message': 'Contact saved successfully'}, 201
from flask import request
from flask_jwt_extended import create_access_token
from flask_restful import Resource
from werkzeug.security import check_password_hash  # For password hash checking

class UserLoginResource(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')  # <-- Accept role from client

        if not email or not password or not role:
            return {'message': 'Email, password, and role are required'}, 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return {'message': 'User not found'}, 404

        if not user.check_password(password):
            return {'message': 'Invalid password'}, 401

        if user.role != role:
            return {'message': 'Role mismatch. Access denied.'}, 403

        access_token = create_access_token(identity=str(user.id))
        return {'access_token': access_token, 'role': user.role, 'username':user.username, 'email':user.email, 'tasks':[task.as_dict() for task in Task.query.all()]}, 200


class TaskResource(Resource):
    @jwt_required()
    def get(self, task_id):
        task = Task.query.get(task_id)
        if task:
            return task.as_dict(), 200
        return {'message': 'Task not found'}, 404
    
    @jwt_required()
    def put(self, task_id):
        task = Task.query.get(task_id)
        if not task:
            return {'message': 'Task not found'}, 404

        data = request.get_json()
        task.task_title = data.get('task_title', task.task_title)
        task.task_description = data.get('task_description', task.task_description)
        task.task_priority = data.get('task_priority', task.task_priority)
        # Handle end_date conversion
        end_date_str = data.get('end_date')
        task.progress = data.get('progress')
        if end_date_str:
            try:
                task.end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
            except ValueError:
                return {"message": "Invalid date format. Use YYYY-MM-DD."}, 400

        db.session.commit()
        return {'message': 'Task updated successfully', 'task': task.as_dict()}, 200
    
    
    @jwt_required()
    def delete(self, task_id):
            task = Task.query.get(task_id)
            if task:
                db.session.delete(task)
                db.session.commit()
                return {'message': 'Task deleted successfully'}, 200
            return {'message': 'Task not found'}, 404


class TasksResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        try:
            if user.role == 'admin':
                # Tasks specifically assigned to the admin
                tasks = Task.query.filter_by(user_id=user.id).all()
                all_user_tasks = []
                for task in tasks:
                    task_dict = task.as_dict()
                    task_user = User.query.get(task.user_id)
                    task_dict['user_email'] = task_user.email if task_user else None
                    all_user_tasks.append(task_dict)

                # All tasks in the system (including admin and all users)
                all_tasks_raw = Task.query.all()
                admin_tasks = []
                for task in all_tasks_raw:
                    task_dict = task.as_dict()
                    task_user = User.query.get(task.user_id)
                    task_dict['user_email'] = task_user.email if task_user else None
                    admin_tasks.append(task_dict)

                return {
                    'admin_tasks': admin_tasks,
                    'tasks': all_user_tasks
                }, 200

            else:
                # Regular user: only fetch their own tasks
                user_tasks_raw = Task.query.filter_by(user_id=user_id).all()
                user_tasks = []
                for task in user_tasks_raw:
                    task_dict = task.as_dict()
                    task_user = User.query.get(task.user_id)
                    task_dict['user_email'] = task_user.email if task_user else None
                    user_tasks.append(task_dict)

                return {'tasks': user_tasks}, 200

        except Exception as e:
            print(f"Error: {e}")
            return {'message': 'An error occurred while retrieving tasks'}, 500

    @jwt_required()
    def post(self):
        data = request.get_json()

        # Extract task details from request data
        task_title = data.get('task_title')
        task_description = data.get('task_description')
        task_priority = data.get('task_priority', 'Medium')
        end_date_str = data.get('end_date')

        # Ensure task title and description are provided
        if not task_title or not task_description:
            return {"message": "Task title and description are required."}, 400

        # Convert string dates to datetime objects
        try:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date() if end_date_str else datetime.utcnow().date()
        except ValueError:
            return {"message": "Invalid date format. Please use 'YYYY-MM-DD' format."}, 400
        user_id = get_jwt_identity()
        max_user_task_id = db.session.query(db.func.max(Task.user_task_id)).filter_by(user_id=user_id).scalar()
        next_user_task_id = (max_user_task_id or 0) + 1
        # Create new task instance
        new_task = Task(
            task_title=task_title,
            task_description=task_description,
            task_priority=task_priority,
            end_date=end_date,
            user_id=user_id,
            user_task_id=next_user_task_id  # ⬅️ new line

        )

        # Add task to the database
        db.session.add(new_task)
        db.session.commit()

        return {"message": "Task created successfully.", "task": new_task.as_dict()}, 201

class UserProfileResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()  # Directly use the user ID
        user = User.query.get(user_id)

        if user:
            tasks = Task.query.filter_by(user_id=user.id).all()

            total_completed = 0
            tasks_in_progress = 0
            weekly_productivity = 0
            one_week_ago = datetime.now().date() - timedelta(days=7)

            for task in tasks:
                if task.progress == 100:
                    total_completed += 1
                    if task.end_date and task.end_date >= one_week_ago:
                        weekly_productivity += 1

                if 0 < task.progress < 100:
                    tasks_in_progress += 1

            return {
                "full_name": user.username,
                "phone": user.phone,
                "role": user.role,
                "gender": user.gender,
                "email": user.email,
                "address": user.address,
                "joined_date": str(date.today()),  # 👈 Add present day as string
                "total_completed_tasks": total_completed,
                "tasks_in_progress": tasks_in_progress,
                "weekly_productivity": weekly_productivity
            }

        return {"message": "User not found"}, 404