from flask_login import UserMixin
from datetime import datetime
from . import db
from flask_bcrypt import check_password_hash, generate_password_hash
from datetime import date, timedelta


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    gender = db.Column(db.String(20),nullable=False)
    address = db.Column(db.Text(100),nullable = False)
    role = db.Column(db.String(50), nullable=True)
    tasks = db.relationship('Task', backref='user', lazy=True)
    def set_password(self, password):
        """Sets the user's password hash."""
        self.password = generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return check_password_hash(self.password, password)
    def tasks_in_progress(self):
        # Count the number of tasks that are in progress (between 1-99% progress)
        return len([task for task in self.tasks if 1 <= task.progress < 100])

    def weekly_productivity(self):
        # Calculate the number of tasks completed in the past week
        one_week_ago = date.today() - timedelta(days=7)
        completed_tasks_in_week = [task for task in self.tasks if task.progress == 100 and task.end_date >= one_week_ago]
        return len(completed_tasks_in_week)

    def as_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "phone": self.phone,
            "role": self.role,
            "tasks": [task.as_dict() for task in self.tasks],
            "total_completed_tasks": self.total_completed_tasks(),
            "tasks_in_progress": self.tasks_in_progress(),
            "weekly_productivity": self.weekly_productivity()
        }
    
class HelpRequest(db.Model):
    __tablename__="help_requests"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    def __repr__(self):
        return f"<HelpRequest {self.email}>"

class Task(db.Model):
    task_id = db.Column(db.Integer, primary_key=True)
    user_task_id = db.Column(db.Integer)
    task_title = db.Column(db.String(255), nullable=False)
    task_description = db.Column(db.Text(500), nullable=False)
    task_priority = db.Column(db.String(50), nullable=True, default="Medium")
    start_date = db.Column(db.Date, nullable=True, default=datetime.utcnow)  # Changed to DateTime
    end_date = db.Column(db.Date, nullable=False)  # Changed to DateTime
    progress = db.Column(db.Integer, default=0)  # e.g., 0 to 100
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Added user_id for foreign key

    def __repr__(self):
        return f"<Task(task_id={self.task_id}, task_title={self.task_title}, task_priority={self.task_priority})>"
    def as_dict(self):
        return {
            "task_id": self.task_id,
            'user_task_id': self.user_task_id,
            "task_title": self.task_title,
            "task_description": self.task_description,
            "task_priority": self.task_priority,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "progress": self.progress,
            "user_id": self.user_id
        }
