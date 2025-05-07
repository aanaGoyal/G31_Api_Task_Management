from django.shortcuts import render,redirect
# from .models import Task
from main.models import AppUser
from flask_jwt_extended import jwt_required, get_jwt_identity
from django.contrib import messages
import calendar
import requests
from .models import Task
from datetime import datetime
from calendar import HTMLCalendar
from django.utils.safestring import mark_safe
from django.shortcuts import get_object_or_404, redirect
import json
from django.http import HttpResponse
from django.core.serializers.json import DjangoJSONEncoder
from django.contrib.auth.decorators import login_required,user_passes_test
from django.http import HttpResponseForbidden
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.db import IntegrityError
# from .forms import UserEditForm
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
User=get_user_model()
from rewards.models import Reward
FLASK_API_BASE = 'http://localhost:5000'

# Helper function to get auth headers
def get_auth_headers(request):
    token = request.session.get('jwt_token')
    return {'Authorization': f'Bearer {token}'} if token else {}

User = get_user_model()


def calender_view(request):
    print("\n--- DEBUG: Entering calender_view ---")

    token = request.session.get('jwt_token')
    print(f"--- DEBUG: JWT Token: {token} ---")
    token = request.session.get('jwt_token')
    user_role = request.session.get('user_role')

    if not token or not user_role:
        return redirect('/login/')

    headers = {"Authorization": f"Bearer {token}"}

    try:
        # Single request to Flask API (includes both user data and tasks)
        response = requests.get(FLASK_API_URL, headers=headers)
        response.raise_for_status()

        data = response.json()
        tasks = data.get('tasks', [])
        username = data.get('username', 'Unknown User')
        role = data.get('role', 'user')

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        tasks = []
        username = 'Unknown User'
        role = 'user'

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"  # Important for sending JSON, even if not sending a body here.
    }

    try:
        print("\n--- DEBUG: Sending GET request to Flask API ---")
        print("URL: http://localhost:5000/api/tasks")
        print(f"Headers: {headers}")
        print(f"Params: {{'user_id': {request.user.id}, 'progress_lt': 100}}")

        response = requests.get(
            'http://localhost:5000/api/tasks',
            params={'user_id': request.user.id, 'progress_lt': 100},  # Corrected parameter name
            headers=headers
        )

        print("\n--- DEBUG: Flask API Response ---")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)

        if response.status_code == 200:
            tasks = response.json().get('tasks', [])  # Access 'tasks' key safely
        else:
            print(f"--- DEBUG: Flask API returned an error: {response.status_code} ---")
            tasks = []  # Ensure tasks is always initialized
            # Consider logging the error message from the Flask API:
            # error_message = response.json().get('msg', f"Failed to fetch tasks: {response.status_code}")
            # messages.error(request, error_message) #  Use messages framework if appropriate in your project.

        tasks_json = json.dumps(
            [
                {
                    'date': task.get('end_date'),  # Use .get() to avoid KeyError
                    'title': task.get('task_title')
                } for task in tasks if task.get('end_date')
            ],
            cls=DjangoJSONEncoder
        )
        print("--- DEBUG: tasks_json: ", tasks_json)

    except requests.exceptions.RequestException as e:
        print("\n--- DEBUG: Exception Occurred during GET request ---")
        traceback.print_exc()
        tasks = []
        tasks_json = '[]'
        # messages.error(request, f'Error contacting Flask API: {str(e)}') #  Use messages framework if appropriate.

    context = {
        'tasks': tasks,
        'tasks_json': tasks_json,
        'role':role
    }

    print("--- DEBUG: Rendering calender.html ---")
    return render(request, 'calender.html', context)


def is_admin(user):
    return user.is_superuser or user.is_staff

@login_required
@user_passes_test(is_admin)
@login_required
@user_passes_test(is_admin)
def delete_task_view_new(request, id):
    try:
        delete_url = f'http://127.0.0.1:5000/api/tasks/{id}'
        response = requests.delete(delete_url)
        if response.status_code == 200:
            messages.success(request, "Task deleted successfully.")
        else:
            messages.error(request, "Failed to delete the task.")
    except requests.exceptions.RequestException:
        messages.error(request, "Error communicating with the API.")

    return redirect('admin_tasks')

 
TASKS_API_URL = "http://127.0.0.1:5000/api/tasks"

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import requests

# @login_required(login_url='/login/')  # ensures Google-auth users get redirected to login
def dashboard_page(request):
    import requests
    from django.contrib import messages

    next_url = request.GET.get('next', '/dashboard/')
    filtered_tasks = []
    username = 'Unknown User'
    role = 'user'

    token = request.session.get('jwt_token')
    user_role = request.session.get('user_role')

    if token and user_role:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get("http://127.0.0.1:5000/api/tasks", headers=headers)
            response.raise_for_status()
            data = response.json()

            tasks = data.get('tasks', [])
            username = data.get('username', 'API User')
            role = data.get('role', user_role)  # fallback to session-stored role

            # ✅ Only filter tasks for non-admin users
            if role == 'admin':
                filtered_tasks = tasks  # Admin sees everything
            else:
                filtered_tasks = [task for task in tasks if task.get('progress') != 100]

        except requests.exceptions.RequestException as e:
            print(f"[FLASK API ERROR] {e}")
            messages.error(request, 'Failed to load tasks from Flask API.')

    elif request.user.is_authenticated:
        try:
            from .models import Task
            all_tasks = Task.objects.filter(user=request.user).exclude(progress=100)
            filtered_tasks = list(all_tasks)
            username = getattr(request.user, 'name', request.user.username)
            role = getattr(request.user, 'role', 'user')
        except Exception as e:
            print(f"[DJANGO DB ERROR] {e}")
            messages.error(request, 'Failed to load tasks from the Django database.')

    else:
        messages.info(request, "Please log in to view your dashboard.")
        return redirect(f'/login/?next={next_url}')

    context = {
        'tasks': filtered_tasks,
        'username': username,
        'role': role,
        'all_priorities': ['Low', 'Medium', 'High', 'Urgent'],
        'next': next_url,
    }

    return render(request, 'dashboard.html', context)

from django.contrib.auth import get_user_model
User=get_user_model()
# from django.db.models import Prefetch

def is_admin(user):
    return user.is_superuser 

# @login_required
# @user_passes_test(is_admin)
User = get_user_model()  # In case you're using a custom user model

def is_admin(user):
    return user.is_authenticated and user.is_superuser

# @login_required
# @user_passes_test(is_admin)
def admin_tasks_view(request):
    if not request.user.is_superuser:
        messages.error(request, "Access denied. Only admins can access this page.")
        return redirect('loginPage')

    try:
        response = requests.get('http://127.0.0.1:5000/api/tasks')
        response.raise_for_status()
        tasks = sorted(response.json(), key=lambda t: t.get('start_date', ''), reverse=True)
    except requests.exceptions.RequestException:
        tasks = []

    users = User.objects.all()  # Keep if you’re showing users (can be removed if not needed)
    return render(request, 'admin_tasks.html', {'tasks': tasks, 'users': users})

# Check if user is an admin (superuser)

#  user is an admin (superuser)
def is_admin(user):
    return user.is_superuser  # Admin check

# Check if the user is a staff member
def is_staff(user):
    return user.is_staff  
FLASK_API_URL = "http://127.0.0.1:5000//api/profile"
@login_required
@user_passes_test(is_admin)
def edit_user(request, user_id):
    user = get_object_or_404(AppUser, id=user_id)  # Get AppUser instead of User

    if request.method == 'POST':
        # Collect the updated data from the POST request
        updated_data = {
            'name': request.POST.get('name', user.name),
            'email': request.POST.get('email', user.email),
            'phone': request.POST.get('phone', user.phone),
            'role': request.POST.get('role', user.role),
            'gender': request.POST.get('gender', user.gender),
            'address': request.POST.get('address', user.address),
        }

        # Make a POST request to Flask API to update user data
        response = requests.put(f"{FLASK_API_URL}/{user_id}", json=updated_data)

        if response.status_code == 200:
            messages.success(request, f'User {user.name} updated successfully!')
            return redirect('admin_tasks')  # Redirect back to admin tasks page
        else:
            messages.error(request, 'Error updating user. Please try again.')

    # For GET request, display current user data
    return render(request, 'edit_user.html', {'user': user})


import requests
from django.shortcuts import render, redirect
from django.http import HttpResponse
import logging

logger = logging.getLogger(__name__)
FLASK_API_BASE = 'http://127.0.0.1:5000'  # Make sure this is defined


# @jwt_required()
import requests

# FLASK_API_URL = 'http://127.0.0.1:5000/api/tasks'
from datetime import date
def get_auth_headers(request):
    token = request.session.get('jwt_token')  # Store token with this key after login
    if not token:
        print("⚠ JWT token missing in session.")
        raise Exception("JWT not found in session.")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
import traceback

def add_task_view(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        priority = request.POST.get('priority')
        start_date = request.POST.get('start_date') or str(date.today())
        end_date = request.POST.get('end_date')

        print("\n--- DEBUG: Received POST data from form ---")
        print(f"Title: {title}, Desc: {description}, Priority: {priority}, Start: {start_date}, End: {end_date}")

        if not all([title, description, priority, end_date]):
            print("Missing required field(s)")
            return render(request, 'addtask.html', {'error': 'All fields are required.'})

        # Check if user is JWT-authenticated (Flask) or Google-authenticated (Django)
        token = request.session.get('jwt_token')
        if token:
            # --- JWT USER: Send to Flask API ---
            payload = {
                "task_title": title,
                "task_description": description,
                "task_priority": priority,
                "start_date": start_date,
                "end_date": end_date,
                "progress": 0  # Ensure progress is set to 0 explicitly
            }

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            try:
                print(f"\n--- Sending POST to Flask API ---")
                response = requests.post('http://127.0.0.1:5000/api/tasks', json=payload, headers=headers)

                if response.status_code == 201:
                    return redirect('/dashboard/')
                else:
                    return render(request, 'addtask.html', {'error': response.json().get('msg', 'Flask task creation failed.')})
            except Exception as e:
                traceback.print_exc()
                return render(request, 'addtask.html', {'error': f'Error contacting Flask API: {str(e)}'})

        else:
            # --- GOOGLE USER: Save to Django DB ---
            try:
                Task.objects.create(
                    user=request.user,
                    task_title=title,
                    task_description=description,
                    task_priority=priority,
                    start_date=start_date,
                    end_date=end_date,
                    progress=0  # Ensure progress is set to 0 explicitly
                )
                return redirect('/dashboard/')
            except Exception as e:
                traceback.print_exc()
                return render(request, 'addtask.html', {'error': f'Django task creation failed: {str(e)}'})

    return render(request, 'addtask.html')
# Task creation view
# Task creation view
def delete_task_view(request, task_id):
    token = request.session.get('jwt_token')

    if token:
        # --- JWT USER: Delete task via Flask API ---
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        try:
            url = f'http://127.0.0.1:5000/api/tasks/{task_id}'
            response = requests.delete(url, headers=headers)

            if response.status_code == 200:
                messages.success(request, 'Task deleted successfully.')
            else:
                try:
                    error_msg = response.json().get('msg', 'Task deletion failed.')
                except Exception:
                    error_msg = 'Task deletion failed.'
                messages.error(request, error_msg)
        except Exception as e:
            traceback.print_exc()
            messages.error(request, f'Error contacting Flask API: {str(e)}')

    else:
        # --- GOOGLE USER: Delete task from Django DB ---
        try:
            task = get_object_or_404(Task, task_id=task_id, user=request.user)
            task.delete()
            messages.success(request, 'Task deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting task: {str(e)}')

    return redirect('dashboard_page')
def edit_progress(request, task_id):
    if request.method == 'POST':
        progress = request.POST.get('progress')  # e.g., 0-100 or text

        print("\n--- DEBUG: Received POST data for progress update ---")
        print(f"Task ID: {task_id}, Progress: {progress}")

        headers = get_auth_headers(request)
        payload = {'progress': progress}

        print("\n--- DEBUG: Sending PUT request to Flask API ---")
        print(f"URL: {FLASK_API_BASE}/api/tasks/{task_id}")
        print(f"Headers: {headers}")
        print(f"Payload: {payload}")

        try:
            response = requests.put(f'{FLASK_API_BASE}/api/tasks/{task_id}', json=payload, headers=headers)

            print("\n--- DEBUG: Flask API Response (PUT) ---")
            print("Status Code:", response.status_code)
            print("Response Text:", response.text)

            if response.status_code == 200:
                return redirect('dashboard_page')  # Redirect to your dashboard URL name
            else:
                error_message = response.json().get('message', 'Failed to update progress.')
                return render(request, 'edit_progress.html', {'task_id': task_id, 'error': error_message})
        except requests.exceptions.RequestException as e:
            print("\n--- DEBUG: Request Exception (PUT) ---")
            traceback.print_exc()
            return render(request, 'edit_progress.html', {'task_id': task_id, 'error': f'Error connecting to Flask API: {str(e)}'})

    # # GET: Prefill progress
    # print("\n--- DEBUG: Sending GET request to Flask API for task details ---")
    # print(f"URL: {FLASK_API_BASE}/api/tasks/{task_id}")
    # print(f"Headers: {get_auth_headers(request)}")

    try:
        response = requests.get(f'{FLASK_API_BASE}/api/tasks/{task_id}', headers=get_auth_headers(request))

        print("\n--- DEBUG: Flask API Response (GET) ---")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)

        if response.status_code == 200:
            task = response.json()
            return render(request, 'edit_progress.html', {'task': task})
        else:
            error_message = response.json().get('message', 'Failed to retrieve task details.')
            return render(request, 'edit_progress.html', {'task_id': task_id, 'error': error_message})
    except requests.exceptions.RequestException as e:
        print("\n--- DEBUG: Request Exception (GET) ---")
        traceback.print_exc()
        return render(request, 'edit_progress.html', {'task_id': task_id, 'error': f'Error connecting to Flask API: {str(e)}'})

    # If it's not a POST and the GET fails, render the form with the task ID
    return render(request, 'edit_progress.html', {'task_id': task_id})

import requests

def completed_tasks(request):
    token = request.session.get('jwt_token')

    if token:
        # --- JWT USER: Fetch tasks from Flask API ---
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.get('http://127.0.0.1:5000/api/tasks', headers=headers)

            if response.status_code == 200:
                all_tasks = response.json().get('tasks', [])
                completed = [task for task in all_tasks if task.get('progress') == 100]
            else:
                return render(request, 'completed_tasks.html', {
                    'error': 'Failed to fetch tasks from API.'
                })
        except Exception as e:
            return render(request, 'completed_tasks.html', {
                'error': f'Error contacting Flask API: {str(e)}'
            })
    else:
        # --- GOOGLE USER: Fetch tasks from Django DB ---
        completed = list(Task.objects.filter(user=request.user, progress=100).values(
            'task_title', 'task_description', 'end_date', 'task_priority', 'progress'
        ))

    # Extract priority data for chart
    task_data = [{'priority': task.get('task_priority')} for task in completed]

    return render(request, 'completed_tasks.html', {
        'tasks': completed,
        'task_data': json.dumps(task_data)
    })
def update_task_view(request, task_id):
    # Check for JWT token in session for Flask API users
    token = request.session.get('jwt_token')

    headers = {
        "Authorization": f"Bearer {token}" if token else '',
        "Content-Type": "application/json"
    }

    if request.method == 'POST':
        task_title = request.POST.get('title')
        task_description = request.POST.get('description')
        end_date = request.POST.get('due_date')
        task_priority = request.POST.get('priority')

        # Check if title is mandatory
        if not task_title:
            messages.error(request, "Title is mandatory")
        else:
            # Data to send to API or save in Django DB
            payload = {
                'task_title': task_title,
                'task_description': task_description,
                'end_date': end_date,
                'task_priority': task_priority
            }

            if token:  # --- JWT USER: Update via Flask API ---
                try:
                    response = requests.put(f'http://localhost:5000/api/tasks/{task_id}', json=payload, headers=headers)

                    if response.status_code == 200:
                        messages.success(request, f"Task '{task_title}' updated successfully")
                        return redirect('dashboard_page')
                    else:
                        messages.error(request, response.json().get('msg', 'Failed to update task. Please try again.'))
                except Exception as e:
                    traceback.print_exc()
                    messages.error(request, f'Error contacting Flask API: {str(e)}')

            else:  # --- GOOGLE USER: Update in Django DB ---
                try:
                    # Fetch task for the logged-in Google user
                    task = get_object_or_404(Task, task_id=task_id, user=request.user)
                    task.task_title = task_title
                    task.task_description = task_description
                    task.end_date = end_date
                    task.task_priority = task_priority
                    task.save()

                    messages.success(request, f"Task '{task_title}' updated successfully")
                    return redirect('dashboard_page')
                except Exception as e:
                    traceback.print_exc()
                    messages.error(request, f'Failed to update task: {str(e)}')

    else:  # GET request to fetch task details
        if token:  # --- JWT USER: Get task details from Flask ---
            try:
                task_response = requests.get(f'http://localhost:5000/api/tasks/{task_id}', headers=headers)

                if task_response.status_code == 200:
                    task = task_response.json()
                    return render(request, 'update_task.html', {'task': task})
                elif task_response.status_code == 403:
                    return HttpResponseForbidden("Access denied to this task.")
                elif task_response.status_code == 404:
                    messages.error(request, "Task not found.")
                    return redirect('dashboard_page')  # Or some other appropriate page
                else:
                    messages.error(request, f"Failed to fetch task details. Status code: {task_response.status_code}")
                    return redirect('dashboard_page')  # Or handle differently
            except Exception as e:
                traceback.print_exc()
                messages.error(request, f'Error contacting Flask API: {str(e)}')
                return redirect('dashboard_page')

        else:  # --- GOOGLE USER: Get task details from Django DB ---
            task = get_object_or_404(Task, task_id=task_id, user=request.user)

        return render(request, 'update_task.html', {'task': task})

    return render(request, 'update_task.html', {}) 
def calender_view(request):
    print("\n--- DEBUG: Entering calender_view ---")

    token = request.session.get('jwt_token')
    print(f"--- DEBUG: JWT Token: {token} ---")
    token = request.session.get('jwt_token')
    user_role = request.session.get('user_role')

    if not token or not user_role:
        return redirect('/login/')

    headers = {"Authorization": f"Bearer {token}"}

    try:
        # Single request to Flask API (includes both user data and tasks)
        response = requests.get(FLASK_API_URL, headers=headers)
        response.raise_for_status()

        data = response.json()
        tasks = data.get('tasks', [])
        username = data.get('username', 'Unknown User')
        role = data.get('role', 'user')

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        tasks = []
        username = 'Unknown User'
        role = 'user'

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"  # Important for sending JSON, even if not sending a body here.
    }

    try:
        print("\n--- DEBUG: Sending GET request to Flask API ---")
        print("URL: http://localhost:5000/api/tasks")
        print(f"Headers: {headers}")
        print(f"Params: {{'user_id': {request.user.id}, 'progress_lt': 100}}")

        response = requests.get(
            'http://localhost:5000/api/tasks',
            params={'user_id': request.user.id, 'progress_lt': 100},  # Corrected parameter name
            headers=headers
        )

        print("\n--- DEBUG: Flask API Response ---")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)

        if response.status_code == 200:
            tasks = response.json().get('tasks', [])  # Access 'tasks' key safely
        else:
            print(f"--- DEBUG: Flask API returned an error: {response.status_code} ---")
            tasks = []  # Ensure tasks is always initialized
            # Consider logging the error message from the Flask API:
            # error_message = response.json().get('msg', f"Failed to fetch tasks: {response.status_code}")
            # messages.error(request, error_message) #  Use messages framework if appropriate in your project.

        tasks_json = json.dumps(
            [
                {
                    'date': task.get('end_date'),  # Use .get() to avoid KeyError
                    'title': task.get('task_title')
                } for task in tasks if task.get('end_date')
            ],
            cls=DjangoJSONEncoder
        )
        print("--- DEBUG: tasks_json: ", tasks_json)

    except requests.exceptions.RequestException as e:
        print("\n--- DEBUG: Exception Occurred during GET request ---")
        traceback.print_exc()
        tasks = []
        tasks_json = '[]'
        # messages.error(request, f'Error contacting Flask API: {str(e)}') #  Use messages framework if appropriate.

    context = {
        'tasks': tasks,
        'tasks_json': tasks_json,
        'role':role
    }

    print("--- DEBUG: Rendering calender.html ---")
    return render(request, 'calender.html', context)
def edit_task(request, task_id):
    token = request.session.get('jwt_token')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        end_date = request.POST.get('due_date')
        priority = request.POST.get('priority')

        if token:
            # JWT user - Update via Flask API
            payload = {
                "task_title": title,
                "task_description": description,
                "end_date": end_date,
                "task_priority": priority
            }

            response = requests.put(
                f'{FLASK_API_BASE}/api/tasks/{task_id}',
                json=payload,
                headers={"Authorization": f"Bearer {token}"}
            )

            if response.status_code == 200:
                return redirect('dashboard')
            else:
                return render(request, 'edit_task.html', {'error': 'Failed to update task'})

        else:
            # Google user - Update in Django
            try:
                task = get_object_or_404(Task, id=task_id, user=request.user)
                task.task_title = title
                task.task_description = description
                task.end_date = end_date
                task.task_priority = priority
                task.save()
                return redirect('dashboard')
            except Exception as e:
                return render(request, 'edit_task.html', {'error': f'Failed to update task: {str(e)}'})

    else:
        # GET method
        if token:
            # JWT user - Get task from Flask
            response = requests.get(
                f'{FLASK_API_BASE}/api/tasks/{task_id}',
                headers={"Authorization": f"Bearer {token}"}
            )
            if response.status_code == 200:
                data = response.json()
                # Normalize Flask keys to match Django keys used in the template
                task = {
                    "task_title": data.get("task_title", ""),
                    "task_description": data.get("task_description", ""),
                    "end_date": data.get("end_date", ""),
                    "task_priority": data.get("task_priority", "Low")
                }
            else:
                return render(request, 'edit_task.html', {'error': f'Failed to fetch task details. Status code: {response.status_code}'})
        else:
            # Google user - Get from Django DB
            task = get_object_or_404(Task, id=task_id, user=request.user)
            # print(f"Task ID: {task.id}") 
        return render(request, 'edit_task.html', {'task': task})

def task_list(request):
    token = request.session.get('jwt_token')
    role = request.session.get('user_role')

    if not token or not role:
        return redirect('/login/')

    headers = {"Authorization": f"Bearer {token}"}
    params = {}

    # Step 1: Add search/filter if present
    title_query = request.GET.get('title', '').strip()
    priority_filter = request.GET.get('priority', '').strip()
    if title_query:
        params['title'] = title_query
    if priority_filter:
        params['priority'] = priority_filter

    # Step 2: Request tasks
    try:
        task_response = requests.get("http://localhost:5000/api/tasks", headers=headers, params=params)
        print("Status Code:", task_response.status_code)
        print("Response Text:", task_response.text)

        if task_response.status_code == 200:
            data = task_response.json()
            tasks = data.get('admin_tasks' if role == 'admin' else 'tasks', [])
        else:
            tasks = []
    except requests.exceptions.RequestException as e:
        print(f"Error fetching tasks: {e}")
        tasks = []

    return render(request, 'admin_tasks.html', {
        'tasks': tasks,
        'all_priorities': ['Low', 'Medium', 'High', 'Urgent'],
        'role': role
    })

from django.contrib.auth.decorators import permission_required

BASE_URL = "http://127.0.0.1:5000/api/help" 

def admin_help_requests(request):
    # Check if the user is an admin
    # if not request.user.is_superuser:
    #     return redirect('some_error_page')  # Redirect if not admin
    token = request.session.get('jwt_token')
    user_role = request.session.get('user_role')

    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(BASE_URL, headers=headers)
        if response.status_code == 401:
            print("Unauthorized: JWT token expired or invalid")
            return redirect('/login/')  # Token is invalid
        response.raise_for_status()
        help_requests = response.json()
        print(help_requests)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching help requests: {e}")
        help_requests = []

    return render(request, 'admin_help.html', {'help_requests': help_requests,'role':user_role})
