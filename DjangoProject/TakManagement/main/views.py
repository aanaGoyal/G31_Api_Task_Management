from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
# from django.contrib.auth.models import User
from .models import AppUser
from django.contrib.auth import get_user_model
User = get_user_model() 
from django.contrib.auth.decorators import login_required
from .models import Profile
from datetime import datetime, timedelta
# from DashboardApp.models import Task
from django.contrib.auth import logout
from django.http import HttpResponseNotAllowed
from allauth.socialaccount.models import SocialAccount
FLASK_API_BASE = 'http://127.0.0.1:5000'

# Helper function to get auth headers
def get_auth_headers(request):
    token = request.session.get('jwt_token')
    return {'Authorization': f'Bearer {token}'} if token else {}
# Create your views here.
def about_us(request):
    return render(request, 'about_us.html')

def base(request):
    return render(request, 'base.html')

def billing(request):
    return render(request, 'billing.html', {
        'banner_message': 'Manage your billing and subscription settings here.'
    })

def contact(request):
    return render(request, 'contact.html')

def features(request):
    return render(request, 'features.html', {
        'banner_message': 'Explore all our powerful features!'
    })

def feedback(request):
    return render(request, 'feedback.html')





def inspiration_hub(request):
    return render(request, 'inspiration_hub.html')

def integrations(request):
    return render(request, 'integrations.html', {
        'banner_message': 'Connect with your favorite tools seamlessly.'
    })

def suggest(request):
    return render(request, 'suggest.html')

def teams(request):
    return render(request, 'teams.html', {
        'banner_message': 'Collaborate and manage your team efficiently.'
    })


def templates(request):
    return render(request, 'templates.html')

def troubleshoot(request):
    return render(request, 'troubleshooting.html', {
        'banner_message': 'Let’s fix any issues you’re facing.'
    })

def get_started(request):
    return render(request, 'get_started.html', {
        'banner_message': 'Welcome to the Get Started Page! Let’s begin your journey.'
    })

def continue_without(request):
    return render(request, 'continue_without_login.html')

# def index2(request):
#     return render(request, 'index2.html')

def index3(request):
    return render(request, 'index3.html')

def index(request):
    return render(request, 'index.html')

def base_exp(request):
    return render(request, 'base_exp')


def index2(request):
    sections = [
        {"title": "Get Started", "description": "Start using the platform quickly.", "route": "get_started"},
        {"title": "Features", "description": "Explore all features we offer.", "route": "features"},
        {"title": "Teams", "description": "Manage your team and roles.", "route": "teams"},
        {"title": "Billing", "description": "View and manage billing options.", "route": "billing"},
        {"title": "Troubleshooting", "description": "Fix common issues and errors.", "route": "troubleshoot"},
        {"title": "Integrations", "description": "Connect with other tools.", "route": "integrations"},
    ]
    return render(request, 'index2.html', {'sections': sections})


from django.contrib.auth import get_user_model
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import AppUser  # Assuming you're using a custom user model (AppUser)
import re


import requests
from django.shortcuts import render, redirect
from django.contrib import messages
import re
from .models import AppUser, Profile
def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('name')  # <-- renamed to match Flask
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        gender = request.POST.get('gender')
        address = request.POST.get('address')
        role = 'user'  # Set role explicitly

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'sign_up_page.html')

        # Log the data you're sending
        print("Sending data to Flask API:", {
            'username': username,
            'email': email,
            'phone': phone,
            'password': password,
            'gender': gender,
            'address': address,
            'role': role
        })

        try:
            response = requests.post(f'{FLASK_API_BASE}/registerapi', json={
                'username': username,
                'email': email,
                'phone': phone,
                'password': password,
                'gender': gender,
                'address': address,
                'role': role  # Send role to the API
            })

            if response.status_code == 201:
                messages.success(request, 'Signup successful! Please log in.')
                return redirect('loginPage')
            else:
                print(f"Error: {response.status_code} - {response.text}")
                messages.error(request, response.json().get('message', 'Signup failed. Please try again.'))

        except requests.exceptions.RequestException as e:
            print(f"Error during signup request: {e}")
            messages.error(request, 'An error occurred during signup. Please try again.')

    return render(request, 'sign_up_page.html')

from django.contrib.auth import authenticate, login
import requests
from django.views.decorators.csrf import csrf_exempt
FLASK_API_URL = 'http://127.0.0.1:5000/loginapi'

import json
@csrf_exempt
def login_view(request):
    next_url = request.GET.get('next', 'dashboard_page')

    if request.user.is_authenticated and SocialAccount.objects.filter(user=request.user).exists():
        # User logged in via Google OAuth
        return redirect(next_url)

    if request.method == 'POST':
        # Get credentials from the form
        email = request.POST.get('email')
        password = request.POST.get('password')
        role = request.POST.get('role')
        # Check credentials and get user data from Flask API (or your DB)
        # Assuming you have a Flask API endpoint for authentication
        data = {
            'email': email,
            'password': password,
            'role':role
        }
        # Set the correct Content-Type and send the POST request with JSON data
        headers = {'Content-Type': 'application/json'}
        response = requests.post(f'{FLASK_API_URL}', data=json.dumps(data), headers=headers)
        print(response.status_code)
        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            print(token)
            user_role = data.get('role')  # Assuming user_id is returned by Flask API

            request.session['jwt_token'] = token
            request.session['user_role'] = user_role
            
            return redirect('/dashboard/')
        elif response.status_code == 400:
            print(response.json()) 

    # If it's a GET request, simply render the login page
    return render(request, 'login_page.html')
            

def logout_view(request):
    if request.method == 'POST':  # Handle POST requests only
        logout(request)
        return redirect('index')  # Redirect to index page after logout
    return HttpResponseNotAllowed(['POST'])

@login_required
def home(request):
    return render(request, 'home.html')

from datetime import datetime, timedelta
from django.shortcuts import get_object_or_404

def profile_view(request):
    token = request.session.get('jwt_token')
    if not token:
        return redirect('loginPage')  # User not logged in

    headers = {"Authorization": f"Bearer {token}"}
    
    # Check the token sent to Flask
    print("Token sent to Flask:", headers)
    
    response = requests.get(f'{FLASK_API_BASE}/api/profile', headers=headers)

    if response.status_code == 200:
        user_data = response.json()
        print("User data from Flask:", user_data)
        context = {'profile_user': user_data}
        print("Context passed to template:", context)
        return render(request, 'profile.html', context)
    else:
        return render(request, 'profile.html', {'error': 'Failed to fetch profile data'})

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

# from .forms import UserEditForm
# @login_required
# @login_required
def edit_profile(request, user_id):
    # Ensure the user can only edit their own profile
    if request.user.id != user_id:
        messages.error(request, "You can only edit your own profile.")
        return redirect('profile')  # Or any other redirect, like the dashboard

    user = get_object_or_404(AppUser, id=user_id)

    if request.method == 'POST':
        username = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        password = request.POST.get('password')
        gender = request.POST.get('gender')
        address = request.POST.get('address')

        # Send the update to Flask API
        response = requests.put(f'{FLASK_API_BASE}/api/users/{user_id}', json={
            'name': username,
            'email': email,
            'phone': phone,
            'password': password,  # Optional, based on how you want to handle password
            'gender': gender,
            'address': address
        })

        if response.status_code == 200:
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')  # Redirect to the profile page after saving changes
        else:
            messages.error(request, 'Error updating profile.')

    # If the request method is not POST, we return the profile edit page (no need for a form here)
    return render(request, 'edit_profile.html', {'user': user})

@login_required
def upload_profile_image(request):
    if request.method == 'POST' and request.FILES.get('profile_image'):
        profile = request.user.profile
        profile.profile_image = request.FILES['profile_image']
        profile.save()
        
        
        return redirect('profile') 
    return redirect('profile')  # Adjust as necessary

@login_required
def delete_profile_image(request):
    if request.method == 'POST':
        profile = request.user.profile
        profile.profile_image.delete(save=True)
        return redirect('profile')


import requests
from django.shortcuts import render
from django.http import JsonResponse

# Base URL of your Flask API
BASE_URL = "http://127.0.0.1:5000/api/help"  # Update this URL to match your Flask app

# Function to get Help Requests from Flask API
def get_help_requests():
    response = requests.get(BASE_URL)
    if response.status_code == 200:
        return response.json()  # Returns data as JSON from Flask API
    else:
        return {'error': 'Failed to fetch help requests'}


def help(request):
    help_requests=get_help_requests()
    return render(request, 'help.html',{'help_requests':help_requests})

