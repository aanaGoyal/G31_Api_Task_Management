from django.contrib.auth.backends import ModelBackend
from .models import AppUser

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = AppUser.objects.get(email=username)  # Use email instead of username

            # If password is provided, check the password
            if password and user.check_password(password):
                return user

            # If no password (Google OAuth), return the user directly
            elif not password:
                return user

        except AppUser.DoesNotExist:
            return None
