from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models 
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
import re
# from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone = models.CharField(max_length=15, null=True, blank=True)
    role = models.CharField(max_length=30, null=True, blank=True)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)

    def __str__(self):
        return f"{self.user.email}'s Profile"

    # Add other fields here (bio, location, etc.)


from django.contrib.auth.base_user import BaseUserManager

class AppUserManager(BaseUserManager):
    def create_user(self, email, name, phone, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, phone=phone, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()  # Important for OAuth users

        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phone, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not password:
            raise ValueError('Superuser must have a password.')

        return self.create_user(email, name, phone, password, **extra_fields)


class AppUser(AbstractUser,PermissionsMixin):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    role = models.CharField(max_length=30, null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], null=True, blank=True)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    address = models.CharField(max_length=255, default='Not Provided') 
    # is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Removing the default username field and making email the primary identifier
    username = None
    objects = AppUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone']

    
    def __str__(self):
        return self.email
