import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField
import datetime
from datetime import timedelta
from django.utils import timezone

from .managers import CustomUserManager


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """Custom User Manager"""
    
    full_name = models.CharField(_("full name"), max_length=100)
    email = models.EmailField(_("email address"), unique=True)
    phone_number = PhoneNumberField(null=True, blank=True, unique=True)
    profile_picture = models.ImageField(upload_to="images/")
    password = models.CharField(max_length=255, blank=False)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    current_income = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name", "phone_number"]
    
    objects = CustomUserManager()
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
    
    def __str__(self) -> str:
        return self.full_name


class OTP(models.Model):
    """OTP table"""
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return self.email


class Budget(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    category = models.CharField(max_length=128)
    name = models.CharField(max_length=128, default='Miscellaneous')
    amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    start_date = models.DateField(timezone.now(), blank=True)
    end_date = models.DateField(blank=True)

    def __str__(self):
        return f"{self.user.full_name}'s {self.name} Budget"