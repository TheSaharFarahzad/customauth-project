# 1. Standard library imports
from django.db import models
from django.utils import timezone

# 2. Third-party imports
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("Superusers must have staff privileges enabled.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superusers must have elevated administrative privileges.")

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        ordering = ("-date_joined",)

    # def __str__(self):
    #     return f"{self.first_name} {self.last_name}"


class UserProfile(models.Model):
    user = models.OneToOneField(
        CustomUser,
        related_name="profile",
        on_delete=models.CASCADE,
    )
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    bio = models.TextField(blank=True)
    profile_picture = models.ImageField(
        default="default_profile_picture.jpg",
        upload_to="profile_pictures",
        blank=True,
    )

    def __str__(self):
        return f"Profile of {self.user.first_name} {self.user.last_name}"
