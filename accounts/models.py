# 1. Standard library imports
from django.db import models
from django.utils import timezone

# 2. Third-party imports
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth import get_user_model


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
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
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    bio = models.TextField(blank=True)
    picture = models.ImageField(
        default="default_profile_pic.jpg", upload_to="profile_pics", blank=True
    )
    is_student = models.BooleanField(default=False)
    is_instructor = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = CustomUserManager()

    class Meta:
        ordering = ("-date_joined",)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class Student(models.Model):
    user = models.OneToOneField(
        get_user_model(),
        related_name="student_profile",
        on_delete=models.CASCADE,
    )
    interests = models.TextField(
        blank=True, help_text="Student's learning interests or areas of focus"
    )
    skill_level = models.CharField(
        max_length=50,
        choices=[
            ("beginner", "Beginner"),
            ("intermediate", "Intermediate"),
            ("advanced", "Advanced"),
        ],
        default="beginner",
    )

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}'s Student Profile"


class Instructor(models.Model):
    user = models.OneToOneField(
        get_user_model(),
        related_name="instructor_profile",
        on_delete=models.CASCADE,
    )
    verification_documents = models.FileField(
        upload_to="verification_docs", blank=True, null=True
    )
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    expertise_area = models.CharField(max_length=255)
    years_of_experience = models.PositiveIntegerField(default=0, blank=True, null=True)

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}'s Instructor Profile"
