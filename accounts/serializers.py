# 1. Third-party imports
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode

# 2. Local imports
from .models import UserProfile
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password

User = get_user_model()


class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirmation = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ["email", "password", "password_confirmation"]

    def validate(self, data):
        """
        Ensure the two passwords match.
        """
        # Check for matching passwords
        if data["password"] != data["password_confirmation"]:
            raise serializers.ValidationError({"password": "Passwords must match."})

        # Check if the email already exists
        if User.objects.filter(email=data["email"]).exists():
            raise serializers.ValidationError(
                {"email": "Custom user with this email already exists."}
            )

        # Custom password validation
        try:
            validate_password(data["password"])
        except ValidationError as e:
            raise serializers.ValidationError({"password": e.messages})

        return data

    def create(self, validated_data):
        """
        Create a new user with a hashed password.
        """
        validated_data.pop("password_confirmation")
        user = User.objects.create_user(
            email=validated_data["email"], password=validated_data["password"]
        )
        return user


class RegisterVerifySerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()


class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Validate if the email is associated with a user and not yet verified.
        """
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        # Check if the user is already verified
        if user.email_verified:
            raise serializers.ValidationError("Email is already verified.")

        return value

    def get_user(self, email):
        """Custom method to get the user based on email"""
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Ensure the new password is different from the old one.
        """
        if data["old_password"] == data["new_password"]:
            raise serializers.ValidationError(
                {
                    "new_password": "The new password must be different from the old password."
                }
            )
        return data


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Check if the email is associated with a registered and active user.
        """
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email doesn't exist.")

        # Check if the user is active
        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")

        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate_new_password(self, value):
        """
        Validate that the password is at least 8 characters long and not the same as the old password.
        """
        min_length = 8  # Define the minimum length of the password
        if len(value) < min_length:
            raise serializers.ValidationError(
                f"Password must be at least {min_length} characters long."
            )

        # Check if the new password is the same as the old password
        uid = self.context.get("uidb64")
        user = User.objects.get(pk=urlsafe_base64_decode(uid).decode())
        if check_password(value, user.password):
            raise serializers.ValidationError(
                {"new_password": "New password cannot be the same as the old one."}
            )

        return value

    def validate(self, data):
        """
        Validate the new password and user existence.
        """
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError({"password": "Passwords must match."})

        # Validate password length and uniqueness
        self.validate_new_password(data["new_password"])

        try:
            uid = urlsafe_base64_decode(data["uidb64"]).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid token or user.")

        return data

    def save(self):
        """
        Set the new password for the user.
        """
        uid = urlsafe_base64_decode(self.validated_data["uidb64"]).decode()
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "email",
            "is_active",
            "is_staff",
            "is_superuser",
            "email_verified",
            "date_joined",
        )


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("first_name", "last_name", "bio", "profile_picture")
