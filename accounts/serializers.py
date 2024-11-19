# 1. Third-party imports
from rest_framework import serializers

# 2. Local imports
from django.contrib.auth import get_user_model
from .models import Student, Instructor


User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "password2", "first_name", "last_name"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password2": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        user = User.objects.create_user(**validated_data)
        user.is_active = False
        user.save()
        return user


class VerifyEmailSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()


class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        if user.email_verified:
            raise serializers.ValidationError("Email is already verified.")

        # Store user object in context to be accessed later in the validate method
        self.context["user"] = user
        return value

    def validate(self, attrs):
        # Add the user to validated_data
        attrs["user"] = self.context["user"]
        return attrs


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = [
            "email",
            "first_name",
            "last_name",
            "password",
            "bio",
            "is_student",
            "is_instructor",
            "picture",
        ]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = get_user_model().objects.create_user(**validated_data)
        return user


class StudentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = [
            "user",
            "interests",
            "skill_level",
        ]


class InstructorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Instructor
        fields = [
            "user",
            "verification_documents",
            "is_verified",
            "expertise_area",
            "years_of_experience",
        ]


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = get_user_model().objects.get(email=value)
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError("No user found with this email address.")
        return value

    def save(self):
        email = self.validated_data.get("email")
        user = get_user_model().objects.get(email=email)
        return user


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def save(self, user):
        user.set_password(self.validated_data["new_password"])
        user.save()
