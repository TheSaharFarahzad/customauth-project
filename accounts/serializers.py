# 1. Third-party imports (external libraries)
from rest_framework import serializers

# 2. Local imports (your project-specific imports)
from django.contrib.auth import get_user_model


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ["email", "first_name", "last_name", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = get_user_model().objects.create_user(**validated_data)
        return user


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
        ]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = get_user_model().objects.create_user(**validated_data)
        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
