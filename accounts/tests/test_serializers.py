# import pytest
# from django.contrib.auth import get_user_model
# from rest_framework.exceptions import ValidationError
# from accounts.serializers import (
#     RegisterSerializer,
#     LoginSerializer,
#     CustomUserSerializer,
#     ChangePasswordSerializer,
#     PasswordResetSerializer,
#     PasswordResetConfirmSerializer,
# )


# @pytest.mark.django_db
# class TestRegisterSerializer:

#     def test_serialize_model(self):
#         user = get_user_model().objects.create_user(
#             email="test@example.com",
#             first_name="John",
#             last_name="Doe",
#             password="securepassword123",
#         )
#         serializer = RegisterSerializer(user)
#         assert serializer.data["email"] == "test@example.com"
#         assert serializer.data["first_name"] == "John"
#         assert serializer.data["last_name"] == "Doe"

#     def test_deserialize_valid_data(self):
#         valid_data = {
#             "email": "test@example.com",
#             "first_name": "John",
#             "last_name": "Doe",
#             "password": "securepassword123",
#         }
#         serializer = RegisterSerializer(data=valid_data)
#         assert serializer.is_valid()
#         assert serializer.errors == {}

#     def test_deserialize_invalid_data(self):
#         invalid_data = {
#             "email": "invalidemail",
#             "first_name": "John",
#             "last_name": "Doe",
#             "password": "short",
#         }
#         serializer = RegisterSerializer(data=invalid_data)
#         assert not serializer.is_valid()
#         assert "email" in serializer.errors
#         assert "password" in serializer.errors


# # @pytest.mark.django_db
# # class TestLoginSerializer:

# #     def test_serialize_model(self):
# #         user = get_user_model().objects.create_user(
# #             email="test@example.com", password="securepassword123"
# #         )
# #         serializer = LoginSerializer(
# #             data={"email": "test@example.com", "password": "securepassword123"}
# #         )
# #         assert serializer.is_valid()

# #     def test_login_invalid_data(self):
# #         invalid_data = {"email": "test@example.com", "password": "wrongpassword"}
# #         serializer = LoginSerializer(data=invalid_data)
# #         assert not serializer.is_valid()
# #         assert "non_field_errors" in serializer.errors


# # @pytest.mark.django_db
# # class TestChangePasswordSerializer:

# #     def test_valid_password_change(self):
# #         user = get_user_model().objects.create_user(
# #             email="test@example.com", password="securepassword123"
# #         )
# #         serializer = ChangePasswordSerializer(
# #             data={"old_password": "securepassword123", "new_password": "newpassword123"}
# #         )
# #         assert serializer.is_valid()

# #     def test_invalid_password_change(self):
# #         user = get_user_model().objects.create_user(
# #             email="test@example.com", password="securepassword123"
# #         )
# #         serializer = ChangePasswordSerializer(
# #             data={"old_password": "wrongpassword", "new_password": "newpassword123"}
# #         )
# #         assert not serializer.is_valid()
# #         assert "old_password" in serializer.errors


# # @pytest.mark.django_db
# # class TestPasswordResetSerializer:

# #     def test_reset_password_valid_email(self):
# #         user = get_user_model().objects.create_user(
# #             email="test@example.com", password="securepassword123"
# #         )
# #         serializer = PasswordResetSerializer(data={"email": "test@example.com"})
# #         assert serializer.is_valid()
# #         user = serializer.save()
# #         assert user.email == "test@example.com"

# #     def test_reset_password_invalid_email(self):
# #         serializer = PasswordResetSerializer(data={"email": "nonexistent@example.com"})
# #         assert not serializer.is_valid()
# #         assert "email" in serializer.errors


# # @pytest.mark.django_db
# # class TestPasswordResetConfirmSerializer:

# #     def test_valid_reset_confirm(self):
# #         user = get_user_model().objects.create_user(
# #             email="test@example.com", password="securepassword123"
# #         )
# #         serializer = PasswordResetConfirmSerializer(
# #             data={
# #                 "new_password": "newpassword123",
# #                 "confirm_password": "newpassword123",
# #             }
# #         )
# #         assert serializer.is_valid()
# #         serializer.save(user)
# #         user.refresh_from_db()
# #         assert user.check_password("newpassword123")

# #     def test_invalid_reset_confirm(self):
# #         user = get_user_model().objects.create_user(
# #             email="test@example.com", password="securepassword123"
# #         )
# #         serializer = PasswordResetConfirmSerializer(
# #             data={
# #                 "new_password": "newpassword123",
# #                 "confirm_password": "differentpassword",
# #             }
# #         )
# #         assert not serializer.is_valid()
# #         assert "non_field_errors" in serializer.errors
