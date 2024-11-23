# import pytest
# from ..serializers import RegisterUserSerializer
# from django.contrib.auth import get_user_model

# User = get_user_model()


# @pytest.mark.django_db
# class TestRegisterUserSerializer:
#     @pytest.mark.parametrize(
#         "data,is_valid,expected_errors",
#         [
#             (
#                 {
#                     "email": "test@example.com",
#                     "password": "password123",
#                     "password_confirmation": "password123",
#                 },
#                 True,
#                 {},
#             ),
#             (
#                 {
#                     "email": "test@example.com",
#                     "password": "password123",
#                     "password_confirmation": "wrongpassword",
#                 },
#                 False,
#                 {"password": ["Passwords must match."]},
#             ),
#             (
#                 {
#                     "email": "",
#                     "password": "password123",
#                     "password_confirmation": "password123",
#                 },
#                 False,
#                 {"email": ["This field may not be blank."]},
#             ),
#             (
#                 {
#                     "email": "invalid-email",
#                     "password": "password123",
#                     "password_confirmation": "password123",
#                 },
#                 False,
#                 {"email": ["Enter a valid email address."]},
#             ),
#             (
#                 {
#                     "email": "test@example.com",
#                     "password": "short",
#                     "password_confirmation": "short",
#                 },
#                 False,
#                 {"password": ["Ensure this field has at least 8 characters."]},
#             ),
#         ],
#     )
#     def test_serializer_validation(self, data, is_valid, expected_errors):
#         """
#         Test RegisterUserSerializer validation logic.
#         """
#         serializer = RegisterUserSerializer(data=data)
#         assert serializer.is_valid() == is_valid
#         if not is_valid:
#             assert serializer.errors == expected_errors

#     def test_serializer_create_user(self):
#         """
#         Test that the serializer successfully creates a user.
#         """
#         data = {
#             "email": "test@example.com",
#             "password": "password123",
#             "password_confirmation": "password123",
#         }
#         serializer = RegisterUserSerializer(data=data)
#         assert serializer.is_valid()
#         user = serializer.save()
#         assert user.email == "test@example.com"
#         assert user.check_password("password123")
