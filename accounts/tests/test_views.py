# import pytest
# import json
# from django.urls import reverse
# from django.core import mail
# from rest_framework import status
# from rest_framework.test import APIClient

# from accounts.models import CustomUser
# from accounts.views import RegisterView, RegisterVerifyView


# @pytest.mark.django_db
# class TestRegisterView:
#     def test_register_user(self, client: APIClient):
#         url = reverse("register")
#         data = {
#             "email": "testuser@example.com",
#             "first_name": "first_name",
#             "last_name": "last_name",
#             "password": "TestPass123",
#         }
#         response = client.post(url, data, format="json")

#         assert response.status_code == status.HTTP_201_CREATED
#         assert "message" in response.data
#         assert "User registered successfully!" in response.data["message"]

#         # Ensure an email was sent
#         assert len(mail.outbox) == 1
#         activation_email = mail.outbox[0]
#         assert "Account Activation" in activation_email.subject
#         assert "Click the link to verify your email" in activation_email.body

#     def test_register_user_invalid_data(self, client: APIClient):
#         url = reverse("register")
#         data = {
#             "email": "testuser@example.com",
#             "first_name": "",
#             "last_name": "",
#             "password": "TestPass123",
#         }
#         response = client.post(url, data, format="json")

#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#         assert "first_name" in response.data
#         assert "last_name" in response.data


# # @pytest.mark.django_db
# # class TestRegisterVerifyView:
# #     def test_verify_email_success(self, client: APIClient):
# #         user = CustomUser.objects.create_user(
# #             email="testuser@example.com", password="TestPass123", is_active=False
# #         )
# #         uidb64 = urlsafe_base64_encode(str(user.id).encode()).decode()
# #         token = str(RefreshToken.for_user(user).access_token)

# #         url = reverse("register-verify", kwargs={"uidb64": uidb64, "token": token})
# #         response = client.get(url)

# #         assert response.status_code == status.HTTP_200_OK
# #         assert "Email verified successfully!" in response.data["message"]

# #     def test_verify_email_invalid_token(self, client: APIClient):
# #         user = CustomUser.objects.create_user(
# #             email="testuser@example.com", password="TestPass123", is_active=False
# #         )
# #         uidb64 = urlsafe_base64_encode(str(user.id).encode()).decode()
# #         invalid_token = "invalidtoken"

# #         url = reverse(
# #             "register-verify", kwargs={"uidb64": uidb64, "token": invalid_token}
# #         )
# #         response = client.get(url)

# #         assert response.status_code == status.HTTP_400_BAD_REQUEST
# #         assert "Invalid token" in response.data["message"]

# #     def test_verify_email_user_not_found(self, client: APIClient):
# #         invalid_uidb64 = urlsafe_base64_encode("999".encode()).decode()
# #         token = "some_valid_token"

# #         url = reverse(
# #             "register-verify", kwargs={"uidb64": invalid_uidb64, "token": token}
# #         )
# #         response = client.get(url)

# #         assert response.status_code == status.HTTP_404_NOT_FOUND
# #         assert "User not found" in response.data["message"]


# # @pytest.mark.django_db
# # class TestLoginView:
# #     def test_login_user(self, client: APIClient):
# #         user = CustomUser.objects.create_user(
# #             email="testuser@example.com", password="TestPass123"
# #         )
# #         url = reverse("login")
# #         data = {"email": "testuser@example.com", "password": "TestPass123"}

# #         response = client.post(url, data, format="json")

# #         assert response.status_code == status.HTTP_200_OK
# #         assert "access" in response.data
# #         assert "refresh" in response.data

# #     def test_login_invalid_user(self, client: APIClient):
# #         url = reverse("login")
# #         data = {"email": "wronguser@example.com", "password": "WrongPassword123"}

# #         response = client.post(url, data, format="json")

# #         assert response.status_code == status.HTTP_400_BAD_REQUEST
# #         assert "error" in response.data
# #         assert "Invalid credentials" in response.data["error"]


# # @pytest.mark.django_db
# # class TestLogoutView:
# #     def test_logout_user(self, client: APIClient):
# #         user = CustomUser.objects.create_user(
# #             email="testuser@example.com", password="TestPass123"
# #         )
# #         client.login(email="testuser@example.com", password="TestPass123")
# #         url = reverse("logout")

# #         response = client.post(url)

# #         assert response.status_code == status.HTTP_200_OK
# #         assert "Successfully logged out" in response.data["message"]


# # @pytest.mark.django_db
# # class TestChangePasswordView:
# #     def test_change_password_success(self, client: APIClient):
# #         user = CustomUser.objects.create_user(
# #             email="testuser@example.com", password="TestPass123"
# #         )
# #         client.login(email="testuser@example.com", password="TestPass123")

# #         url = reverse("change-password")
# #         data = {"old_password": "TestPass123", "new_password": "NewPass123"}

# #         response = client.post(url, data, format="json")

# #         assert response.status_code == status.HTTP_200_OK
# #         assert "Password changed successfully" in response.data["message"]

# #     def test_change_password_invalid_old_password(self, client: APIClient):
# #         user = CustomUser.objects.create_user(
# #             email="testuser@example.com", password="TestPass123"
# #         )
# #         client.login(email="testuser@example.com", password="TestPass123")

# #         url = reverse("change-password")
# #         data = {"old_password": "WrongOldPassword", "new_password": "NewPass123"}

# #         response = client.post(url, data, format="json")

# #         assert response.status_code == status.HTTP_400_BAD_REQUEST
# #         assert "Old password is incorrect" in response.data["error"]
