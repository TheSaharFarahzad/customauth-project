import json
import pytest

# from model_bakery import baker
from django.urls import reverse
from accounts.models import CustomUser as User

pytestmark = pytest.mark.django_db


class TestUserEndpoints:

    # Endpoint base for user-related views
    base_url = "/api/"

    def test_register(self, api_client):
        user_data = {
            "email": "testuser@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "password123",
        }

        response = api_client.post(
            self.base_url + "register/", user_data, format="json"
        )
        response_data = json.loads(response.content)
        assert (
            response_data["message"]
            == "User registered successfully! Please check your email to activate your account."
        )

    # def test_login(self, api_client):
    #     user = baker.make(
    #         User,
    #         username="testuser",
    #         email="testuser@example.com",
    #         password="password123",
    #     )
    #     login_data = {"username": "testuser", "password": "password123"}

    #     response = api_client.post(self.base_url + "login/", login_data, format="json")

    #     assert response.status_code == 200
    #     assert "access" in json.loads(response.content)

    # def test_logout(self, api_client):
    #     user = baker.make(
    #         User,
    #         username="testuser",
    #         email="testuser@example.com",
    #         password="password123",
    #     )
    #     api_client.force_authenticate(user=user)

    #     response = api_client.post(self.base_url + "logout/")

    #     assert response.status_code == 204

    # def test_change_password(self, api_client):
    #     user = baker.make(
    #         User,
    #         username="testuser",
    #         email="testuser@example.com",
    #         password="password123",
    #     )
    #     api_client.force_authenticate(user=user)

    #     password_data = {
    #         "old_password": "password123",
    #         "new_password": "newpassword123",
    #     }

    #     response = api_client.post(
    #         self.base_url + "password/change/", password_data, format="json"
    #     )

    #     assert response.status_code == 200

    # def test_password_reset(self, api_client):
    #     user = baker.make(
    #         User,
    #         username="testuser",
    #         email="testuser@example.com",
    #         password="password123",
    #     )

    #     password_reset_data = {"email": "testuser@example.com"}

    #     response = api_client.post(
    #         self.base_url + "password/reset/", password_reset_data, format="json"
    #     )

    #     assert response.status_code == 200
    #     assert "email" in json.loads(response.content)

    # def test_password_reset_confirm(self, api_client):
    #     # Assuming you have a way to generate the uidb64 and token
    #     uidb64 = "dummyuid"  # Generate accordingly
    #     token = "dummy-token"  # Generate accordingly
    #     reset_confirm_data = {"new_password": "newpassword123"}

    #     url = reverse("password_reset_confirm", args=[uidb64, token])
    #     response = api_client.post(url, reset_confirm_data, format="json")

    #     assert response.status_code == 200

    # def test_user_profile(self, api_client):
    #     user = baker.make(
    #         User,
    #         username="testuser",
    #         email="testuser@example.com",
    #         password="password123",
    #     )
    #     api_client.force_authenticate(user=user)

    #     response = api_client.get(self.base_url + "user/")

    #     assert response.status_code == 200
    #     assert json.loads(response.content)["username"] == user.username

    # def test_update_user_profile(self, api_client):
    #     user = baker.make(
    #         User,
    #         username="testuser",
    #         email="testuser@example.com",
    #         password="password123",
    #     )
    #     api_client.force_authenticate(user=user)

    #     update_data = {"username": "updateduser", "email": "updateduser@example.com"}

    #     response = api_client.put(
    #         self.base_url + "user/update/", update_data, format="json"
    #     )

    #     assert response.status_code == 200
    #     assert json.loads(response.content)["username"] == update_data["username"]
    #     assert json.loads(response.content)["email"] == update_data["email"]
