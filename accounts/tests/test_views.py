# 1. Standard library imports
from unittest.mock import patch

# 2. Django imports
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from accounts.models import CustomUser

# 3. Third-party imports
import pytest
from rest_framework import status
from rest_framework.test import APIClient


User = get_user_model()


@pytest.fixture
def api_client():
    """Provides an instance of APIClient."""
    return APIClient()


@pytest.fixture
def create_user(db):
    def make_user(email="testuser@example.com", password="password123", **kwargs):
        return User.objects.create_user(email=email, password=password, **kwargs)

    return make_user


@pytest.mark.django_db
@patch("accounts.views.send_email")
def test_register_verify_success(mock_send_email, api_client):
    # Step 1: Register a new user
    register_url = reverse("register")
    register_data = {
        "email": "testuser@example.com",
        "password": "password123",
        "password2": "password123",
        "first_name": "Test",
        "last_name": "User",
    }
    response = api_client.post(register_url, data=register_data, format="json")
    assert response.status_code == 201
    assert CustomUser.objects.filter(email=register_data["email"]).exists()

    # Step 2: Extract UID and token from the mocked email
    user = CustomUser.objects.get(email=register_data["email"])
    assert mock_send_email.called
    email_context = mock_send_email.call_args[1]["context"]
    token = email_context["token"]
    uid = email_context["uid"]
    assert token == default_token_generator.make_token(user)
    assert uid == urlsafe_base64_encode(str(user.pk).encode())

    # Step 3: Verify the email using the token and UID
    verify_url = reverse("verify-email")
    verify_data = {"uid": uid, "token": token}
    response = api_client.post(verify_url, data=verify_data)
    assert response.status_code == 200
    assert response.data["detail"] == "Email verified successfully."

    # Step 4: Ensure user email is marked as verified
    user.refresh_from_db()
    assert user.email_verified is True


@pytest.mark.django_db
def test_register_password_mismatch(api_client):
    register_url = reverse("register")
    register_data = {
        "email": "testuser@example.com",
        "password": "password123",
        "password2": "password456",
        "first_name": "Test",
        "last_name": "User",
    }

    response = api_client.post(register_url, data=register_data)
    assert response.status_code == 400
    assert "password2" in response.data


@pytest.mark.django_db
def test_register_invalid_data(api_client):
    register_url = reverse("register")
    invalid_data = {
        "email": "",
        "password": "password123",
        "first_name": "",
        "last_name": "",
    }

    response = api_client.post(register_url, data=invalid_data)
    assert response.status_code == 400
    assert "email" in response.data
    assert "first_name" in response.data
    assert "last_name" in response.data


@pytest.mark.django_db
@patch("accounts.views.send_email")
def test_register_verify_invalid_token(mock_send_email, api_client):
    # Step 1: Register a new user
    register_url = reverse("register")
    register_data = {
        "email": "testuser@example.com",
        "password": "password123",
        "password2": "password123",
        "first_name": "Test",
        "last_name": "User",
    }
    response = api_client.post(register_url, data=register_data)
    assert response.status_code == 201

    # Step 2: Extract UID but use an invalid token
    user = CustomUser.objects.get(email=register_data["email"])
    uid = urlsafe_base64_encode(str(user.pk).encode())
    invalid_token = "invalid-token"

    # Step 3: Verify email with invalid token
    verify_url = reverse("verify-email")
    verify_data = {"uid": uid, "token": invalid_token}
    response = api_client.post(verify_url, data=verify_data)

    assert response.status_code == 400
    assert response.data["detail"] == "Invalid or expired token."


@pytest.mark.django_db
def test_register_verify_user_not_found(api_client):
    # Step 1: Use a non-existent UID
    non_existent_uid = urlsafe_base64_encode(b"9999")  # UID for a non-existent user
    valid_token = default_token_generator.make_token(CustomUser())  # Dummy token

    # Step 2: Attempt to verify email
    verify_url = reverse("verify-email")
    verify_data = {"uid": non_existent_uid, "token": valid_token}
    response = api_client.post(verify_url, data=verify_data)

    assert response.status_code == 404
    assert response.data["detail"] == "No CustomUser matches the given query."


@pytest.mark.django_db
@patch("accounts.views.send_email")
def test_register_resend_verification_email(mock_send_email, api_client, create_user):
    # Step 1: Create a user without email verification
    user = create_user(email_verified=False)

    # Step 2: Resend verification email
    resend_url = reverse("resend-verification")
    response = api_client.post(resend_url, data={"email": user.email})

    assert response.status_code == 200
    assert response.data["detail"] == "Verification email resent."
    assert mock_send_email.called


@pytest.mark.django_db
@pytest.mark.django_db
def test_login_success(api_client, create_user):
    password = "password123"
    user = create_user(email="test@example.com", password=password)

    url = reverse("login")
    response = api_client.post(url, {"email": user.email, "password": password})

    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data
    assert "refresh" in response.data


@pytest.mark.django_db
def test_login_invalid_credentials(api_client):
    url = reverse("login")
    response = api_client.post(
        url, {"email": "nonexistent@example.com", "password": "password123"}
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_logout_success(api_client, create_user):
    user = create_user(email="test@example.com", password="password123")
    api_client.force_authenticate(user=user)

    url = reverse("logout")
    response = api_client.post(url)

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_change_password_success(api_client, create_user):
    user = create_user(email="test@example.com", password="password123")
    api_client.force_authenticate(user=user)

    url = reverse("change_password")
    data = {"old_password": "password123", "new_password": "newpassword123"}
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_200_OK
    user.refresh_from_db()
    assert user.check_password("newpassword123")


@pytest.mark.django_db
def test_change_password_invalid_old_password(api_client, create_user):
    user = create_user(email="test@example.com", password="password123")
    api_client.force_authenticate(user=user)

    url = reverse("change_password")
    data = {"old_password": "wrongpassword", "new_password": "newpassword123"}
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@patch("accounts.views.send_email")
@pytest.mark.django_db
def test_password_reset_success(mock_send_email, api_client, create_user):
    # Arrange
    user = create_user(email="test@example.com", password="password123")
    url = reverse("reset_password")

    # Act
    response = api_client.post(url, {"email": user.email})

    # Assert
    assert response.status_code == status.HTTP_200_OK

    # Check that send_email was called once
    mock_send_email.assert_called_once()

    # Verify the arguments passed to send_email
    called_args, called_kwargs = mock_send_email.call_args
    assert called_kwargs["subject"] == "Reset Your Password"
    assert called_kwargs["recipient_list"] == [user.email]
    assert called_kwargs["body"] == "accounts/password_reset_email.html"
    assert "context" in called_kwargs
    assert "user" in called_kwargs["context"]
    assert "reset_link" in called_kwargs["context"]


@pytest.mark.django_db
def test_user_profile_view(api_client, create_user):
    user = create_user(email="test@example.com", password="password123")
    api_client.force_authenticate(user=user)

    url = reverse("user_profile")
    response = api_client.get(url)

    assert response.status_code == status.HTTP_200_OK
