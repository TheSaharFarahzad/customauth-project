import pytest
from django.urls import reverse

from rest_framework import status
from unittest.mock import patch
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
import base64


# Get the custom user model
User = get_user_model()


@pytest.fixture
def api_client():
    from rest_framework.test import APIClient

    return APIClient()


@pytest.fixture
def create_user(db):
    def make_user(email="test@example.com", password="password123", **kwargs):
        return User.objects.create_user(email=email, password=password, **kwargs)

    return make_user


@pytest.mark.django_db
@patch("rest_framework_simplejwt.tokens.AccessToken")
def test_register_verify_success(mock_access_token, create_user, api_client):
    user = create_user(email="test@example.com", password="password123")
    user.is_active = False
    user.save()

    # Create a valid access token for the user
    access_token = AccessToken.for_user(user)

    # Mock the AccessToken class to return the token object
    mock_access_token.return_value = access_token

    # Base64 encode the user ID
    uidb64 = base64.urlsafe_b64encode(str(user.id).encode()).decode("utf-8")

    # Construct the URL with the base64-encoded user ID and the mocked token
    url = reverse("verify_register", args=[uidb64, str(access_token)])

    # Perform the GET request
    response = api_client.get(url)

    # Assert that the status code is 200 OK
    assert response.status_code == status.HTTP_200_OK

    # Refresh user from the database to verify changes
    user.refresh_from_db()
    assert user.is_active
    assert user.email_verified


@pytest.mark.django_db
def test_register_password_mismatch(api_client):
    data = {
        "email": "testuser@example.com",
        "password": "password123",
        "confirm_password": "differentpassword",
    }
    url = reverse("register")
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "password" in response.data


@pytest.mark.django_db
def test_register_invalid_data(api_client):
    data = {"email": "invalid_email", "password": "short", "confirm_password": "short"}
    url = reverse("register")
    response = api_client.post(url, data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data


@pytest.mark.django_db
@patch("rest_framework_simplejwt.tokens.AccessToken")
def test_register_verify_success(mock_access_token, create_user, api_client):
    user = create_user(email="test@example.com", password="password123")
    user.is_active = False
    user.save()

    # Create a valid AccessToken for the user
    access_token = AccessToken.for_user(user)

    # Mock AccessToken to return the valid token
    mock_access_token.return_value = access_token

    # Base64 encode the user ID
    uidb64 = base64.urlsafe_b64encode(str(user.id).encode()).decode("utf-8")

    # Construct the URL with the base64-encoded user ID and the actual token
    url = reverse("verify_register", args=[uidb64, str(access_token)])

    # Perform the GET request
    response = api_client.get(url)

    # Assert that the status code is 200 OK
    assert response.status_code == status.HTTP_200_OK

    # Refresh user from the database to verify changes
    user.refresh_from_db()
    assert user.is_active
    assert user.email_verified


@pytest.mark.django_db
def test_register_verify_invalid_token(api_client):
    # Invalid token scenario
    url = reverse("verify_register", args=["9999", "invalidtoken"])
    response = api_client.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_register_verify_user_not_found(api_client):
    # Create a user with necessary fields (email, first_name, last_name)
    user = User.objects.create_user(
        email="valid@example.com",
        password="password123",
        first_name="John",
        last_name="Doe",
    )

    # Create an access token for the user
    valid_token = AccessToken.for_user(user)

    # Simulate a request with a non-existent user ID (9999)
    non_existent_user_id = 9999
    uidb64 = base64.urlsafe_b64encode(str(non_existent_user_id).encode()).decode(
        "utf-8"
    )
    url = reverse("verify_register", args=[uidb64, str(valid_token)])

    # Perform the GET request
    response = api_client.get(url)

    # Check the content for debugging
    print(response.content)

    # Assert that the status code is 400 (due to user ID mismatch)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


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
