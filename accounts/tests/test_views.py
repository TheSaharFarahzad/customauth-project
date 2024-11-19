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
@pytest.mark.parametrize(
    "register_data,expected_status,expected_errors",
    [
        # Valid registration
        (
            {
                "email": "validuser@example.com",
                "password": "password123",
                "password2": "password123",
                "first_name": "Valid",
                "last_name": "User",
            },
            201,
            None,
        ),
        # Password mismatch
        (
            {
                "email": "mismatchuser@example.com",
                "password": "password123",
                "password2": "password456",
                "first_name": "Mismatch",
                "last_name": "User",
            },
            400,
            ["password2"],
        ),
        # Missing fields
        (
            {
                "email": "",
                "password": "password123",
                "first_name": "",
                "last_name": "",
            },
            400,
            ["email", "first_name", "last_name"],
        ),
    ],
)
def test_register_user(api_client, register_data, expected_status, expected_errors):
    register_url = reverse("register")
    response = api_client.post(register_url, data=register_data)

    assert response.status_code == expected_status
    if expected_errors:
        for field in expected_errors:
            assert field in response.data


@pytest.mark.django_db
@patch("accounts.views.send_email")
@pytest.mark.parametrize(
    "uid,token,expected_status,expected_detail",
    [
        # Successful verification
        (
            lambda user: urlsafe_base64_encode(str(user.pk).encode()),
            lambda user: default_token_generator.make_token(user),
            200,
            "Email verified successfully.",
        ),
        # Invalid token
        (
            lambda user: urlsafe_base64_encode(str(user.pk).encode()),
            lambda user: "invalid-token",
            400,
            "Invalid or expired token.",
        ),
        # Non-existent user
        (
            lambda user: urlsafe_base64_encode(b"9999"),  # UID for non-existent user
            lambda user: default_token_generator.make_token(user),
            404,
            "No CustomUser matches the given query.",
        ),
    ],
)
def test_verify_register(
    mock_send_email,
    api_client,
    create_user,
    uid,
    token,
    expected_status,
    expected_detail,
):
    # Step 1: Create a user for cases where user is needed
    user = create_user(email="testuser@example.com", email_verified=False)

    # Step 2: Calculate the UID and token based on the user
    generated_uid = uid(user)
    generated_token = token(user)

    # Step 3: Simulate email verification request
    verify_url = reverse("verify-email")
    verify_data = {"uid": generated_uid, "token": generated_token}
    response = api_client.post(verify_url, data=verify_data)

    # Step 4: Assert the expected outcome
    assert response.status_code == expected_status
    assert response.data["detail"] == expected_detail

    # Additional check for successful verification
    if expected_status == 200:
        user.refresh_from_db()
        assert user.email_verified is True


@pytest.mark.django_db
@patch("accounts.views.send_email")
@pytest.mark.parametrize(
    "email_verified,exists,expected_status,expected_detail,mock_email_called",
    [
        # User exists and is not verified
        (
            False,
            True,
            200,
            "Verification email resent.",
            True,
        ),
        # User already verified
        (
            True,
            True,
            400,
            "Email is already verified.",
            False,
        ),
        # User does not exist
        (
            False,
            False,
            400,
            "User with this email does not exist.",
            False,
        ),
    ],
)
def test_resend_verification_email(
    mock_send_email,
    api_client,
    create_user,
    email_verified,
    exists,
    expected_status,
    expected_detail,
    mock_email_called,
):
    # Step 1: Set up the user if it exists
    if exists:
        user = create_user(email_verified=email_verified)
        email = user.email
    else:
        email = "nonexistent@example.com"

    # Step 2: Attempt to resend verification email
    resend_url = reverse("resend-verification")
    response = api_client.post(resend_url, data={"email": email})

    # Debugging response for unexpected formats or errors
    print("Response status code:", response.status_code)
    print("Response data:", response.data)

    # Step 3: Assert the expected response
    assert response.status_code == expected_status

    if "detail" in response.data:
        # View explicitly returned a "detail" message
        assert response.data["detail"] == expected_detail
    elif "email" in response.data:
        # Serializer validation error
        assert response.data["email"][0] == expected_detail
    else:
        assert False, f"Unexpected response format: {response.data}"

    assert mock_send_email.called == mock_email_called


@pytest.mark.django_db
@pytest.mark.parametrize(
    "login_data,expected_status,expected_keys",
    [
        # Valid login
        (
            {"email": "test@example.com", "password": "password123"},
            status.HTTP_200_OK,
            ["access", "refresh"],
        ),
        # Invalid email
        (
            {"email": "invalid@example.com", "password": "password123"},
            status.HTTP_400_BAD_REQUEST,
            None,
        ),
        # Invalid password
        (
            {"email": "test@example.com", "password": "wrongpassword"},
            status.HTTP_400_BAD_REQUEST,
            None,
        ),
    ],
)
def test_login(api_client, create_user, login_data, expected_status, expected_keys):
    if login_data["email"] == "test@example.com":
        create_user(email="test@example.com", password="password123")

    url = reverse("login")
    response = api_client.post(url, data=login_data)

    assert response.status_code == expected_status
    if expected_keys:
        for key in expected_keys:
            assert key in response.data


@pytest.mark.django_db
@pytest.mark.parametrize(
    "authenticated, expected_status",
    [
        # Authenticated user logs out
        (
            True,
            status.HTTP_200_OK,
        ),
        # Unauthenticated user tries to log out
        (
            False,
            status.HTTP_401_UNAUTHORIZED,
        ),
    ],
)
def test_logout(api_client, create_user, authenticated, expected_status):
    # Step 1: Set up the user and authentication if needed
    if authenticated:
        user = create_user(email="test@example.com", password="password123")
        api_client.force_authenticate(user=user)

    # Step 2: Attempt to log out
    url = reverse("logout")
    response = api_client.post(url)

    # Step 3: Assert the expected response status
    assert response.status_code == expected_status


@pytest.mark.django_db
@pytest.mark.parametrize(
    "old_password,new_password,expected_status,check_new_password",
    [
        # Valid old password
        (
            "password123",
            "newpassword123",
            status.HTTP_200_OK,
            True,
        ),
        # Invalid old password
        (
            "wrongpassword",
            "newpassword123",
            status.HTTP_400_BAD_REQUEST,
            False,
        ),
    ],
)
def test_change_password(
    api_client,
    create_user,
    old_password,
    new_password,
    expected_status,
    check_new_password,
):
    user = create_user(email="test@example.com", password="password123")
    api_client.force_authenticate(user=user)

    url = reverse("change_password")
    data = {"old_password": old_password, "new_password": new_password}
    response = api_client.post(url, data)

    assert response.status_code == expected_status
    if check_new_password:
        user.refresh_from_db()
        assert user.check_password(new_password) is True
    else:
        assert not user.check_password(new_password)


@pytest.mark.django_db
@patch("accounts.views.send_email")
@pytest.mark.parametrize(
    "email, exists, expected_status, mock_email_called, expected_subject, expected_body",
    [
        # Valid email, user exists
        (
            "test@example.com",
            True,
            status.HTTP_200_OK,
            True,
            "Reset Your Password",
            "accounts/password_reset_email.html",
        ),
        # Invalid email, user does not exist
        (
            "nonexistent@example.com",
            False,
            status.HTTP_400_BAD_REQUEST,
            False,
            None,
            None,
        ),
        # Empty email
        (
            "",
            False,
            status.HTTP_400_BAD_REQUEST,
            False,
            None,
            None,
        ),
        # User exists, but email is already reset
        (
            "reset@example.com",
            True,
            status.HTTP_200_OK,
            True,
            "Reset Your Password",
            "accounts/password_reset_email.html",
        ),
    ],
)
def test_password_reset(
    mock_send_email,
    api_client,
    create_user,
    email,
    exists,
    expected_status,
    mock_email_called,
    expected_subject,
    expected_body,
):
    # Arrange: Create user if exists
    if exists:
        user = create_user(email=email, password="password123")
    else:
        user = None  # No user will be created if the email doesn't exist

    # Act: Make a password reset request
    url = reverse("reset_password")
    response = api_client.post(url, {"email": email})

    # Assert: Check the response status
    assert response.status_code == expected_status

    # Check if email was sent based on the scenario
    if mock_email_called:
        mock_send_email.assert_called_once()
        called_args, called_kwargs = mock_send_email.call_args
        assert called_kwargs["subject"] == expected_subject
        assert called_kwargs["body"] == expected_body
        assert called_kwargs["recipient_list"] == [email]
        assert "context" in called_kwargs
        assert "user" in called_kwargs["context"]
        assert "reset_link" in called_kwargs["context"]
    else:
        mock_send_email.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "test_uid, test_token, new_password, confirm_password, expected_status, expected_detail, mock_email_called",
    [
        # Successful password reset confirmation
        (
            "valid_uid",
            "valid_token",
            "newpassword123",
            "newpassword123",
            status.HTTP_200_OK,
            "Password reset successful.",
            False,  # Email not called in this case
        ),
        # Invalid token case
        (
            "valid_uid",
            "invalid_token",
            "newpassword123",
            "newpassword123",
            status.HTTP_400_BAD_REQUEST,
            "Invalid token.",
            False,  # Email not called in this case
        ),
        # User not found for uid
        (
            "non_existent_uid",
            "valid_token",
            "newpassword123",
            "newpassword123",
            status.HTTP_400_BAD_REQUEST,
            "Invalid user or token.",
            False,
        ),
        # Passwords do not match
        (
            "valid_uid",
            "valid_token",
            "newpassword123",
            "mismatchpassword",
            status.HTTP_400_BAD_REQUEST,
            "Passwords do not match.",
            False,
        ),
        # Empty new password field
        (
            "valid_uid",
            "valid_token",
            "",
            "newpassword123",
            status.HTTP_400_BAD_REQUEST,
            "This field may not be blank.",
            False,
        ),
        # Empty confirm password field
        (
            "valid_uid",
            "valid_token",
            "newpassword123",
            "",
            status.HTTP_400_BAD_REQUEST,
            "This field may not be blank.",
            False,
        ),
        # Both fields empty
        (
            "valid_uid",
            "valid_token",
            "",
            "",
            status.HTTP_400_BAD_REQUEST,
            "This field may not be blank.",
            False,
        ),
    ],
)
@patch("django.core.mail.send_mail")
def test_password_reset_confirm5(
    mock_send_email,
    api_client,
    create_user,
    test_uid,
    test_token,
    new_password,
    confirm_password,
    expected_status,
    expected_detail,
    mock_email_called,
):
    # Arrange: Create a user and generate valid uidb64 and token for a real password reset
    user = create_user(email="test@example.com", password="oldpassword123")

    # Trigger password reset email
    url_reset = reverse("reset_password")
    response_reset = api_client.post(url_reset, data={"email": user.email})

    assert response_reset.status_code == status.HTTP_200_OK
    assert "message" in response_reset.data

    # Generate valid uidb64 and token for the user
    uidb64 = (
        urlsafe_base64_encode(str(user.pk).encode())
        if test_uid == "valid_uid"
        else test_uid
    )
    token = (
        default_token_generator.make_token(user)
        if test_token == "valid_token"
        else test_token
    )

    # Act: Post to password reset confirm
    url_confirm = reverse("confirm_reset_password", args=[uidb64, token])
    response_confirm = api_client.post(
        url_confirm,
        data={"new_password": new_password, "confirm_password": confirm_password},
    )

    # Assert: Check if the response contains expected status and detail
    assert response_confirm.status_code == expected_status

    if expected_status == status.HTTP_200_OK:
        assert response_confirm.data["detail"] == expected_detail
        user.refresh_from_db()
        assert user.check_password(new_password)
    elif expected_status == status.HTTP_400_BAD_REQUEST:
        if "detail" in response_confirm.data:
            assert response_confirm.data["detail"] == expected_detail
        elif "non_field_errors" in response_confirm.data:
            assert response_confirm.data["non_field_errors"][0] == expected_detail
        elif "new_password" in response_confirm.data:
            assert response_confirm.data["new_password"][0] == expected_detail
        elif "confirm_password" in response_confirm.data:
            assert response_confirm.data["confirm_password"][0] == expected_detail
        else:
            raise AssertionError(
                f"Expected error detail '{expected_detail}' not found in response: {response_confirm.data}"
            )

    # If an email should have been sent, check if send_email was called
    if mock_email_called:
        mock_send_email.assert_called_once()
    else:
        mock_send_email.assert_not_called()


# @pytest.mark.django_db
# def test_user_profile_view(api_client, create_user):
#     user = create_user(email="test@example.com", password="password123")
#     api_client.force_authenticate(user=user)

#     url = reverse("user_profile")
#     response = api_client.get(url)

#     assert response.status_code == status.HTTP_200_OK
