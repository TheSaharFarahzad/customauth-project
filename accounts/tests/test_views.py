# 1. Standard library imports
from unittest.mock import patch

# 2. Django imports
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import status
from rest_framework.test import APIClient

# 3. Third-party imports
import pytest
import logging


User = get_user_model()


@pytest.fixture
def api_client():
    """Provides an instance of APIClient."""
    return APIClient()


@pytest.fixture
def create_user(django_user_model):
    """Fixture to create a new user."""

    def _create_user(email, password, **kwargs):
        return django_user_model.objects.create_user(
            email=email, password=password, **kwargs
        )

    return _create_user


@pytest.mark.django_db
@pytest.mark.parametrize(
    "register_data, expected_status, expected_error_field, expected_error_message",
    [
        # Test missing email
        (
            {
                "email": "",
                "password": "password123",
                "password_confirmation": "password123",
                "first_name": "",
                "last_name": "",
            },
            status.HTTP_400_BAD_REQUEST,
            "email",
            "This field may not be blank.",
        ),
        # Test missing password
        (
            {
                "email": "missingfields@example.com",
                "password": "",
                "password_confirmation": "",
                "first_name": "No",
                "last_name": "Password",
            },
            status.HTTP_400_BAD_REQUEST,
            "password",
            "This field may not be blank.",
        ),
        # Test missing password confirmation
        (
            {
                "email": "missingpasswordconfirmation@example.com",
                "password": "password123",
                "first_name": "No",
                "last_name": "Confirmation",
            },
            status.HTTP_400_BAD_REQUEST,
            "password_confirmation",
            "This field is required.",
        ),
        # Test invalid email format
        (
            {
                "email": "invalidemailformat.com",
                "password": "password123",
                "password_confirmation": "password123",
                "first_name": "Invalid",
                "last_name": "Email",
            },
            status.HTTP_400_BAD_REQUEST,
            "email",
            "Enter a valid email address.",
        ),
        # Test email already registered
        (
            {
                "email": "existing@example.com",
                "password": "password123",
                "password_confirmation": "password123",
                "first_name": "Existing",
                "last_name": "User",
            },
            status.HTTP_400_BAD_REQUEST,
            "email",
            "custom user with this email already exists.",
        ),
        # Test weak password (less than 8 characters)
        (
            {
                "email": "weakpassword@example.com",
                "password": "short",
                "password_confirmation": "short",
                "first_name": "Weak",
                "last_name": "Password",
            },
            status.HTTP_400_BAD_REQUEST,
            "password",
            "This password is too short. It must contain at least 8 characters.",
        ),
        # Test weak password (too common)
        (
            {
                "email": "commonpassword@example.com",
                "password": "password123",
                "password_confirmation": "password123",
                "first_name": "Common",
                "last_name": "Password",
            },
            status.HTTP_400_BAD_REQUEST,
            "password",
            "This password is too common.",
        ),
        # Test wrong password confirmation
        (
            {
                "email": "wrongconfirmation@example.com",
                "password": "password123",
                "password_confirmation": "password456",
                "first_name": "Wrong",
                "last_name": "Confirmation",
            },
            status.HTTP_400_BAD_REQUEST,
            "password",
            "Passwords must match.",
        ),
        # Test valid registration (to make sure it's valid)
        (
            {
                "email": "validuser@example.com",
                "password": "Sfrc.453",
                "password_confirmation": "Sfrc.453",
                "first_name": "Valid",
                "last_name": "User",
            },
            status.HTTP_201_CREATED,
            None,
            None,
        ),
    ],
)
@patch("accounts.email.send_email")
def test_register_user(
    mock_send_email,
    api_client,
    register_data,
    expected_status,
    expected_error_field,
    expected_error_message,
    create_user,
):

    logging.basicConfig(
        level=logging.DEBUG,  # format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # If the email is already registered, we don't create a new user for the test
    if expected_error_field == "email" and "existing" in register_data["email"]:
        logging.debug(f"manam sahar dooste shoma {register_data["email"]}")
        # Simulate an already existing user by creating it first
        create_user(register_data["email"], register_data["password"])

    register_url = reverse("register")
    response = api_client.post(register_url, data=register_data)

    # Assert the status code matches the expected status
    assert response.status_code == expected_status

    # If we expect an error, check for the field and the error message
    if expected_error_field:
        assert expected_error_field in response.data
        if expected_error_message:
            assert expected_error_message in str(response.data)


@pytest.mark.django_db
@patch("accounts.views.send_email")
def test_register_and_send_email(mock_send_mail, api_client, create_user):
    # Arrange: Create a user and set up the registration data
    register_url = reverse("register")
    user_data = {
        "email": "newuser@example.com",
        "password": "securepassword123",
        "password_confirmation": "securepassword123",
    }

    # Act: Register the user via the API
    response = api_client.post(register_url, user_data, format="json")

    # Assert: Check if the user was created and response is correct and send_mail was called
    assert response.status_code == status.HTTP_201_CREATED
    assert User.objects.filter(email=user_data["email"]).exists()
    mock_send_mail.assert_called_once()
    mock_send_mail.assert_called_with(
        subject="Verify Your Email",
        body="emails/verify_email.html",
        context={
            "token": mock_send_mail.call_args[1]["context"]["token"],
            "uid": mock_send_mail.call_args[1]["context"]["uid"],
            "user": mock_send_mail.call_args[1]["context"]["user"],
        },
        recipient_list=["newuser@example.com"],
    )


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
            lambda user: "invalid-token",  # Manually providing an invalid token
            400,
            "Invalid or expired token.",
        ),
        # Non-existent user
        (
            lambda user: urlsafe_base64_encode(b"9999"),  # UID for non-existent user
            lambda user: default_token_generator.make_token(user),
            400,
            "Invalid UID.",
        ),
        # Malformed UID
        (
            lambda user: "invalid-uid",  # Providing a malformed UID
            lambda user: default_token_generator.make_token(user),
            400,
            "Invalid UID.",
        ),
    ],
)
def test_register_verify(
    mock_send_mail,
    api_client,
    create_user,
    uid,
    token,
    expected_status,
    expected_detail,
):
    # Step 1: Create a user and simulate registration
    register_url = reverse("register")
    user_data = {
        "email": "newuser@example.com",
        "password": "securepassword123",
        "password_confirmation": "securepassword123",
    }
    response = api_client.post(register_url, user_data, format="json")
    assert response.status_code == status.HTTP_201_CREATED

    # Fetch the user from the database to verify it was created
    user = User.objects.get(email=user_data["email"])
    assert User.objects.filter(email=user_data["email"]).exists()

    # Ensure the email was sent
    mock_send_mail.assert_called_once()
    context = mock_send_mail.call_args[1]["context"]  # Get context from mock call
    assert "token" in context and "uid" in context and "user" in context

    # Step 2: Calculate the UID and token based on the context passed in the email
    generated_uid = context["uid"]
    generated_token = context["token"]

    # Step 3: Simulate email verification request with the correct token and uid for successful test
    # For invalid test cases, use the manually supplied invalid token/uid from parametrize
    verify_url = reverse("register-verify")
    verify_data = (
        {"uid": generated_uid, "token": generated_token}
        if expected_status == 200
        else {
            "uid": uid(user),
            "token": token(user),  # Inject invalid uid/token manually for failing cases
        }
    )
    response = api_client.post(verify_url, data=verify_data)

    # Step 4: Assert the expected outcome
    assert response.status_code == expected_status
    assert response.data["detail"] == expected_detail

    # Step 5: Additional check for successful verification
    if expected_status == 200:
        user.refresh_from_db()  # Reload user from database
        assert user.email_verified is True


@pytest.mark.django_db
@patch("accounts.views.send_email")
@pytest.mark.parametrize(
    "uid,token,expected_status,expected_detail",
    [
        # Missing UID
        (
            lambda user: None,
            lambda user: default_token_generator.make_token(user),
            400,
            "This field is required.",
        ),
        # Missing token
        (
            lambda user: urlsafe_base64_encode(str(user.pk).encode()),
            lambda user: None,
            400,
            "This field is required.",
        ),
        # Missing both UID and token
        (
            lambda user: None,
            lambda user: None,
            400,
            "This field is required.",
        ),
    ],
)
def test_register_verify_missing_fields(
    mock_send_mail,
    api_client,
    create_user,
    uid,
    token,
    expected_status,
    expected_detail,
):
    # Step 1: Create a user and simulate registration
    register_url = reverse("register")
    user_data = {
        "email": "newuser@example.com",
        "password": "securepassword123",
        "password_confirmation": "securepassword123",
    }
    response = api_client.post(register_url, user_data, format="json")
    assert response.status_code == status.HTTP_201_CREATED

    # Fetch the user from the database to verify it was created
    user = User.objects.get(email=user_data["email"])
    assert User.objects.filter(email=user_data["email"]).exists()

    # Ensure the email was sent
    mock_send_mail.assert_called_once()
    context = mock_send_mail.call_args[1]["context"]  # Get context from mock call
    assert "token" in context and "uid" in context and "user" in context

    # Step 2: Calculate the UID and token based on the context passed in the email
    generated_uid = context["uid"]
    generated_token = context["token"]

    # Step 3: Simulate email verification request with missing fields
    verify_url = reverse("register-verify")

    # Determine if uid or token is missing and create verify_data accordingly
    verify_data = {}
    if uid(user) is not None:
        verify_data["uid"] = uid(user)
    if token(user) is not None:
        verify_data["token"] = token(user)

    response = api_client.post(verify_url, data=verify_data)

    # Step 4: Assert the expected outcome (adjusted for missing fields)
    assert response.status_code == expected_status

    # Check if 'uid' or 'token' field is in response.data and validate the error message
    if "uid" in response.data:
        assert response.data["uid"][0] == expected_detail
    if "token" in response.data:
        assert response.data["token"][0] == expected_detail


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
            "Verification email resent successfully.",
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
def test_register_resend_verification_email(
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
        user = User.objects.create_user(
            email="testuser@example.com", password="testpassword"
        )
        user.email_verified = email_verified
        user.save()
        email = user.email
    else:
        email = "nonexistent@example.com"  # Non-existent user

    # Step 2: Attempt to resend verification email
    resend_url = reverse("register-resend-verification")  # Correct URL
    response = api_client.post(resend_url, data={"email": email})

    # Step 3: Assert the expected response
    assert response.status_code == expected_status

    if expected_status == 200:
        # If the status is 200, check that the success message is returned
        assert response.data["detail"] == expected_detail
    elif expected_status == 400:
        # If the status is 400, check that the validation error message is returned
        if "email" in response.data:
            assert response.data["email"][0] == expected_detail
        else:
            assert response.data["detail"] == expected_detail

    # Step 4: Assert whether the email was sent
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
            status.HTTP_401_UNAUTHORIZED,
            None,
        ),
        # Invalid password
        (
            {"email": "test@example.com", "password": "wrongpassword"},
            status.HTTP_401_UNAUTHORIZED,
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
    "authenticated, refresh_token, expected_status, expected_message",
    [
        # Authenticated user logs out with a valid refresh token
        (
            True,
            "valid-refresh-token",
            status.HTTP_200_OK,
            "Successfully logged out.",
        ),
        # Authenticated user logs out with an invalid refresh token
        (
            True,
            "invalid-refresh-token",
            status.HTTP_400_BAD_REQUEST,
            "Invalid token.",
        ),
        # Unauthenticated user tries to log out
        (
            False,
            None,
            status.HTTP_401_UNAUTHORIZED,
            "Authentication credentials were not provided.",
        ),
        # Authenticated user logs out without providing a refresh token
        (
            True,
            None,
            status.HTTP_400_BAD_REQUEST,
            "Refresh token required.",
        ),
    ],
)
def test_logout(
    api_client,
    create_user,
    authenticated,
    refresh_token,
    expected_status,
    expected_message,
):
    # Step 1: Set up the user and authentication if needed
    if authenticated:
        user = create_user(email="test@example.com", password="password123")
        api_client.force_authenticate(user=user)

    # Step 2: Prepare the payload
    payload = {}
    if refresh_token:
        payload["refresh_token"] = refresh_token

    # Step 3: Mock the RefreshToken and its blacklist method
    with patch("accounts.views.RefreshToken") as MockRefreshToken:
        mock_token = MockRefreshToken.return_value
        # Mock the behavior of the blacklist method
        if refresh_token == "valid-refresh-token":
            mock_token.blacklist.return_value = None  # Simulate successful blacklisting
        else:
            mock_token.blacklist.side_effect = Exception(
                "Invalid token"
            )  # Simulate invalid token error

        # Step 4: Attempt to log out
        url = reverse("logout")
        response = api_client.post(url, data=payload)

        # Step 5: Assert the expected response status and message
        assert response.status_code == expected_status
        assert expected_message in response.data.values()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "old_password, new_password, expected_status, check_new_password",
    [
        # Valid password change
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
        # New password is the same as the old one
        (
            "password123",
            "password123",
            status.HTTP_400_BAD_REQUEST,
            False,
        ),
        # Missing new password (serializer validation should catch this)
        (
            "password123",
            "",
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
    # Create user and authenticate
    user = create_user(email="test@example.com", password="password123")
    api_client.force_authenticate(user=user)

    # URL for the password change view
    url = reverse("password-change")

    # Prepare data for the request
    data = {"old_password": old_password, "new_password": new_password}

    # Send PUT request to change password
    response = api_client.put(url, data)

    # Assert the response status
    assert response.status_code == expected_status

    # If password change was successful (status 200), check the new password
    if expected_status == status.HTTP_200_OK:
        user.refresh_from_db()
        assert user.check_password(new_password) is True
    elif expected_status == status.HTTP_400_BAD_REQUEST:
        # Ensure the password has not been updated and remains the old one
        user.refresh_from_db()
        if old_password == "wrongpassword":
            # If the old password is incorrect, ensure the original password is still there
            assert user.check_password("password123") is True
        else:
            # Other validation failure cases (like the same old and new password)
            assert user.check_password(old_password) is True


@pytest.mark.django_db
def test_change_password_unauthenticated(api_client):
    """
    Test that an unauthenticated user cannot change the password.
    """
    url = reverse("password-change")
    data = {"old_password": "password123", "new_password": "newpassword123"}

    # Make a request without authentication
    response = api_client.put(url, data)

    # Assert that the response is unauthorized
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data


@pytest.mark.django_db
@patch("django.core.mail.EmailMessage.send")
@pytest.mark.parametrize(
    "email, exists, is_active, expected_status, mock_email_called",
    [
        # Valid email, user exists, and is active - email should be sent.
        (
            "test@example.com",
            True,
            True,
            200,
            True,
        ),
        # Valid email, but user does not exist - should return 400 and not send email.
        (
            "nonexistent@example.com",
            False,
            True,
            400,
            False,
        ),
        # Empty email - should return 400 and not send email.
        (
            "",
            False,
            True,
            400,
            False,
        ),
        # Valid email, user exists, but is inactive - should return 400 and not send email.
        (
            "inactive@example.com",
            True,
            False,
            400,
            False,
        ),
        # Invalid email format - should return 400 and not send email.
        (
            "invalid-email",
            False,
            True,
            400,
            False,
        ),
    ],
)
def test_password_reset(
    mock_email_send,
    api_client,
    create_user,
    email,
    exists,
    is_active,
    expected_status,
    mock_email_called,
):
    """
    Test the password reset endpoint with various email inputs and user states.
    """
    # If the user should exist, create a user with the specified email and active state.
    if exists:
        create_user(email=email, password="password123", is_active=is_active)

    # Make a POST request to the password reset endpoint with the provided email.
    url = reverse("password-reset")
    response = api_client.post(url, {"email": email})

    # Assert the response status matches the expected status.
    assert response.status_code == expected_status

    # Assert whether the email sending logic was triggered based on expectations.
    if mock_email_called:
        mock_email_send.assert_called_once()
    else:
        mock_email_send.assert_not_called()


@pytest.mark.django_db
@patch("accounts.email.send_email")
def test_password_reset_email(mock_send_email, api_client, create_user):

    user = create_user(email="test@example.com", password="oldpassword123")
    url = reverse("password-reset")
    response = api_client.post(url, {"email": user.email})
    assert response.status_code == 200
    assert "Password reset email sent." in response.data.get("message", "")

    # Simulate valid UID and token (mocked for the test)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))  # Mocked UID encoding
    token = "valid-token"  # This should be a valid token generated in your app

    # Prepare the data for the request
    data = {
        "new_password": "newpassword123",
        "confirm_password": "newpassword123",
        "uidb64": uidb64,
        "token": token,
    }

    # Call the password reset confirm view
    url = reverse("password-reset-confirm", kwargs={"uidb64": uidb64, "token": token})
    response = api_client.post(url, data)

    # Assert: Check if the response is correct and send_email was called
    assert response.status_code == 200
    assert "Password reset successful." in response.data.get("message", response.data)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "new_password, confirm_password, expected_status, error_field, expected_message",
    [
        # Valid password reset
        (
            "newpassword123",
            "newpassword123",
            200,
            "message",
            "Password reset successful.",
        ),
        # Passwords do not match
        (
            "newpassword123",
            "differentpassword123",
            400,
            "password",
            "Passwords must match.",
        ),
        # New password is too short
        (
            "short",
            "short",
            400,
            "new_password",
            "Password must be at least 8 characters long.",
        ),
        # New password is same as old password
        (
            "oldpassword123",
            "oldpassword123",
            400,
            "new_password",
            "New password cannot be the same as the old one.",
        ),
        # Missing required fields
        (
            "",
            "",
            400,
            "new_password",
            "This field may not be blank.",
        ),
    ],
)
@patch("accounts.email.send_email")
def test_password_reset_confirm(
    mock_send_email,
    api_client,
    create_user,
    new_password,
    confirm_password,
    expected_status,
    error_field,
    expected_message,
):
    # Create a valid user for testing
    user = create_user(email="test@example.com", password="oldpassword123")

    # Simulate valid UID and token (mocked for the test)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))  # Mocked UID encoding
    token = "valid-token"  # This should be a valid token generated in your app

    # Prepare the data for the request
    data = {
        "new_password": new_password,
        "confirm_password": confirm_password,
        "uidb64": uidb64,
        "token": token,
    }

    # Call the password reset confirm view
    url = reverse("password-reset-confirm", kwargs={"uidb64": uidb64, "token": token})
    response = api_client.post(url, data)

    # Assert the response status code
    assert response.status_code == expected_status

    # For error status codes, check for error message in the specified error field
    if expected_status == 400:
        # Get the error details from the response
        error_field_data = response.data.get(error_field)

        # If the error is a dictionary (nested error structure), get the specific error message
        if isinstance(error_field_data, dict):
            # Check if the error is inside the nested dictionary under the same error field
            error_field_data = error_field_data.get(error_field, "")

        assert expected_message in str(error_field_data)
    else:
        # For successful responses, check the message in the response
        assert expected_message in response.data.get(error_field, response.data)
