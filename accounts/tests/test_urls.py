from django.urls import reverse, resolve
from ..views import (
    RegisterAPIView,
    RegisterVerifyAPIView,
    ResendVerificationAPIView,
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView,
    PasswordResetConfirmView,
    UserProfileView,
)
import pytest


@pytest.mark.parametrize(
    "url_name, view_class, args",
    [
        ("register", RegisterAPIView, []),
        ("register-verify", RegisterVerifyAPIView, []),
        ("register-resend-verification", ResendVerificationAPIView, []),
        ("login", LoginView, []),
        ("logout", LogoutView, []),
        ("password-change", PasswordChangeView, []),
        ("password-reset", PasswordResetView, []),
        ("profile", UserProfileView, []),
        ("password-reset-confirm", PasswordResetConfirmView, ["uidb64", "token"]),
    ],
)
def test_url_resolves_correct_view(url_name, view_class, args):
    """
    Test that the URL resolves to the correct view.
    """
    # If the URL requires arguments, pass them when reversing
    if args:
        url = reverse(url_name, kwargs={args[0]: "test_uid", args[1]: "test_token"})
    else:
        url = reverse(url_name)

    assert resolve(url).func.view_class == view_class
