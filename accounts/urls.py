# 1. Django imports
from django.urls import path

# 2. Local imports
from .views import (
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


urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("register/verify/", RegisterVerifyAPIView.as_view(), name="register-verify"),
    path(
        "register/resend-verification/",
        ResendVerificationAPIView.as_view(),
        name="register-resend-verification",
    ),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("password/change/", PasswordChangeView.as_view(), name="password-change"),
    path("password/reset/", PasswordResetView.as_view(), name="password-reset"),
    path(
        "password/reset/confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
    path("profile/", UserProfileView.as_view(), name="profile"),
]
