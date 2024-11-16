# 1. Django imports
from django.urls import path, re_path

# 2. Local imports
from .views import (
    RegisterView,
    RegisterVerifyView,
    LoginView,
    LogoutView,
    ChangePasswordView,
    PasswordResetView,
    PasswordResetConfirmView,
    UserProfileView,
)


urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    re_path(
        r"^register/verify/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,64})/$",
        RegisterVerifyView.as_view(),
        name="register_verify",
    ),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("password/change/", ChangePasswordView.as_view(), name="password_change"),
    path("password/reset/", PasswordResetView.as_view(), name="password_reset"),
    re_path(
        r"^password/reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,40})/$",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("profile/", UserProfileView.as_view(), name="user_profile"),
]
