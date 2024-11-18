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
    # re_path(
    #     r"^register/verify/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,64})/$",
    #     RegisterVerifyView.as_view(),
    #     name="verify_register",
    # ),
    path(
        "register/verify/<str:uidb64>/<str:token>/",
        RegisterVerifyView.as_view(),
        name="verify_register",
    ),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("password/change/", ChangePasswordView.as_view(), name="change_password"),
    path("password/reset/", PasswordResetView.as_view(), name="reset_password"),
    re_path(
        r"^password/reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,40})/$",
        PasswordResetConfirmView.as_view(),
        name="confirm_reset_password",
    ),
    path("profile/", UserProfileView.as_view(), name="user_profile"),
]
