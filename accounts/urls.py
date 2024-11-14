# 1. Django imports
from django.urls import path

# 2. Local imports (your views from the same app)
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    ChangePasswordView,
    UserProfileView,
    UpdateUserProfileView,
)


urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("password/change/", ChangePasswordView.as_view(), name="change_password"),
    path("user/", UserProfileView.as_view(), name="user_profile"),
    path("user/update/", UpdateUserProfileView.as_view(), name="update_user_profile"),
]
