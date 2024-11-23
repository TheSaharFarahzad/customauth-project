# 1. Django imports
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

# 2. Third-party imports
from rest_framework import serializers
from rest_framework import status, permissions, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# 3. Local imports
from .serializers import (
    RegisterUserSerializer,
    RegisterVerifySerializer,
    ResendVerificationSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    UserProfileSerializer,
)
from .email import send_email


User = get_user_model()


class RegisterAPIView(generics.CreateAPIView):
    """
    Handles user registration and sends an email verification link.
    """

    queryset = User.objects.all()
    serializer_class = RegisterUserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(str(user.pk).encode())
        send_email(
            subject="Verify Your Email",
            body="emails/verify_email.html",
            context={"token": token, "uid": uid, "user": user},
            recipient_list=[user.email],
        )


class RegisterVerifyAPIView(generics.GenericAPIView):
    """
    Verifies the user's email address using a token.
    """

    serializer_class = RegisterVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]

        try:
            user_id = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=user_id)

            if default_token_generator.check_token(user, token):
                user.email_verified = True
                user.save()
                return Response({"detail": "Email verified successfully."})
            else:
                return Response(
                    {"detail": "Invalid or expired token."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (User.DoesNotExist, ValueError):
            return Response(
                {"detail": "Invalid UID."}, status=status.HTTP_400_BAD_REQUEST
            )


class ResendVerificationAPIView(generics.GenericAPIView):
    """
    Resends email verification link.
    """

    serializer_class = ResendVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Use the custom method to get the user
        email = request.data.get("email")
        user = serializer.get_user(email)

        if user is None:
            return Response(
                {"detail": "User with this email does not exist."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.email_verified:
            return Response(
                {"detail": "Email is already verified."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(str(user.pk).encode())
        send_email(
            subject="Resend Verification Email",
            body="emails/verify_email.html",
            context={"token": token, "uid": uid, "user": user},
            recipient_list=[user.email],
        )
        return Response({"detail": "Verification email resent successfully."})


class LoginView(APIView):
    """
    Handles user login and returns JWT tokens.
    """

    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )
        if user:
            refresh = RefreshToken.for_user(user)
            return Response(
                {"access": str(refresh.access_token), "refresh": str(refresh)}
            )
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


class LogoutView(APIView):
    """
    Logs out the user by blacklisting the refresh token.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        if refresh_token:
            try:
                RefreshToken(refresh_token).blacklist()
                return Response({"message": "Successfully logged out."})
            except Exception:
                return Response(
                    {"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )
        return Response(
            {"error": "Refresh token required."}, status=status.HTTP_400_BAD_REQUEST
        )


class PasswordChangeView(generics.UpdateAPIView):
    """
    Allows users to change their password.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"error": "Old password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"message": "Password changed successfully."})


class PasswordResetView(generics.GenericAPIView):
    """
    Initiates the password reset process by sending a reset email.
    """

    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {"detail": "User with this email doesn't exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            send_email(
                subject="Reset Your Password",
                body="emails/password_reset_email.html",
                context={"user": user},
                recipient_list=[email],
            )

            return Response(
                {"message": "Password reset email sent."},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(generics.GenericAPIView):
    """
    Resets the password using a UID and token.
    """

    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, token, *args, **kwargs):
        """
        Handle the password reset request.
        Deserialize data, validate, and save the new password.
        """
        # Initialize the serializer with the incoming data and context
        serializer = self.serializer_class(
            data=request.data, context={"uidb64": uidb64, "token": token}
        )

        # Validate the data
        serializer.is_valid(raise_exception=True)

        # Save the new password
        serializer.save()

        # Return success response
        return Response(
            {"message": "Password reset successful."}, status=status.HTTP_200_OK
        )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Allows authenticated users to retrieve and update their profile.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user.profile
