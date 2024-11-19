# 1. Django imports
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import (
    gettext_lazy as _,
    gettext as _,
)
from django.shortcuts import get_object_or_404

# 2. Third-party imports
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken

# 3. Local imports
from .serializers import (
    RegisterSerializer,
    VerifyEmailSerializer,
    ResendVerificationSerializer,
    LoginSerializer,
    CustomUserSerializer,
    StudentProfileSerializer,
    InstructorProfileSerializer,
    ChangePasswordSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
)
from .email import send_email


User = get_user_model()


class RegisterAPIView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Send verification email
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(str(user.pk).encode())
        send_email(
            subject="Verify Your Email",
            body="emails/verify_email.html",
            context={"token": token, "uid": uid, "user": user},
            recipient_list=[user.email],
        )
        return Response(
            {
                "detail": "Registration successful. Check your email to verify your account."
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyEmailAPIView(GenericAPIView):
    serializer_class = VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        user_id = urlsafe_base64_decode(uid).decode()
        user = get_object_or_404(User, pk=user_id)

        if default_token_generator.check_token(user, token):
            user.email_verified = True
            user.save()
            return Response(
                {"detail": "Email verified successfully."}, status=status.HTTP_200_OK
            )
        return Response(
            {"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST
        )


class ResendVerificationAPIView(GenericAPIView):
    serializer_class = ResendVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        if user.email_verified:
            return Response(
                {"detail": "Email already verified."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Resend verification email
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(str(user.pk).encode())
        send_email(
            subject="Resend Verification Email",
            body="emails/verify_email.html",
            context={"token": token, "uid": uid, "user": user},
            recipient_list=[user.email],
        )
        return Response(
            {"detail": "Verification email resent."}, status=status.HTTP_200_OK
        )


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        # Validate the input data using the serializer
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Extract the email and password from the validated data
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        # Authenticate the user using the provided credentials
        user = authenticate(request, email=email, password=password)

        # Check if the user is authenticated
        if user is not None:
            # Generate tokens if authentication is successful
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response(
                {"access": access_token, "refresh": str(refresh)},
                status=status.HTTP_200_OK,
            )

        # Return an error response if authentication fails
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_400_BAD_REQUEST,
        )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Invalidate the token manually if using a custom system
        refresh_token = request.data.get("refresh_token")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception:
                return Response(
                    {"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
                )
        return Response(
            {"message": "Successfully logged out"}, status=status.HTTP_200_OK
        )


class ChangePasswordView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.validated_data["old_password"]):
                return Response(
                    {"error": "Old password is incorrect"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.set_password(serializer.validated_data["new_password"])
            user.save()
            return Response(
                {"message": "Password changed successfully"}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(str(user.id).encode())

            reset_link = f"{request.build_absolute_uri('/password/reset/confirm/')}{uidb64}/{token}/"

            send_email(
                subject="Reset Your Password",
                body="accounts/password_reset_email.html",
                context={"user": user, "reset_link": reset_link},
                recipient_list=[user.email],
            )

            return Response(
                {"message": "Password reset email sent successfully."},
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, token):
        try:
            user_id = urlsafe_base64_decode(uidb64).decode()
            user = get_user_model().objects.get(id=user_id)

            if not default_token_generator.check_token(user, token):
                return Response(
                    {"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )

            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=user)

                return Response(
                    {"detail": "Password reset successful."}, status=status.HTTP_200_OK
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.is_student:
            serializer = StudentProfileSerializer(user.student)
        elif user.is_instructor:
            serializer = InstructorProfileSerializer(user.instructor)
        else:
            serializer = CustomUserSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)
