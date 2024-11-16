# 1. Django imports
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

# 2. Django REST Framework imports
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

# 3. Local imports
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    CustomUserSerializer,
    StudentProfileSerializer,
    InstructorProfileSerializer,
    ChangePasswordSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
)
from .email import send_email
from .models import CustomUser


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            refresh = RefreshToken.for_user(user)
            verification_token = str(refresh.access_token)

            verification_url = f"{request.scheme}://{request.get_host()}/register/verify/{user.id}/{verification_token}/"

            # Using the custom send_email function
            send_email(
                subject="Account Activation",
                body="register/verify_email_template.html",
                context={"verification_url": verification_url},
                recipient_list=[user.email],
            )

            return Response(
                {
                    "message": "User registered successfully! Please check your email to activate your account."
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterVerifyView(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            access_token = AccessToken(token)

            user = CustomUser.objects.get(id=uidb64)

            if str(user.id) == uidb64:
                user.email_verified = True
                user.is_active = True
                user.save()
                return Response(
                    {"message": "Email verified successfully!"},
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"message": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )

        except CustomUser.DoesNotExist:
            return Response(
                {"message": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except TokenError:
            return Response(
                {"message": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(email=email, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response(
                {"access": access_token, "refresh": str(refresh)},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
        )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
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
