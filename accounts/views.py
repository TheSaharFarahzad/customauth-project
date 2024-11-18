# 1. Django REST Framework imports
from rest_framework import status, permissions
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import Http404

# 2. Third-party imports
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
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


from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.generics import GenericAPIView
import base64
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView
from .serializers import LoginSerializer

User = get_user_model()


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    def get(self, request, uidb64, token):
        try:
            user_id = int(urlsafe_base64_decode(uidb64).decode())
            user = User.objects.get(id=user_id)
        except (User.DoesNotExist, ValueError, TypeError):
            raise Http404("User not found.")

        # Validate the token
        try:
            access_token = AccessToken(token)
            if str(user.id) != str(access_token["user_id"]):
                return Response(
                    {"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )
        except TokenError:
            return Response(
                {"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Activate the user
        user.is_active = True
        user.email_verified = True
        user.save()

        return Response(
            {"detail": "User verified successfully."}, status=status.HTTP_200_OK
        )

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate refresh token
            refresh = RefreshToken.for_user(user)
            verification_token = str(refresh.access_token)

            # Create verification URL
            verification_url = f"{request.scheme}://{request.get_host()}/register/verify/{user.id}/{verification_token}/"

            # Send email
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
    """
    This view verifies a user's email based on a provided token.
    It handles token validation, user retrieval, and email verification.
    """

    def get(self, request, uidb64, token):
        try:
            # Decode the uidb64 to get the user ID
            user_id_from_url = int(base64.urlsafe_b64decode(uidb64).decode("utf-8"))
        except (TypeError, ValueError) as e:
            return Response(
                {"message": f"Invalid user ID: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Validate the token and extract the user ID
            access_token = AccessToken(token)
            user_id_from_token = access_token["user_id"]
        except Exception as e:
            return Response(
                {"message": f"Invalid or expired token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # If the user ID from URL does not match the user ID from the token
        if user_id_from_url != user_id_from_token:
            return Response(
                {"message": "User ID mismatch."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Try to fetch the user from the database using the user ID from the URL
        try:
            user = User.objects.get(id=user_id_from_url)
        except User.DoesNotExist:
            return Response(
                {"message": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        # If the user is found but already verified
        if user.email_verified:
            return Response(
                {"message": "User is already verified."},
                status=status.HTTP_200_OK,
            )

        # Otherwise, verify the user's email and activate the account
        user.email_verified = True
        user.is_active = True
        user.save()

        return Response(
            {"message": "Email verified successfully!"},
            status=status.HTTP_200_OK,
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


# class LoginView(GenericAPIView):
#     serializer_class = LoginSerializer

#     def post(self, request):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         email = serializer.validated_data["email"]
#         password = serializer.validated_data["password"]

#         user = authenticate(email=email, password=password)
#         if user:
#             refresh = RefreshToken.for_user(user)
#             access_token = str(refresh.access_token)
#             return Response(
#                 {"access": access_token, "refresh": str(refresh)},
#                 status=status.HTTP_200_OK,
#             )
#         return Response(
#             {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
#         )


# class LogoutView(APIView):
#     permission_classes = [permissions.IsAuthenticated]

#     def post(self, request):
#         request.user.auth_token.delete()
#         return Response(
#             {"message": "Successfully logged out"}, status=status.HTTP_200_OK
#         )


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
