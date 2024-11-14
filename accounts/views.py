# 1. Standard Python imports
from django.contrib.auth import authenticate

# 2. Django REST Framework imports
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

# 3. Third-party imports
from rest_framework_simplejwt.tokens import RefreshToken

# 4. Local imports (imports from your own app)
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    CustomUserSerializer,
)


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User registered successfully!"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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


class LogoutView(GenericAPIView):
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


class UserProfileView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializer

    def get(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateUserProfileView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializer

    def put(self, request):
        serializer = self.get_serializer(request.user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User profile updated successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
