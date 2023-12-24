from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate, login, logout
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import date, timedelta

from .models import CustomUser, OTP
from .utils import send_password_reset_mail, generate_email_token, unscramble_email_token
from .serializers import (
    UserSerializer, CurrentUserSerializer, LoginUserSerializer, 
    LogoutSerializer, PasswordTokenRequestSerializer,
    PasswordTokenConfirmSerializer, PasswordResetSerializer
)
    

@extend_schema(tags=["User Auth"])
class RegisterUserView(generics.CreateAPIView):
    """Endpoint to register a new user"""
    serializer_class = UserSerializer
    queryset = CustomUser.objects.all()
    permission_classes = [AllowAny]
    
    @extend_schema(
        summary="Register User",
        description="This is POST Method in which user data is created",
        request=UserSerializer,
        responses={
            201: OpenApiResponse(description='Json Response'),
            400: OpenApiResponse(description='Validation error')
        }
    )
    def create(self, request, *args, **kwargs):
        """Register new user"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.save()
        
        response = {
            "message": "User created successfully",
            "status": status.HTTP_201_CREATED,
            "response": serializer.data
        }
        return Response(response, status=status.HTTP_201_CREATED)


@extend_schema(tags=["User Detail"])
class UserRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """Get, Update and Delete current user"""
    serializer_class = CurrentUserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        return self.request.user
    
    def retrieve(self, request, *args, **kwargs):
        """Get current user"""
        object = self.get_object()
        serializer = self.get_serializer(object)
        response = {
            "message": "User data fetched successfully",
            "statusCode": status.HTTP_200_OK,
            "data": serializer.data
        }
        return Response(response, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        """update current user"""
        partial = kwargs.pop('partial', False)
        
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        response = {
            "message": "User data updated successfully",
            "statusCode": status.HTTP_200_OK,
            "data": serializer.data
        }
        return Response(response, status=status.HTTP_200_OK)
        
    def perform_update(self, instance):
        """save updated instance"""
        instance.save()
    
    def destroy(self, request, *args, **kwargs):
        """delete current user"""
        instance = self.get_object()
        self.perform_destroy(instance)
        response = {
            'message': "User deleted successfully",
            "statusCode": status.HTTP_204_NO_CONTENT,
        }
        return Response(response, status=status.HTTP_204_NO_CONTENT)
    
    def perform_destroy(self, instance):
        instance.delete()
    

@extend_schema(tags=["User Auth"])
class UserLoginView(generics.GenericAPIView):
    """Endpoint to authenticate users using login and password"""
    permission_classes = [AllowAny]
    serializer_class = LoginUserSerializer
    
    def post(self, request, *args, **kwargs):
        """login users"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        serializer = UserSerializer(user)
        token = RefreshToken.for_user(user)
        data = serializer.data
        data["token"] = {"refresh": str(token), "access": str(token.access_token)}
        return Response(data, status=status.HTTP_200_OK)
    

@extend_schema(tags=["User Auth"])
class LogoutView(generics.GenericAPIView):
    """An endpoint to logout users"""
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer
    
    def post(self, request, *args, **kwargs):
        """blacklist refresh tokens."""
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"Error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

@extend_schema(tags=["Password Reset"])
class PasswordTokenRequestView(generics.GenericAPIView):
    """generate and send password to mail if it exists"""
    serializer_class = PasswordTokenRequestSerializer
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        """generate and send password to mail if it exists"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        send_password_reset_mail(email=email)
        email_token = generate_email_token(email)
        response = {
            "message": "OTP sent successfully",
            "statusCode": status.HTTP_200_OK,
            "data": {
                "email_token": email_token
            }
        }
        return Response(response, status=status.HTTP_200_OK)
        

@extend_schema(tags=["Password Reset"])
class PasswordTokenConfirmView(generics.GenericAPIView):
    """confirm the otp sent to the user"""
    serializer_class = PasswordTokenConfirmSerializer
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        """confirm otp sent to user"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data["otp"]
        email_token = request.data["email_token"]
        email = unscramble_email_token(email_token)
        try:
            otp_object = OTP.objects.get(email=email)
        except OTP.DoesNotExist:
            return Response({"message": "OTP not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if otp_object.expires_at < timezone.now():
            return Response({"message": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)
        
        if otp != otp_object.otp:
            return Response({"Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
        
        otp_object.is_used = True
        otp_object.save()
        
        response = {
            "message": "OTP confirmed",
            "statusCode": status.HTTP_200_OK,
            "email_token": generate_email_token(email)
        }
        return Response(response, status=status.HTTP_200_OK)


@extend_schema(tags=["Password Reset"])
class PasswordResetView(generics.GenericAPIView):
    """Set new password for user"""
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        """set new password for user"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data["password"]
        email_token = request.data["email_token"]
        email = unscramble_email_token(email_token)
        
        if "Error" in email:
            return Response({"message": "Token already expired"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = CustomUser.objects.get(email=email)
            otp = OTP.objects.filter(email=email).first()
        except CustomUser.DoesNotExist:
            return Response({"message": "User with the email not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if otp.is_used:
            user.set_password(password)
            user.save()
        else:
            return Response({"message": "Confirm OTP first!"}, status=status.HTTP_400_BAD_REQUEST)
        
        response = {
            "message": "Password reset successful!",
            "statusCode": status.HTTP_200_OK,
        }
        return Response(response, status=status.HTTP_200_OK)

