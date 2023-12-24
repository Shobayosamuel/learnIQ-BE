from rest_framework import serializers
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    """serialize custom user model"""
    password = serializers.CharField(write_only=True)
    
    class Meta:
        """meta class for user model"""
        model = CustomUser
        fields = ["id", "email", "full_name", "phone_number", 'password',]
        
    def create(self, validated_data):
        """create and return user with encrypted password"""
        password = validated_data.pop("password")
        user = CustomUser.objects.create_user(password=password, **validated_data)
        user.save()
        return user
    
        
class CurrentUserSerializer(serializers.ModelSerializer):
    """serializer for the current user"""
    profile_picture = serializers.SerializerMethodField()
    class Meta:
        """meta class for the current user"""
        model = CustomUser
        fields = ["email", "full_name", "phone_number", "profile_picture"]
    
    def get_profile_picture(self, obj) -> str:
        """get complete profile picture link"""
        if obj.profile_picture:
            media_url = settings.MEDIA_URL
            return f"{media_url}{obj.profile_picture}"
        return None
class LoginUserSerializer(serializers.Serializer):
    """serializer for login"""
    email = serializers.EmailField(required=True, write_only=True)
    password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Email not found or password not correct")
            

class LogoutSerializer(serializers.Serializer):
    """serializer for logout"""
    refresh = serializers.CharField()
    
    
class PasswordTokenRequestSerializer(serializers.Serializer):
    """serializer for requesting token"""
    email = serializers.EmailField(required=True)
    
    def validate(self, attrs):
        """check if the email exists"""
        email = attrs.get("email", "")
        if CustomUser.objects.filter(email=email).exists():
            return attrs
        raise serializers.ValidationError("Email not found")
        
        
class PasswordTokenConfirmSerializer(serializers.Serializer):
    """serializer to confirm the otp"""
    otp = serializers.CharField(max_length=6, required=True)
    email_token = serializers.CharField()
    
    
class PasswordResetSerializer(serializers.ModelSerializer):
    """serializer for password reset"""
    email_token = serializers.CharField()
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        """meta class for password reset"""
        model = CustomUser
        fields = ["email_token", "password", "confirm_password"]
    
    def validate(self, attrs):
        """check if the two password fields match"""
        password = attrs.get("password")
        confirm_password = attrs.get("confirm_password")
        
        # check if password field matches
        if password != confirm_password:
            raise serializers.ValidationError("The two password fields did not match")
        return attrs
