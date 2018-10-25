from rest_framework import serializers
from .models import Songs
from django.contrib.auth.models import User

class SongSerializer(serializers.ModelSerializer):

    class Meta:
        model = Songs
        fields = '__all__'


class TokenSerializer(serializers.Serializer):
    """
    This serializer serializes the token data
    """
    token = serializers.CharField(max_length=255)

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ("username","email","password")

class ChangePasswordSerializer(serializers.Serializer):
    """This serializes the passwords submitted"""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
