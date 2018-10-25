from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework.generics import (
    ListAPIView,
    RetrieveAPIView,
    ListCreateAPIView, 
    RetrieveUpdateDestroyAPIView, 
    CreateAPIView, 
    UpdateAPIView
)
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from rest_framework.views import status
from .models import Songs, TokenBlackList
from .serializers import SongSerializer, TokenSerializer, UserSerializer, ChangePasswordSerializer

# Get the JWT settings, add these lines after the import/from lines
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

@staticmethod
def confirm_token_is_active(request):

    token = request.META.get('HTTP_AUTHORIZATION')
    # is token in the blacklist?
    token = TokenBlackList.objects.get(token=token)

    if token is None:
        return False
    
    return True


class ListUsersView(ListAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = UserSerializer

# Create your views here.
class ListSongsView(ListCreateAPIView):
    # you can only view the song list if you are authenticated
    permission_classes = (permissions.IsAuthenticated,)

    queryset = Songs.objects.all()
    serializer_class = SongSerializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

class SongDetailsView(RetrieveUpdateDestroyAPIView):

    # you can only view song details if you're authenticated
    permission_classes = (permissions.IsAuthenticated,)
    
    queryset = Songs.objects.all()
    serializer_class = SongSerializer

class LoginView(CreateAPIView):
    """
    POST auth/login/
    """
    # This permission class will overide the global permission
    # class setting
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        # grab credentials from request
        username = request.data.get("username","")
        password = request.data.get("password","")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # login saves the user’s ID in the session,
            # using Django’s session framework.
            login(request, user)

            serializer = TokenSerializer(data={'token': jwt_encode_handler(jwt_payload_handler(user))})

            serializer.is_valid()
            return Response(data={'token':serializer.data})

        return Response(status=status.HTTP_401_UNAUTHORIZED)


class RegisterView(CreateAPIView):

    # Available to all
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):

        #grab user data
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if not username and not password and not email:
            return Response(
                data={'message':'Username, email and password are required for registration'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # create new user
        User.objects.create_user(
            username=username, email=email, password=password
        )

        return Response(status=status.HTTP_201_CREATED)

class ChangePasswordView(UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    def put(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)

        user = User.objects.get(id=request.user.id)
        if serializer.is_valid():
            if not user.check_password(serializer.data.get('old_password')):
                return Response({'old password':['Wrong Old Password']}, status=status.HTTP_400_BAD_REQUEST)
            
            # update user password
            user.set_password(serializer.data.get('new_password'))
            user.save()
            return Response(data={'status':'Password changed successfully'}, status=status.HTTP_202_ACCEPTED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(RetrieveAPIView):

    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):

        # get request token and register it in the blacklist
        token = request.META.get('HTTP_AUTHORIZATION')

        TokenBlackList.objects.create(token=token)

        # logout(request)
        return Response(data={'status':'logged out successfully'})
