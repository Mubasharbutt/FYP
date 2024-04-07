from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from accounts.serializers import LoginSerializer, SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserProfileSerializer1, UserRegistrationSerializer
from django.contrib.auth import authenticate
from accounts.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Assuming this is views.py in your app directory
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics, permissions
from django.shortcuts import get_object_or_404

from .models import User, UserProfile  # Import your User model
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import AccessToken
import os

User = get_user_model()

# Ensure you're using the correct User model

# Generate Token Manually
def get_tokens_for_user(user):
  access = AccessToken.for_user(user)
  refresh= RefreshToken.for_user(user)
  

  return {
      'refresh': str(refresh),
      'access': str(access),
  }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

# class UserChangePasswordView(APIView):
#   renderer_classes = [UserRenderer]
#   permission_classes = [IsAuthenticated]
#   def post(self, request, format=None):
#     serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
#     serializer.is_valid(raise_exception=True)
#     return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, *args, **kwargs):
    serializer = SendPasswordResetEmailSerializer(data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)




#________________________________________________________________________________________________________________________
from rest_framework import generics, status
from django.contrib.auth import authenticate, login


class UserProfileListCreateView(generics.ListCreateAPIView):
    serializer_class = UserProfileSerializer1

    def get_queryset(self):
        return UserProfile.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        # Check if the user already has four profiles
        if self.get_queryset().count() >= 4:
            return Response({'detail': 'You can create only four profiles.'}, status=status.HTTP_400_BAD_REQUEST)

        # Set the user field to the main user before saving the profile
        request.data['user'] = request.user.id

        # Create the profile
        return super().create(request, *args, **kwargs)
    
class UserProfileListAPIView(generics.ListAPIView):
    serializer_class = UserProfileSerializer1

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        return UserProfile.objects.filter(user_id=user_id)
    
class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        profile_name = request.data.get('profile_name')
        password = request.data.get('password')

        # Authenticate user using the provided profile credentials
        user = authenticate(request, profile_name=profile_name, password=password)
        print(user)

        if user:
            # If authentication is successful, generate or retrieve the token
            # token, created = Token.objects.get_or_create(user=user)
            token = get_tokens_for_user(user)


            return Response({'detail': 'Login successful','token': token}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

