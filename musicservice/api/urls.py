from django.urls import path, include
from .views import (
    ListUsersView,
    ListSongsView, 
    SongDetailsView, 
    LoginView, 
    RegisterView, 
    ChangePasswordView, 
    LogoutView
)

urlpatterns = [
    path('users/', ListUsersView.as_view(), name="users-all"),
    path('songs/', ListSongsView.as_view(), name="songs-all"),
    path('songs/<int:pk>', SongDetailsView.as_view(), name="song-details"),
    path('auth/login/', LoginView.as_view(), name="auth-login"),
    path('auth/register/', RegisterView.as_view(), name="auth-register"),
    path('auth/reset-password/', ChangePasswordView.as_view(), name="auth-reset-password"),
    path('auth/logout/', LogoutView.as_view(), name="auth-logout")
]