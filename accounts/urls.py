from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('users/', views.user_list, name='user_list'),
    path('users/new/', views.user_form, name='user_create'),
    path('users/<int:pk>/edit/', views.user_form, name='user_edit'),
]
