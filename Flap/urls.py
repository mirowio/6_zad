"""
Definition of urls for Flap.
"""

from datetime import datetime
from django.urls import path
from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from app import forms, views


urlpatterns = [
    path('', views.home, name='home'),
    path('rabotaem/', views.rabotaem, name='rabotaem'),
]
