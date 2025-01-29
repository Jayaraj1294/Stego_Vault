from django.urls import path
from . import views

urlpatterns=[
    path('',views.log,name="log"),
    path('register/',views.reg,name="reg"),
    path('dashboard/',views.dash,name="dash"),
]