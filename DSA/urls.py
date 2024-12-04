from django.urls import path
from .views import  RegisterView,VerifyOTPView, LoginView



urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/VerifyOTP/', VerifyOTPView.as_view(), name='VerifyOTP'),
    path('api/login/', LoginView.as_view(), name='login'),
]
