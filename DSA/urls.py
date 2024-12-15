from django.urls import path
from .views import  RegisterView,VerifyOTPView, LoginView,UserProfileView,UpdateUserProfileView,FileUploadView,UploadStudentDetailsView,StudentDetailsView



urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/VerifyOTP/', VerifyOTPView.as_view(), name='VerifyOTP'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/get_user_profile/', UserProfileView.as_view(), name='get_user_profile'),
    path('api/update_user_profile/',UpdateUserProfileView.as_view(), name='get_user_profile'),
    path('api/upload-file/', FileUploadView.as_view(), name='upload_file'),
    path('api/upload-details/', UploadStudentDetailsView.as_view(), name='upload_student_details'),
     path('api/student-details/', StudentDetailsView.as_view(), name='student_details')
     
]
