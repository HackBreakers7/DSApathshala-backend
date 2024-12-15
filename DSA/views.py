from django.core.mail import send_mail
import random
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import CustomUser, OTP
from django.conf import settings
from django.db import transaction
import random
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .models import CustomUser, OTP
import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime
import random

from .models import CustomUser, OTP


class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Extract data from the request
        username = request.data.get('username')
        full_name = request.data.get('full_name')
        user_class = request.data.get('user_class')
        roll_no = request.data.get('roll_no')
        stream = request.data.get('stream')
        email = request.data.get('email')
        contact_number = request.data.get('contact_number')
        dob = request.data.get('dob')
        password = request.data.get('password')
        college_name = request.data.get('college_name')

        # Validate that required fields are present
        required_fields = ['username', 'full_name', 'email', 'user_class', 
                           'roll_no', 'stream', 'dob', 'college_name', 
                           'contact_number', 'password']
        for field in required_fields:
            if not request.data.get(field):
                return Response({'error': f'{field} is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the username or email already exists
        if CustomUser.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        if CustomUser.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate date of birth format
        try:
            dob = datetime.strptime(dob, '%Y-%m-%d').date()
        except ValueError:
            try:
                dob = datetime.strptime(dob, '%d-%m-%Y').date()
            except ValueError:
                return Response({'error': 'Invalid date format for dob. Use YYYY-MM-DD or DD-MM-YYYY.'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP
        otp_code = str(random.randint(100000, 999999))

        try:
            # Store temporary data
            user = CustomUser(
                username=username,
                full_name=full_name,
                user_class=user_class,
                roll_no=roll_no,
                stream=stream,
                email=email,
                contact_number=contact_number,
                dob=dob,
                college_name=college_name,
            )
            user.set_password(password)  # Hash password before saving
            user.save()  # Save user to database

            # Send OTP email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}. It is valid for 10 minutes.',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            # Create OTP record
            OTP.objects.create(user=user, otp_code=otp_code)

            # Return success response
            return Response({'message': 'User registered successfully. Please verify OTP.'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"Registration failed: {e}")
            return Response({'error': 'Registration failed. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class VerifyOTPView(APIView):
    def post(self, request):
        otp_code = request.data.get('otp_code')
        email = request.data.get('email')

        if not otp_code or not email:
            return Response({'error': 'OTP code and email are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the user and associated OTP
            user = CustomUser.objects.get(email=email)
            otp_instance = OTP.objects.get(user=user, otp_code=otp_code)

            # If OTP is valid, activate the user
            if otp_instance.is_valid:
                user.is_active = True
                user.save()
                otp_instance.delete()  # Remove OTP after verification
                return Response({'message': 'OTP verified successfully. Your account is now active.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"OTP verification failed: {e}")
            return Response({'error': 'An error occurred during OTP verification. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from .models import CustomUser, OTP


class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Extract username and OTP code from request
        username = request.data.get('username')
        otp_code = request.data.get('otp_code')

        # Validate if username or OTP is missing
        if not username or not otp_code:
            return Response({"error": "Both username and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to fetch the user from database
            user = CustomUser.objects.get(username=username)

            # Attempt to fetch the OTP record
            otp_record = OTP.objects.get(otp_code=otp_code, user=user)

            # Check if OTP is already verified
            if otp_record.otp_verified:
                return Response({"error": "This OTP has already been verified."}, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as verified
            otp_record.otp_verified = True
            otp_record.save()

            # Respond with success message
            return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            # Handle invalid username scenario
            return Response({"error": "Invalid username provided."}, status=status.HTTP_400_BAD_REQUEST)

        except OTP.DoesNotExist:
            # Handle invalid OTP scenario
            return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception:
            # Handle unexpected exceptions
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        print(f"Received login attempt - Username: {username}")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        print(f"User found: {user.username}")

        # Check if the user is active
        if not user.is_active:
            return Response({"error": "Account is inactive. Please contact support."}, status=status.HTTP_403_FORBIDDEN)

        # Determine if the user is a superuser or normal user
        is_superuser = user.is_staff and user.is_active

        # Check password
        if user.check_password(password):
            # Generate tokens only if the user exists and the password is correct
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Include `is_superuser` in the access token payload
            access_token_payload = refresh.access_token.payload
            access_token_payload['is_superuser'] = is_superuser

            # Optionally store tokens in the database
            user.refresh_token = str(refresh)  # Save refresh token
            user.access_token = access_token  # Save access token
            user.save()

            return Response({
                "refresh": str(refresh),
                "access": access_token,
                "is_superuser": is_superuser,  # Include `is_superuser` in the response
                "message": "Login successful.",
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

class UserProfileView(APIView):
    """
    API View to fetch and return user profile details.
    """
    permission_classes = [AllowAny]
 # Restrict to authenticated users

    def get(self, request):
        user = request.user  # Get the current logged-in user
        profile_data = {
            "full_name": user.full_name,
            "user_class": user.user_class,
            "roll_no": user.roll_no,
            "stream": user.stream,
            "dob": user.dob,
            "college_name": user.college_name,
            "contact_number": user.contact_number,
            "username": user.username,
            "email": user.email,
        }
        return Response(profile_data)

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
import json
from django.utils.dateparse import parse_date
from django.contrib.auth import get_user_model


User = get_user_model()

method_decorator(csrf_exempt, name='dispatch')
class UpdateUserProfileView(View):
    permission_classes = [AllowAny]
    # Exempt CSRF only on this endpoint for JWT token-based flow
    
    def put(self, request):
        try:
            # Debugging headers
            print("Headers:", request.headers)

            # Extract JWT token from the request header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization token missing or invalid'}, status=401)

            token = auth_header.split(' ')[1]
            try:
                # Decode and validate the token
                validated_token = JWTAuthentication().get_validated_token(token)
                user = JWTAuthentication().get_user(validated_token)
            except Exception as e:
                print("JWT Error:", e)
                return JsonResponse({'error': 'Invalid or expired token'}, status=401)

            # Parse user profile data from the request payload
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

            # Prevent updates to roll_no or username
            if 'roll_no' in data or 'username' in data:
                return JsonResponse({'error': 'Cannot modify roll_no or username.'}, status=403)

            # Update user fields if provided in the payload
            user.full_name = data.get('full_name', user.full_name)
            user.stream = data.get('stream', user.stream)
            user.college_name = data.get('college_name', user.college_name)
            user.contact_number = data.get('contact_number', user.contact_number)

            # Handle date of birth safely
            if 'dob' in data:
                parsed_dob = parse_date(data['dob'])
                if not parsed_dob:
                    return JsonResponse({'error': 'Invalid date format for dob. Expected YYYY-MM-DD.'}, status=400)
                user.dob = parsed_dob

            # Save the updated user data
            user.save()
            return JsonResponse({'message': 'Profile updated successfully!'}, status=200)

        except Exception as e:
            print("Unexpected error:", str(e))
            return JsonResponse({'error': 'Internal server error', 'details': str(e)}, status=500)

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models import UserProfile

@method_decorator(csrf_exempt, name='dispatch')
class FileUploadView(View):
    def post(self, request):
        try:
            user_profile, created = UserProfile.objects.get_or_create(user=request.user)
            file_type = request.POST.get('file_type')

            if file_type == 'profile_photo':
                user_profile.profile_photo = request.FILES['file']
            elif file_type == 'header_background':
                user_profile.header_background = request.FILES['file']
            elif file_type == 'certificates':
                user_profile.certificates = request.FILES['file']
            else:
                return JsonResponse({'error': 'Invalid file type'}, status=400)

            user_profile.save()
            return JsonResponse({'message': 'File uploaded successfully!', 'file_url': getattr(user_profile, file_type).url})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from .models import StudentResult
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication  # Use JWT authentication

from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from .models import StudentResult  # Assuming this is your model

class UploadStudentDetailsView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Retrieve data from the request
            roll_no = request.data.get('roll_no')
            name = request.data.get('name')
            performance = float(request.data.get('performance', 0))  # Score out of 4
            mcqs = float(request.data.get('mcqs', 0))  # Score out of 4
            attendance = float(request.data.get('attendance', 0))  # Score out of 
            practical_no = int(request.data.get('practical_no', 0))  # Number of practicals attended
            batch = request.data.get('batch')

            # Check if all required fields are provided
            if not all([roll_no, name, mcqs, attendance, practical_no, batch]):
                return JsonResponse({'success': False, 'error': 'All fields are required.'}, status=400)

            # Create the StudentResult object
            student_result = StudentResult(
                roll_no=roll_no,
                name=name,
                performance=performance,
                mcqs=mcqs,
                attendance=attendance,
                practical_no=practical_no,
                batch=batch,
            )
            student_result.save()

            # Calculate total score (performance + mcqs + attendance)
            total_score = round(student_result.performance + student_result.mcqs + student_result.attendance , 2)

            # Return a success response with the total score
            return JsonResponse({
                'success': True,
                'message': 'Student details uploaded successfully.',
                'total_score': total_score,  # Total out of 10
                'practical_no': practical_no,  # Number of practicals attended
            })

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

from django.http import JsonResponse
from django.views import View
from .models import StudentResult  # Ensure the correct model is imported

class StudentDetailsView(View):
    def get(self, request):
        # Fetch all students from the database
        students = StudentResult.objects.all().values(
            'roll_no', 'name', 'performance', 'mcqs', 'attendance', 'practical_no', 'batch'
        )
        # Return the data as JSON
        return JsonResponse({'students': list(students)}, safe=False)
