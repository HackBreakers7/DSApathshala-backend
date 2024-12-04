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
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime


logger = logging.getLogger(__name__)


class RegisterView(APIView):
    def post(self, request):
        if request.method == 'POST':

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
            'roll_no', 'stream', 'dob', 'college_name','contact_number',
            'password']
        for field in required_fields:
            if not request.data.get(field):
                return Response({'error': f'{field} is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the username or email already exists
        if CustomUser.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        

        # Validate dob format
        try:
            # First, try to parse it as YYYY-MM-DD
            dob = datetime.strptime(dob, '%Y-%m-%d').date()
        except ValueError:
            try:
                # If that fails, try parsing it as DD-MM-YYYY
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
                password=password,  # Don't save yet, need to verify OTP first
                college_name=college_name
            )
            user.set_password(password)  # Hash password before saving
            user.save()  # Save user to create a reference for OTP

            # Send OTP email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            # Create OTP record
            otp_instance = OTP.objects.create(
                user=user,  # Associate OTP with the newly created user
                otp_code=otp_code
            )
            # Return success response to wait for OTP verification
            return Response(
                {'message': 'User registered successfully. Please verify OTP.'},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            print(f"Registration failed: {e}")
            return Response(
                {'error': 'Registration failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        print(f"Received request data: {request.data}")
        username = request.data.get('username')
        otp = request.data.get('otp_code')

        # Validate input
        if not username or not otp:
            return Response({"error": "Username and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user and OTP record
            user = CustomUser.objects.get(username=username)  # Fetch the user
            otp_record = OTP.objects.get(otp_code=otp, user=user)  # Fetch OTP record based on OTP and user

            # Check if OTP is already verified
            if otp_record.otp_verified:
                return Response({"error": "OTP has already been verified."}, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as verified
            otp_record.otp_verified = True
            otp_record.save()

            # Return success response
            return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid username."}, status=status.HTTP_400_BAD_REQUEST)

        except OTP.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": f"Error during OTP verification: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
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

        # Check password
        if user.check_password(password):
            # Generate tokens only if the user exists and the password is correct
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            access_token_payload = refresh.access_token.payload
            access_token_payload['is_superuser'] = user.is_superuser  # Add this line
            
            # Store tokens in the database (optional)
            user.refresh_token = str(refresh)  # Save refresh token
            user.access_token = access_token  # Save access token (optional)
            user.save()

            return Response({
                "refresh": str(refresh),
                "access": access_token,
                "message": "Login successful.",
                
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
