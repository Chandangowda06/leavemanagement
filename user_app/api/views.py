from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from django.utils import timezone
import random
import re
from django.db.models import Q
from django.forms import ValidationError
from user_app.api.utils import default_token_generator
from rest_framework import viewsets
from django.contrib.auth.models import User, Group
from user_app.api.serializers import CollegeSerializer, DepartmentSerializer, EventSerializer, LeaveApplicationSerailizer, PasswordConfirmSerializer, PasswordResetSerializer, ProfileSerializer, ReviewSerializer, RoleSerializer, UserCreateSerializer, GroupSerializer,LoginSerializer
from user_app.api.twilo import send_msg
from user_app.models import College, Department, Events, LeaveApplication, Profile, Review, Roles
from rest_framework import generics
from rest_framework.decorators import action
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import login
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth import get_user_model
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.views import PasswordResetView
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib.auth.views import PasswordResetDoneView
from django.utils.encoding import force_bytes
from user_app.api.utils import send_password_reset_email, extract_user_from_token
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from user_app.api.utils import send_email
from rest_framework.parsers import MultiPartParser
from user_app.api.utils import generate_pdf

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username', None)
            email = serializer.validated_data.get('email', None)
            password = serializer.validated_data['password']

            user = None

            if username:
                user = User.objects.filter(username=username).first()
            elif email:
                user = User.objects.filter(email=email).first()

            if user is not None and user.check_password(password):
                token, created = Token.objects.get_or_create(user=user)
                return Response({'token': token.key, 'username': user.username})
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request, formate=None):
        if request.user.auth_token:
            request.auth.delete()  # Delete the user's token
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        return Response({'message': 'User Already logged out.'}, status=status.HTTP_401_UNAUTHORIZED)

class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    def perform_create(self, serializer):
        serializer.save()
        return Response({"username": serializer.validated_data.get("username", None)})


class ProfileViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

    def perform_create(self, serializer):
        # Perform the creation of the profile
        role_id = self.request.data.get('staff_role')

        # Fetch the Roles instance based on the provided role_id
        role_instance = get_object_or_404(Roles, id=role_id)

        # Perform the creation of the profile
        serializer.save(staff_role=role_instance)
        
        serializer.save()

        # Access the created profile instance
        profile_instance = serializer.instance

        # additional operations, including accessing the request
        try:
            phone = serializer.validated_data.get('phone', '')
            name = serializer.validated_data.get('name', '')
            role = role_instance.name
            username = serializer.validated_data.get('user', '')
            email = get_object_or_404(User, username=username).email
            frontend_domain = self.request.headers.get('Origin')
            passwd_reset_url = f"{frontend_domain}/password_reset/"
            sub = "From Team BGI - Profile Created Successfully - "
            msg = f"{name} you are successfully registered for BGI web app as a {role}. Your userid: {username}, reset your password to continue {passwd_reset_url} \n\n\nThankyou for using our web app"
            send_email(sub=sub, msg=msg, to=email)
            # send_msg(phone, msg=f"{sub} {msg}")
           
        except Exception as e:
            print("Error in sending message", e)

    def get_queryset(self):
        # Get the user making the request
        user = self.request.user
        # Get the role of the user
        user_role = user.profile.staff_role if hasattr(user, 'profile') else None
        user_role = user_role.name.lower()
        # Depending on the user's role, filter the profiles accordingly
        if user_role == 'hod':
            # Filter profiles for HOD
            # Modify the condition based on your specific logic
            queryset = Profile.objects.filter(department=user.profile.department)
        elif user_role == 'principal':
            # Filter profiles for Principal
            # Modify the condition based on your specific logic
            queryset = Profile.objects.filter(college=user.profile.college)
        elif user_role in ['director', 'ceo', 'admin']:
            # No specific filtering for Director (can view all profiles)
            queryset = Profile.objects.all()
        else:
            # Default case (e.g., regular staff)
            # You might want to handle this differently based on your requirements
            queryset = Profile.objects.filter(staff_role__role_type=user.profile.staff_role.role_type, department=user.profile.department, college=user.profile.college)

        return queryset



class CollegeViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    
    queryset = College.objects.all()
    serializer_class = CollegeSerializer

    def get_queryset(self):

        user = self.request.user
      
        # Get the role of the user
        user_role = user.profile.staff_role if hasattr(user, 'profile') else None
        user_role = user_role.name.lower()
       
        # Depending on the user's role, filter the colleges accordingly
        if user_role in ['hod', 'pricipal']:
            queryset = College.objects.filter(name=user.profile.college)

        elif user_role in ['admin', 'director', 'ceo']:
            queryset = College.objects.all()

        else:
            queryset = College.objects.none()

        return queryset

class DepartmentViewSet(viewsets.ModelViewSet):
    queryset = Department.objects.all()
    serializer_class = DepartmentSerializer
    def get_queryset(self):

        user = self.request.user
       
        # Get the role of the user
        user_role = user.profile.staff_role if hasattr(user, 'profile') else None
        user_role = user_role.name.lower()
        
        # Depending on the user's role, filter the colleges accordingly
        if user_role in ['hod']:
            queryset = Department.objects.filter(name=user.profile.department)

        elif user_role == 'principal':
            # Filter profiles for Principal
            # Modify the condition based on your specific logic
            queryset = Department.objects.filter(college=user.profile.college)

        elif user_role in ['admin', 'director', 'ceo']:
            queryset = Department.objects.all()

        else:
            queryset = Department.objects.none()

        return queryset

class GroupList(generics.ListAPIView):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


class PasswordResetAV(APIView):
 
    def post(self, request, format=None, serializer_class=PasswordResetSerializer):
        serializer = serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email', None)
            user = get_object_or_404(User, email=email)
            try:
                send_password_reset_email(user, request=request)
                return Response({'message': 'Password reset link sent to your email'}, status=status.HTTP_200_OK)
            except Exception as e:
                print("Error in sending password reset email", e)
                return Response({'error': 'Error sending password reset email'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid data', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class PasswordConfirmAV(APIView):

    def post(self, request, uidb64, token, format=None, serializer_class=PasswordConfirmSerializer):
        # Extract uidb64 and token from the URL
        uidb64 = uidb64
        token = token

        # Use uidb64 and token to get the user
        user = extract_user_from_token(uidb64, token)

        if user is None:
            return Response({'error': 'Invalid user or token'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            user.set_password(password)
            user.save()
            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid data', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class RolesViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Roles.objects.all()
    serializer_class = RoleSerializer

    def get_queryset(self):

        user = self.request.user
        user_role = user.profile.staff_role if hasattr(user, 'profile') else None
        user_role = user_role.name.lower()
        # Depending on the user's role, filter the colleges accordingly
        if user_role in ['hod']:
            queryset = Roles.objects.filter(role_type="Teaching")

        elif user_role == 'principal':
            # Filter profiles for Principal
            # Modify the condition based on your specific logic
            queryset = Roles.objects.filter(role_type__in=["Teaching", "Non-teaching"])

        elif user_role in ['admin', 'director', 'ceo']:
            queryset = Roles.objects.all()

        else:
            queryset = Department.objects.none()

        return queryset


    
class ProfileByUsernameView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, username, format=None):
        # Find the User instance by username
        user = User.objects.filter(username=username).first()

        if not user:
            return Response({'error': 'User with this username does not exist'}, status=status.HTTP_404_NOT_FOUND)

        # Find the corresponding Profile instance
        profile = Profile.objects.filter(user=user).first()

        if not profile:
            return Response({'error': 'Profile not found for this user'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the Profile instance
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def partial_update(self, request, username, format=None):
       
        user = User.objects.filter(username=username).first()
        staff_role = self.request.data.get('staff_role')
        if not user:
            return Response({'error': 'User with this username does not exist'}, status=status.HTTP_404_NOT_FOUND)

        profile = Profile.objects.filter(user=user).first()

        if not profile:
            return Response({'error': 'Profile not found for this user'}, status=status.HTTP_404_NOT_FOUND)
        
        if staff_role:
            role_instance = get_object_or_404(Roles, id=staff_role)
            profile.staff_role = role_instance
            profile.save()
            
        serializer = ProfileSerializer(profile, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserByUsernameView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserCreateSerializer
    def get(self, request, username, format=None):
        # Find the User instance by username
        user = User.objects.filter(username=username).first()

        if not user:
            return Response({'error': 'User with this username does not exist'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserCreateSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def partial_update(self, request, username, format=None):
       
        user = User.objects.filter(username=username).first()

        if not user:
            return Response({'error': 'User with this username does not exist'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserCreateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def destroy(self, request, username, format=None):
        user = User.objects.filter(username=username).first()

        if not user:
            return Response({'error': 'User with this username does not exist'}, status=status.HTTP_404_NOT_FOUND)

        user.delete()
        return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


class EventViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    
    queryset = Events.objects.all()
    serializer_class = EventSerializer

    def perform_create(self, serializer):

        profile = Profile.objects.get(user = self.request.user)

        if not profile:
            raise ValueError({'user': "Profile is not available"})
        
        serializer.save(author=profile)

    def get_queryset(self):
        user = self.request.user
        profile = Profile.objects.filter(user=user).first()
        if not profile:
            raise ValueError({'Profile': "No profile"})
        
        user_role = profile.staff_role.name.lower()
        
        # Depending on the user's role, filter the colleges accordingly
        if user_role in ['ceo', 'director']:
            queryset = Events.objects.all()

        else:
            queryset = Events.objects.filter(author=profile)

        return queryset
    
class LeaveApplicationViewSet(viewsets.ModelViewSet):

    queryset = LeaveApplication.objects.all()
    serializer_class = LeaveApplicationSerailizer

    def perform_create(self, serializer):

        profile = Profile.objects.get(user = self.request.user)

        if not profile:
            raise ValueError({'user': "Profile is not available"})
        
        application_id = int(str(datetime.now().date()).replace('-', '') + str(random.randint(1000, 2000)))
        user = self.request.user
        user_role = user.profile.staff_role.role_type if hasattr(user, 'profile') else None
        user_role = user_role.lower()

        if user_role == 'hod':
            serializer.validated_data['approved_hod'] = 1
            serializer.validated_data['approved_principal'] = 2
            serializer.validated_data['approved_director'] = 2
            serializer.validated_data['approved_ceo'] = 2
        elif user_role == 'principal':
            serializer.validated_data['approved_principal'] = 1
            serializer.validated_data['approved_director'] = 2
            serializer.validated_data['approved_ceo'] = 2
        elif user_role == 'ao':
            serializer.validated_data['approved_AO'] = True
            serializer.validated_data['approved_ceo'] = 2
        elif user_role == 'director':
            serializer.validated_data['approved_director'] = True
            serializer.validated_data['approved_ceo'] = 2

            
        context ={'staff_role': profile.staff_role.name, 'staff_id': profile.staff_id, 'name': profile.name, 'department': profile.department, 'college': profile.college,
        'leave_type': serializer.validated_data['leave_type'],
        'reason': serializer.validated_data['leave_reason'],
        'start_date': serializer.validated_data['start_date'],
        'end_date': serializer.validated_data['end_date'],
        'alternative_staff': serializer.validated_data['alternative_staff'],
        'date': datetime.today(),
        }
        file = generate_pdf(context=context, name=application_id)
        serializer.save(applicant=profile, application_id=application_id, letter=file)

          
        
       
    
    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        user = request.user
        user_role = user.profile.staff_role if hasattr(user, 'profile') else None
        applicant_role = instance.applicant.staff_role.name
        applicant_role = applicant_role.lower() if applicant_role else None
        user_role = user_role.name.lower() if user_role else None
        action_taken = request.data.get('action_taken')
        print(action_taken)

        # Validate the action
        if action_taken not in ['Approved', 'Rejected']:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)
        
        sub = "Leave Application Status"
        msg = f"Your leave application with id {instance.application_id} has been {action_taken} by {user_role}"
        to = user.email

        
        if user_role == 'hod':
            if action_taken == 'Approved':
                instance.approved_hod = 1
                instance.hod_approval_timestamp = datetime.now()
                
            elif action_taken == 'Rejected':
                instance.approved_hod = 0
                instance.approval_status = 'Rejected'
            instance.save()
            try:
                send_email(sub=sub, msg=msg, to=to)
                send_msg(instance.applicant.phone, msg=f"{sub} {msg}")
            except Exception as e:
                print(e)
            return Response({"message": "updated successfully"}, status=status.HTTP_200_OK)
            

        elif user_role == 'principal':
            if action_taken == 'Approved':        
                instance.approved_principal = 1
                instance.principal_approval_timestamp = timezone.now()
            elif action_taken == 'Rejected':
                instance.approved_principal = 0
                instance.approval_status = 'Rejected'
            instance.save()
            try:
                send_email(sub=sub, msg=msg, to=to)
                send_msg(instance.applicant.phone, msg=f"{sub} {msg}")
            except Exception as e:
                print(e)
            return Response({"message": "updated successfully"}, status=status.HTTP_200_OK)

        elif user_role == 'director':
            if action_taken == 'Approved':
                instance.approved_director = 1
                instance.director_approval_timestamp = timezone.now()
                if applicant_role not in ['ao', 'director', 'ceo', 'principal']:
                    instance.approval_status = 'Approved'
                    profile = get_object_or_404(Profile, pk=instance.applicant.id)
                    leaves_taken = profile.leaves_taken 
                    profile.leaves_taken = leaves_taken + 1
                    profile.save()
                    
            elif action_taken == 'Rejected':
                instance.approved_director = 0
                if applicant_role not in ['ao', 'director', 'ceo', 'principal']:
                    instance.approval_status = 'Rejected'
            instance.save()
            try:
                send_email(sub=sub, msg=msg, to=to)
                send_msg(instance.applicant.phone, msg=f"{sub} {msg}")
            except Exception as e:
                print(e)
            return Response({"message": "updated successfully"}, status=status.HTTP_200_OK)

        elif user_role == 'ceo':
            if action_taken == 'Approved':
                instance.approved_ceo = 1
                instance.ceo_approval_timestamp = timezone.now()
                instance.approval_status = 'Approved'
                profile = get_object_or_404(Profile, pk=instance.applicant.id)
                leaves_taken = profile.leaves_taken 
                profile.leaves_taken = leaves_taken + 1
                profile.save()
            elif action_taken == 'Rejected':
                instance.approved_ceo = 0
                instance.approval_status = 'Rejected'
            instance.save()
            try:
                send_email(sub=sub, msg=msg, to=to)
                send_msg(instance.applicant.phone, msg=f"{sub} {msg}")
            except Exception as e:
                print(e)
            return Response({"message": "updated successfully"}, status=status.HTTP_200_OK)

        elif user_role == 'ao':
            if action_taken == 'Approve':
                instance.approved_AO = 1
                instance.AO_approval_timestamp = timezone.now()
            elif action_taken == 'Rejected':
                instance.approved_AO = 0
            try:
                send_email(sub=sub, msg=msg, to=to)
                send_msg(instance.applicant.phone, msg=f"{sub} {msg}")
            except Exception as e:
                print(e)
            return Response({"message": "updated successfully"}, status=status.HTTP_200_OK)
        else:
                # Handle the case where the user role is not recognized
            return Response({"error": "Invalid user role"}, status=status.HTTP_400_BAD_REQUEST)
            



        
    def get_queryset(self):
        # Get the user making the request
        user = self.request.user
        # Get the role of the user
        user_role = user.profile.staff_role if hasattr(user, 'profile') else None
        user_role = user_role.name.lower() if user_role else None
        # Depending on the user's role, filter the profiles accordingly
        print(user_role, user.profile.department)
        if user_role == 'hod':
            queryset = LeaveApplication.objects.filter(applicant__department=user.profile.department, approved_hod=2)
            print(queryset, user.profile)

        elif user_role == 'principal':
            queryset = LeaveApplication.objects.filter(
                    applicant__college=user.profile.college,
                    approved_principal=2,  # Not yet approved by Principal
                    ).exclude(
                    Q(applicant__staff_role__role_type='Teaching') & ~Q(approved_hod=1)
                    )


        elif user_role == 'ao':
            queryset = LeaveApplication.objects.filter(applicant__staff_role__role_type__in=["Non-teaching", "Institution-staff"]).exclude(
                    Q(applicant__staff_role__role_type='Non-teaching') & ~Q(approved_pricipal=1)
                    )

        elif user_role == 'director':
            queryset = LeaveApplication.objects.filter(
            Q(applicant__staff_role__role_type__in=['Teaching', 'Principal', "HOD"]) & Q(approved_principal=1) &  Q(approved_director=2)|
            Q(applicant__staff_role__role_type__in=['Non-teaching', 'Institution-staff']) & Q(approved_AO=1) & Q(approved_director=2)
             )

        elif user_role == 'ceo':
             queryset = LeaveApplication.objects.filter(
                Q(applicant__staff_role__role_type__in=['Director', 'Principal', 'AO', 'CFO']) &
                Q(approved_ceo=2)  # Not yet approved by CEO
                ).exclude(Q(applicant__staff_role__role_type='Principal') & ~Q(approved_director=1))
        else:
            # Default case (e.g., regular staff)
            # You might want to handle this differently based on your requirements
            queryset = LeaveApplication.objects.none()

        return queryset
    
class LeaveApplicationReadonly(viewsets.ReadOnlyModelViewSet):
    serializer_class = LeaveApplicationSerailizer
    
    def get_queryset(self):
        # Customize the queryset based on the current user
        profile = self.request.user.profile
        if not profile:
            raise ValueError({'profile': profile})
        # Assuming there's a ForeignKey in your Account model that associates it with a user
        queryset = LeaveApplication.objects.filter(applicant=profile)

        return queryset

class ReviewView(viewsets.ModelViewSet):
    serializer_class = ReviewSerializer
    
    def get_queryset(self, **kwargs):
        return Review.objects.none()
    
    def create(self, request, *args, **kwargs):
        print("Request data:", request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        profile = Profile.objects.filter(user=self.request.user).first()
        serializer.save(user=profile)

class ReviewList(generics.ListAPIView):
    serializer_class = ReviewSerializer
    
    def get_queryset(self, **kwargs):
        event_id = self.kwargs.get('pk')
        print(event_id)
        return Review.objects.filter(event=event_id)