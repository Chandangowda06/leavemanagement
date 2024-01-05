import re
from django.contrib.auth.models import User, Group
from rest_framework import serializers
from user_app.models import Events, LeaveApplication, Profile, College, Department, Review, Roles


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField()



class UserCreateSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username',  'email', 'password', 'password2')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'}
            }
        }

    def create(self, validated_data):
        password = validated_data.get('password')
        password2 = validated_data.pop('password2')

        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, validated_data['email']):
            raise serializers.ValidationError({'email': 'Enter a valid email address'})

        if password != password2:
            raise serializers.ValidationError({'password2': 'Passwords must match'})

        if User.objects.filter(email=validated_data['username']).exists():
            raise serializers.ValidationError({'username': 'User already exists'})
        
        if User.objects.filter(email=validated_data['email']).exists():
            raise serializers.ValidationError({'email': 'Email already exists'})
        
        if len(password) < 6 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError({'password': 'Password must be at least 6 characters and contain symbols'})
        
        validated_data['email'] = validated_data['email'].lower()
        validated_data['username'] = validated_data['username'].lower()
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        
        return user
    
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Roles
        fields = "__all__"

class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(slug_field='username', queryset=User.objects.all())
    staff_role = RoleSerializer(read_only=True)
    college = serializers.SlugRelatedField(slug_field='name', queryset=College.objects.all(),  required=False, allow_null=True)
    department = serializers.SlugRelatedField(slug_field='name', queryset=Department.objects.all(),  required=False, allow_null=True)

    class Meta:
        model = Profile
        fields = '__all__'

    def create(self, validated_data):
        user = User.objects.filter(username=validated_data["user"]).first()
       
        # staff_role = Roles.objects.filter(name=validated_data["staff_role"]).first()
        phone_pattern = r'\d{10}'
        if not re.match(phone_pattern, validated_data['phone']):
            raise serializers.ValidationError({'phone': 'Enter a valid phone number'})
        
        if Profile.objects.filter(user=user).exists():
            raise serializers.ValidationError({'error': 'User Profile already exists'})
        
        
        profile = Profile(**validated_data)
        profile.save()
        return profile
    
    

class CollegeSerializer(serializers.ModelSerializer):
    principal = serializers.SlugRelatedField(slug_field='username', queryset=User.objects.all()) 

    class Meta:
        model = College
        fields = '__all__'
        
    def create(self, validated_data):

        if College.objects.filter(name=validated_data["name"]).exists():
            raise serializers.ValidationError({'name': 'College already exists'})
        
        if not User.objects.filter(username=validated_data["principal"]).exists():
            raise serializers.ValidationError({'principal': 'User not found'})
        
        college = College(**validated_data)
        college.save()
        return college
        
        

class DepartmentSerializer(serializers.ModelSerializer):
    college = serializers.SlugRelatedField(slug_field='name', queryset=College.objects.all()) 
    hod = serializers.SlugRelatedField(slug_field='username', queryset=User.objects.all()) 

    class Meta:
        model = Department
        fields = '__all__'

    
class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = "__all__"

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):

        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email):
            raise serializers.ValidationError({'email': 'Enter a valid email address'})

        if User.objects.filter(email=email).exists():
           return email
        else:
            raise serializers.ValidationError({'email': 'Email does not exist'})
        
class PasswordConfirmSerializer(serializers.Serializer):
    password = serializers.CharField()
    password2 = serializers.CharField()

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')

        # Perform your validation logic here
        if len(password) < 6 or not any(char in r'!@#$%^&*(),.?":{}|<>' for char in password):
            raise serializers.ValidationError({'password': 'Password must be at least 6 characters and contain symbols'})

        if password != password2:
            raise serializers.ValidationError({'password2': 'Passwords must match'})
        
        return data



class EventSerializer(serializers.ModelSerializer):
    author = ProfileSerializer(source='author.user.profile', read_only=True)
    
    class Meta:
        model = Events
        fields = "__all__"

    def get_author(self, obj):
        return obj.author.serialize_user()
    
class LeaveApplicationSerailizer(serializers.ModelSerializer):
    applicant = ProfileSerializer(source='applicant.user.profile', read_only=True)
    application_id = serializers.CharField(read_only=True)

    class Meta:
        model = LeaveApplication
        fields = "__all__"
            
class ReviewSerializer(serializers.ModelSerializer):
    user = ProfileSerializer(required=False)

    class Meta:
        model = Review
        fields = "__all__"
            
            
