
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.db.models.signals import post_save



class College(models.Model):
    name = models.CharField(max_length=255)
    principal = models.ForeignKey(User, blank=True, on_delete=models.SET_NULL, null=True, related_name="principal")

    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['-id']

class Department(models.Model):
    name = models.CharField(max_length=60)
    hod = models.ForeignKey(User, blank=True, on_delete=models.SET_NULL, null=True, related_name="hod")
    college = models.ForeignKey(College, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
    class Meta:
        ordering = ['-id']
    
class Roles(models.Model):
    ROLES_TYPE = (
        ('CEO', "CEO"),
        ('Director', "Director"),
        ('AO', "AO"),
        ('HOD', "HOD"),
        ('Principal', "Principal"),
        ('CFO', "CFO"),
        ('Teaching', "Teaching"),
        ('Non-teaching', "Non-teaching"),
        ('Admin', "Admin"),
        ('Institution-staff', "Institution-staff"))
    name = models.CharField(max_length=255)
    role_type = models.CharField(choices=ROLES_TYPE, max_length=50)

    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['-id']

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    name = models.CharField(max_length=60)
    staff_id = models.CharField(max_length=20)
    staff_role = models.ForeignKey(Roles, null=True, blank=True, on_delete=models.SET_NULL, related_name="role")
    phone = models.CharField(max_length=20, blank=True, null=True)
    image = models.ImageField(upload_to='profile_images', default='/user.png', null=True, blank=True)
    college = models.ForeignKey(College, blank=True, on_delete=models.SET_NULL, null=True)
    department = models.ForeignKey(Department, blank=True, on_delete=models.SET_NULL, null=True)
    total_leaves = models.IntegerField(default=12)
    leaves_taken = models.IntegerField(default=0)

    def __str__(self):
        return self.user.username
    
    def serialize_user(self):
        return str(self.user)
    
    class Meta:
        ordering = ['-id']
    
class Events(models.Model):
    author = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="author")
    title = models.CharField(max_length=80)
    description = models.CharField(max_length=1000)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    category = models.CharField(max_length=50)
    document = models.FileField(upload_to='event_documents/')

    def __str__(self):
        return f"{self.author.user.username}-{self.title}"
    
    class Meta:
        ordering = ['-id']

class Review(models.Model):
    event = models.ForeignKey(Events, on_delete=models.CASCADE, related_name="reviews")
    user = models.ForeignKey(Profile, on_delete=models.CASCADE)
    rating = models.IntegerField()  # You can use a rating scale, such as 1 to 5
    feedback = models.TextField()

    def __str__(self):
        return f"{self.user.username} - {self.event.title}"
    
    
class LeaveApplication(models.Model):
    APPROVAL_STATUSES = (
        ('Pending', 'Pending Approval'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )
    LEAVE_TYPES = (
        ('Casual Leave', 'Casual Leave'),
        ('Half-day leave', 'Half-day leave'),
        ('One-day leave', 'One-day leave'),
        ('Earned/Vacation/Privilege Leave', 'Earned/Vacation/Privilege Leave'),
        ('Sick Leave/Medical Leave', 'Sick Leave/Medical Leave'),
        ('Maternity Leave', 'Maternity Leave'),
        ('Paternity leave', 'Paternity leave'),
        ('Sabbatical Leave', 'Sabbatical Leave'),
        ('Bereavement leave', 'Bereavement leave'),
        ('Compensatory leave', 'Compensatory leave'),
        ('Compassionate leave', 'Compassionate leave')
    )

    applicant = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name="applicant")
    application_id = models.CharField(max_length=20)
    leave_type = models.CharField(max_length=100, choices=LEAVE_TYPES)
    leave_reason = models.CharField(max_length=500)
    start_date = models.DateField()
    end_date = models.DateField()
    alternative_staff = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True, blank=True, related_name="alternative_staff")
    approval_status = models.CharField(max_length=20, choices=APPROVAL_STATUSES, default='Pending')
    approved_hod = models.IntegerField(choices=[(0, 'Rejected'), (1, 'Approved'), (2, 'No Action')], default=2, null=True, blank=True)
    approved_principal = models.IntegerField(choices=[(0, 'Rejected'), (1, 'Approved'), (2, 'No Action')], default=2, null=True, blank=True)
    approved_director = models.IntegerField(choices=[(0, 'Rejected'), (1, 'Approved'), (2, 'No Action')], default=2, null=True, blank=True)
    approved_AO = models.IntegerField(choices=[(0, 'Rejected'), (1, 'Approved'), (2, 'No Action')], default=2, null=True, blank=True)
    approved_ceo = models.IntegerField(choices=[(0, 'Rejected'), (1, 'Approved'), (2, 'No Action')], default=2, null=True, blank=True)
    letter = models.FileField(default=None, blank=True, upload_to='letters/')
    # Timestamps
    submission_timestamp = models.DateTimeField(auto_now_add=True)
    hod_approval_timestamp = models.DateTimeField(null=True, blank=True)
    principal_approval_timestamp = models.DateTimeField(null=True, blank=True)
    director_approval_timestamp = models.DateTimeField(null=True, blank=True)
    ceo_approval_timestamp = models.DateTimeField(null=True, blank=True)
    AO_approval_timestamp = models.DateTimeField(null=True, blank=True)



    def __str__(self):
        return f"{self.applicant.name}-{self.application_id} - Leave Application"
    
    class Meta:
        ordering = ['-id']
