from django.contrib import admin
from user_app.models import College, Department, Events, LeaveApplication, Profile, Review, Roles

# Register your models here.
admin.site.register(College)
admin.site.register(Department)
admin.site.register(Profile)
admin.site.register(Roles)
admin.site.register(Events)
admin.site.register(LeaveApplication)
admin.site.register(Review)