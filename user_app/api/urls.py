from django.urls import path, include
from django.contrib.auth import views as auth_views
from rest_framework.routers import DefaultRouter
from user_app.api.views import LeaveApplicationReadonly, EventViewSet, LeaveApplicationViewSet, ReviewList, ReviewView, RolesViewSet, UserByUsernameView, ProfileByUsernameView, PasswordConfirmAV, PasswordResetAV, UserViewSet, ProfileViewSet, CollegeViewSet, DepartmentViewSet, GroupList, CustomObtainAuthToken, LogoutView

router = DefaultRouter()
router.register(r'user', UserViewSet)
router.register(r'profile', ProfileViewSet)
router.register(r'college', CollegeViewSet)
router.register(r'department', DepartmentViewSet)
router.register(r'roles', RolesViewSet)
router.register(r'events', EventViewSet)
router.register(r'review', ReviewView, basename="review")
router.register(r'leave-application', LeaveApplicationViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('group-list/', GroupList.as_view(), name='group-list'),
    path('application-list/', LeaveApplicationReadonly.as_view({'get': 'list'}), name='application-list'),
    path('login/', CustomObtainAuthToken.as_view(), name='login'),
    path('reviews/<int:pk>/', ReviewList.as_view(), name='review-list'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('user-profile/<str:username>/', ProfileByUsernameView.as_view(), name='profile-detail'),
    path('user-detail/<str:username>/', UserByUsernameView.as_view(), name='user-detail'),
    path('password_reset/', PasswordResetAV.as_view(), name='password_reset'),
    path('password_reset/confirm/<uidb64>/<token>/', PasswordConfirmAV.as_view(), name='password_reset_confirm'),
]
