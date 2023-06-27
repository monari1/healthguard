from django.urls import path
from .views import get_access_token,get_logged_in_user, get_member_eligibility, request_otp, start_visit_via_otp

urlpatterns = [
    path('get-access-token/', get_access_token, name='get_access_token'),
    path('logged-in-user/', get_logged_in_user, name='logged-in-user'),
    path('member-eligibility/', get_member_eligibility, name='member-eligibility'),
    path('request-otp/', request_otp, name='request-otp'),
    path('start-visit-via-otp/', start_visit_via_otp, name='start-visit-via-otp'),
]
