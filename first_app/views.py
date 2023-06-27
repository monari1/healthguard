from rest_framework.decorators import api_view
from rest_framework.response import Response
import requests
# Create your views here.

# pip install requests
import requests


from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from rest_framework import status


class UserLoginAPIView(ObtainAuthToken):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)

        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
def get_access_token(request):
    url = 'https://accounts.multitenant.slade360.co.ke/oauth2/token/'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type": "password",
        # Substitute with your client_id,
        "client_id": "lTRf5PYzgq7Pxcx49JdVdhOyt0umRFk8aOI6ktX1",
        "client_secret": "8kjpLqrhhgDMB4q2Q6jYlI6TNQugWZkVeLWzW7dHOtwsZ4cY4yEJhrytUdcUhikkEPLlkfTMSmvA8QGHofeF9iM7B0sqo8Mzj8MZY3IPML5apzHWnueie84nzuwWVnpg",
        "username": "wafulahvictor@gmail.com",  # Your email.
        "password": "Wafulah68#",  # Your healthcloud account password.
    }
    response = requests.post(url, data=data, headers=headers)
    response.raise_for_status()
    access_token = response.json().get('access_token')
    return Response({'access_token': access_token})

# pprint(data)


access_token = 'lyUgo7Fpe6Xg0Sxw8MqACwQePwMD2s'


@api_view(['GET'])
def get_logged_in_user(request):
    access_token = 'lyUgo7Fpe6Xg0Sxw8MqACwQePwMD2s'
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    response = requests.get(
        'https://accounts.multitenant.slade360.co.ke/v1/user/me/',
        headers=headers
    )
    response.raise_for_status()
    return Response(response.json())


@api_view(['GET'])
def get_member_eligibility(request):
    member_number = 'DEMO/001'
    payer_slade_code = '457'
    access_token = 'lyUgo7Fpe6Xg0Sxw8MqACwQePwMD2s'
    headers = {'Authorization': 'Bearer {}'.format(access_token)}

    url = (
        'https://provider-edi-api.multitenant.slade360.co.ke/v1/beneficiaries/'
        'member_eligibility/?member_number={}&payer_slade_code={}'.format(
            member_number, payer_slade_code
        )
    )

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return Response(response.json())


@api_view(['POST'])
def request_otp(request):
    otp_id = request.data.get('otp_id')

    access_token = 'lyUgo7Fpe6Xg0Sxw8MqACwQePwMD2s'
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    url = (
        'https://provider-edi-api.multitenant.slade360.co.ke/v1/beneficiaries/'
        'beneficiary_contacts/' + str(otp_id) + '/send_otp/'
    )

    response = requests.post(url, headers=headers)
    response.raise_for_status()

    return Response(response.json())

    #    {"otp_id":"5583"}


@api_view(['POST'])
def start_visit_via_otp(request):
    payload = {
        "beneficiary_id": 636561,
        "factors": [
            "OTP"
        ],
        "benefit_type": "OUTPATIENT",
        "benefit_code": "BEN/00",
        "policy_number": "POL/001",
        "policy_effective_date": "2023-01-01T00:00:00+03:00",
        "otp": int('045311'),
        "beneficiary_contact": 254790360360,
        "scheme_name": "Muungano Scheme",
        "scheme_code": "POL/001"
    }
    access_token = 'lyUgo7Fpe6Xg0Sxw8MqACwQePwMD2s'
    headers = {
        'Authorization': 'Bearer {}'.format(access_token),
        'Content-Type': 'application/json'
    }

    url = 'https://accounts.multitenant.slade360.co.ke/authorizations/start_visit/'

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return Response(response.json())

    # {
    #     "beneficiary_id": 636561,
    #     "factors": ["OTP"],
    #     "benefit_type": "OUTPATIENT",
    #     "benefit_code": "BEN/001",
    #     "policy_number": "POL/001",
    #     "policy_effective_date": "2023-01-01T00:00:00+03:00",
    #     "otp": 720291,
    #     "beneficiary_contact": "+254790360360",
    #     "scheme_name": "Muungano Scheme",
    #     "scheme_code": "POL/001"
    # }
# start_visit_via_otp()

# # def validate_authorization_token():
# #     {
# #     "first_name": "John",
# #     "last_name": "Kerry",
# #     "other_names": "string",
# #     "member_number": "DEMO/001",
# #     "auth_token": "CGY7WNU8S8",
# #     "visit_type": "OUTPATIENT",
# #     "scheme_code": "string",
# #     "scheme_name": "string",
# #     "payer_code": "string"
# #     }
# #     return x
# # #validate_authorization_token()

# # def create_balance_reservation():
# #     {
# #     "authorization": "35b36a8a-6799-4ab5-81d8-1635adef3a6b",
# #     "invoice_number": "ORE1234/22",
# #     "amount": 2500
# #     }
