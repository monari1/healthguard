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


class UserLogoutView(APIView):
    def post(self, request):
        # Perform logout logic here
        # ...

        # Clear session data or revoke authentication tokens
        request.session.flush()

        # Return appropriate response
        return Response({'message': 'User logged out successfully'})


def get_access_token():
    url = 'https://accounts.multitenant.slade360.co.ke/oauth2/token/'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        "grant_type": "password",
        "client_id": "lTRf5PYzgq7Pxcx49JdVdhOyt0umRFk8aOI6ktX1",
        "client_secret": "8kjpLqrhhgDMB4q2Q6jYlI6TNQugWZkVeLWzW7dHOtwsZ4cY4yEJhrytUdcUhikkEPLlkfTMSmvA8QGHofeF9iM7B0sqo8Mzj8MZY3IPML5apzHWnueie84nzuwWVnpg",
        "username": "wafulahvictor@gmail.com",
        "password": "Wafulah68#",
    }
    response = requests.post(url, data=data, headers=headers)
    response.raise_for_status()
    access_token = response.json().get('access_token')
    return access_token
# pprint(data)


access_token = get_access_token()


@api_view(['GET'])
def get_logged_in_user(request):
    access_token = get_access_token()
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    response = requests.get(
        'https://accounts.multitenant.slade360.co.ke/v1/user/me/',
        headers=headers
    )
    response.raise_for_status()
    return Response(response.json())

#  membershipNumber: "",
#     insurerNumber:


@api_view(['POST'])
def get_member_eligibility(request):
    member_number = request.data.get('membershipNumber')
    # 'DEMO/001'
    payer_slade_code = request.data.get('insurerNumber')
    #  '457'
    print(member_number, 'HELLO', payer_slade_code)
    access_token = get_access_token()
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

    access_token = get_access_token()

    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    url = (
        'https://provider-edi-api.multitenant.slade360.co.ke/v1/beneficiaries/'
        'beneficiary_contacts/' + str(otp_id) + '/send_otp/'
    )

    response = requests.post(url, headers=headers)
    response.raise_for_status()

    otp_number = response.json().get('success').split(' ')[-1]
    return Response(otp_number)

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
        "otp": 425751,
        "beneficiary_contact": "+254790360360",
        "scheme_name": "Muungano Scheme",
        "scheme_code": "POL/001"
    }
    access_token = get_access_token()
    headers = {
        'Authorization': 'Bearer {}'.format(access_token),
        'Content-Type': 'application/json'
    }

    url = ('https://provider-edi-api.multitenant.slade360.co.ke/v1/authorizations/start_visit/')

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


@api_view(['POST'])
def create_authorization(request):
    payload = request.data

    # Extract values from the payload
    print(payload)

    # Process the payload and generate the response
    detail = "Authorization for Paul Mutinda successfully created"
    edi_auth_id = 17387
    edi_auth_guid = "35b36a8a-6799-4ab5-81d8-1635adef3a6b"
    member_number = 1234567
    auth_token = "234567-5TFHXF"
    first_name = "John"
    last_name = "Kerry"

    response = {

        "status": "Success",
        "message": "Successful validation of authorization token",
        "authorization_guid": "35b36a8a-6799-4ab5-81d8-1635adef3a6b",
        "authorization_date": "2023-04-15T05:11:52.980845Z",
        "benefit_balance": 30000,
        "reserved_amount": 0,
        "auth_expiry": "2023-04-17T08:11:52.686677+03:00",
        "auth_status": "AUTHORIZED",
        "copay_value": 800,
        "copay_type": "FLAT",
        "member_number": "DEMO/001",
        "member_name": "John Kerry",
        "scheme_name": "Muungano Scheme",
        "service_type": "OUTPATIENT",
        "is_wellness_member": "true",
        "edi_auth_guid": "35b36a8a-6799-4ab5-81d8-1635adef3a6b",
    }

    return Response(response)


@api_view(['POST'])
def reserve_from_authorization(request):
    authorization = request.data.get('authorization')
    invoice_number = request.data.get('invoice_number')
    amount = request.data.get('amount')

    payload = {
        'authorization': authorization,
        'invoice_number': invoice_number,
        'amount': amount
    }
    print(payload)
    access_token = get_access_token()
    headers = {'Authorization': 'Bearer {}'.format(access_token)}

    response = requests.post(
        'https://provider-edi-api.multitenant.slade360.co.ke/v1/balances/reservations/reserve_from_authorization/',
        json=payload,
        headers=headers
    )
    
    response.raise_for_status()

    

    return Response(response.json())

@api_view(['POST'])
def reservations(request):
    authorization = request.data.get('authorization')
    invoice_number = request.data.get('invoice_number')
    amount = request.data.get('amount')

    payload = {
        'authorization': authorization,
        'invoice_number': invoice_number,
        'amount': amount
    }
    print(payload)
    access_token = get_access_token()
    headers = {'Authorization': 'Bearer {}'.format(access_token)}

    response = {
       "id": 123,
       "providerName": "string",
       "guid": "35b36a8a-6799-4ab5-81d8-1635adef3a6b",
       "replicated": "2022-05-27T14:58:16.163579+03:00",
       "beneficiaryCode": "string",
       "policyNumber": "string",
       "policyEffectiveDate": "string",
       "payerSladeCode": 0,
       "authorization": "35b36a8a-6799-4ab5-81d8-1635adef3a6b",
       "invoiceNumber": "string",
       "providerSladeCode": 0,
       "amount": 0,
       "benefitCode": "string",
       "parentBenefitCode": "string",
       "benefit": "string",
       "dateReserved": "string",
       "amountReleased": 0,
       "dateReleased": "string",
       "releasedBy": "string",
       "reservedVia": "string",
       "expiryDate": "string",
       "releaseNotes": "string",
       "payerInvoiceReference": "string"
    }
    

    

    return Response(response)

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
