from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework.views import status
from .models import Songs
from .serializers import SongSerializer
from django.contrib.auth.models import User

# Create your tests here.
class ModelTestCase(TestCase):
    
    @staticmethod
    def create_new_song(title="", artist=""):
        if (title is not None or title != "") and (artist is not None or artist != ""):
            Songs.objects.create(title=title, artist=artist)

    """Set up variables to use during tests"""
    def test_model_can_create_instance(self):

        self.create_new_song("Star Child", "Wintersun")
        self.assertEqual(Songs.objects.count(), 1)


class ViewTestCase(TestCase):

    @staticmethod
    def create_new_song(title="", artist=""):
        if (title is not None or title != "") and (artist is not None or artist != ""):
            Songs.objects.create(title=title, artist=artist)

    def login_a_user(self, username="", password=""):
        return self.client.post(reverse("auth-login"), data={'username':username, 'password':password}, format="json")

    def user_login(self, username="", password=""):
        # get a token from DRF
        response = self.client.post(reverse('create-token'), data={'username':username, 'password':password}, format="json")
        self.token = response.data['token']

        # set token in the header
        self.client.credentials(HTTP_AUTHORIZATION='Bearer '+ self.token)

        self.client.login(username=username,password=password)

        return self.token

    def setUp(self):
        self.client = APIClient()

        # Create admin user
        self.user = User.objects.create_superuser(
            username="test_user",
            email="test@mail.com",
            password="testing",
            first_name="test",
            last_name="user",
        )

        """Create a few songs for testing the GET endpoint"""
        self.create_new_song("Winter Madness","Wintersun")
        self.create_new_song("Endless War","Norther")
        self.create_new_song("Wanderer of Time","Ensiferum")


    def test_login_user_with_valid_credentials(self):
        resp = self.login_a_user("test_user", "testing")
        
        # assert that the token exists
        self.assertIn("token", resp.data)

        # assert that the status is 200
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        # test login with invalid credentials
        resp = self.login_a_user("false_user","wrongpassword")
        # assert status code 401 UNAUTHORISED
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_register_a_user_with_valid_data(self):
        response = self.client.post(reverse('auth-register'), data={
            'username':'new_user',
            'password':'new_pass',
            'email':'new_user@email.com'
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    
    def test_register_a_user_with_invalid_data(self):
        response = self.client.post(reverse('auth-register'), data={
            'username':'',
            'password':'',
            'email':''
        }, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_all_songs(self):
        self.user_login('test_user','testing')
        resp = self.client.get(reverse("songs-all"),format="json")

        # data from db
        expected = Songs.objects.all()
        serialized = SongSerializer(expected, many=True)

        # assertion tests
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data, serialized.data)

    def test_change_password(self):
        
        #change password for test user
        self.user_login('test_user','testing')
        response = self.client.put(reverse("auth-reset-password"), data={
            'old_password':'testing',
            'new_password':'new_password_changed'
        }, format="json")
        self.assertEqual(response.status_code,status.HTTP_202_ACCEPTED)

    def test_user_logout(self):
        # create new user
        user = User.objects.create_user(
            username="login_user", 
            email="login@user.com", 
            password="login_pwd"
        )
        
        # login client
        t_client = APIClient()
        response = t_client.post(reverse("auth-login"), data={'username':user.username,'password':'login_pwd'}, format="json")
        
        # assert that the status is 200
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        

        # verify successful login
        self.assertIn("token", response.data)
        
        # set token in the header for our client
        token = response.data['token']
        t_client.credentials(HTTP_AUTHORIZATION='Bearer '+ token)

        # logout request
        response = t_client.get(reverse("auth-logout"), format="json")
        print(response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # try and fetch songs while unauthenticated
        response = t_client.get()
        
        