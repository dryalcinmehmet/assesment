from django.contrib.auth.models import User
from rest_framework.test import APITestCase, force_authenticate
from .models import Questions, Answers

class SnippetTestCase(APITestCase):
    def setUp(self):
        self.username = 'john_doe'
        self.password = 'foobar'
        self.user = User.objects.create(username=self.username, password=self.password)
        self.client.force_authenticate(user=self.user)

    def question_post(self):
        response = self.client.post('/questions/', {'title': 'Foo Bar', 'question':"What?"}, format='json')
        self.assertEqual(response.status_code, 200)

    def question_get(self):
        response = self.client.get('/questions/')
        self.assertEqual(response.status_code, 200)