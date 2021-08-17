import os
import re
from time import sleep
from django.contrib.auth.models import User, Group
from rest_framework import viewsets
from rest_framework import permissions
from .serializers import UserSerializer, GroupSerializer, AnswersSerializer, QuestionSerializer, ListdirSerializer
from django.views.generic import TemplateView, ListView, DetailView
from django.shortcuts import render
from .version import Version
from django.contrib.auth import get_user_model
from .models import Questions, Answers
from django.shortcuts import get_object_or_404
from .forms import SignupForm
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from .forms import QuoteForm
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework.validators import ValidationError
from rest_framework import mixins as mixins
from rest_framework.decorators import api_view
from rest_framework import serializers
from rest_framework import generics, permissions
from rest_framework.response import Response
from .serializers import UserSerializer, CreateUserSerializer, LoginUserSerializer, LogoutUserSerializer, ChangePasswordSerializer
from rest_framework import status
from django.dispatch import receiver
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from rest_framework.views import APIView
from rest_framework import parsers, renderers, status
from rest_framework.response import Response
from rest_framework.exceptions import APIException

from django_rest_passwordreset.models import ResetPasswordToken
from django_rest_passwordreset.views import get_password_reset_token_expiry_time
from django.utils import timezone
from datetime import timedelta


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]

class AnswerViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Answers.objects.all()
    serializer_class = AnswersSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, BasicAuthentication]
    permission_classes = [permissions.IsAuthenticated]

class QuestionViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Questions.objects.all()
    serializer_class = QuestionSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, BasicAuthentication]
    permission_classes = [permissions.IsAuthenticated]

class LoginAPI(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = LoginUserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": str(Token.objects.get_or_create(user=user)[0])
        })

class LogoutAPI(APIView):
    queryset = User.objects.all()
    serializer_class = LogoutUserSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)

class RegistrationAPI(generics.GenericAPIView):
    queryset = User.objects.all()
    serializer_class = CreateUserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": str(Token.objects.create(user=user))
        })

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    authentication_classes = [TokenAuthentication, SessionAuthentication, BasicAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })

class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "index.html"

class PasswordResetView(TemplateView):
    template_name = "auth/password_reset_form.html"

    def get(self, request, *args, **kwargs):
        form = PasswordResetForm()
        return render(request, self.template_name, {
            'form': form
        })

    def post(self, request):
        if request.method == 'POST':
            form = PasswordResetForm(request.user, request.POST)
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)  # Important!
                messages.success(request, 'Şifreniz başarıyla değiştirildi!')
                return redirect('password_reset_complete')
            else:
                return render(request, self.template_name, {
                    'errors': "Mevcut şifrenizi ve yeni şifrelerinizi doğru girdiğinizden emin olun!."
                })
        else:
            form = PasswordChangeForm(request.user)
        return render(request, self.template_name, {
            'form': form
        })

class PasswordChangeView(LoginRequiredMixin, TemplateView):
    template_name = "auth/password_change_form.html"
    login_url = 'login'

    def get(self, request, *args, **kwargs):
        form = PasswordChangeForm(request.user)
        return render(request, self.template_name, {
            'form': form
        })

    def post(self, request):
        if request.method == 'POST':
#            import ipdb; ipdb.set_trace()
            form = PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)  # Important!
                messages.success(request, 'Şifreniz başarıyla değiştirildi!')
                return redirect('login')
            else:
                return render(request, self.template_name, {
                    'errors': [v for v in form.errors.values()][0]
                })
        else:
            form = PasswordChangeForm(request.user)
        return render(request, self.template_name, {
            'form': form
        })

class PasswordChangeSuccessView(LoginRequiredMixin, TemplateView):
    template_name = "auth/password_reset_complete.html"
    login_url = 'login'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {
            'change_status': True
        })

class SignUpView(TemplateView):
    template_name = "auth/signup.html"
    login_url = 'login'

    def post(self, request, *args, **kwargs):
        form = SignupForm()
        if request.method == 'POST':
            form = SignupForm(request.POST)
            email = request.POST.get('email')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')

            if str(password1) != str(password2):
                return render(request, self.template_name,
                              {'register_error': 'Parolalar eşleşmiyor!'})

            if User.objects.filter(email=email).first():
                return render(request, self.template_name,
                              {'register_error': 'E-Mail adresiniz zaten sistemimizde kayıtlı!'})

            if form.is_valid():
                post = form.save(commit=False)
                post.username = email
                post.first_name = first_name
                post.last_name = last_name
                post.save()

                return redirect(self.login_url)

        return render(request, self.template_name, {'form': form})

class SignOutView(TemplateView):

    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            logout(self.request)
        return redirect('login')

class SignInView(TemplateView):
    template_name = "auth/login.html"


    def post(self, request, *args, **kwargs):
        if request.method == 'POST':
            email = request.POST.get('email')
            password = request.POST.get('password')
            UserModel = get_user_model()
            try:
                user = UserModel.objects.get(email=email)
                user = authenticate(username=user, password=password)
                if user:
                    if user.is_active:
                        login(request, user)
                        return redirect('home')
                    else:
                        return HttpResponse("Your account was inactive.")
                else:
                    return render(request, self.template_name,
                                  {'login_error': 'Bilgiler hatalı, lütfen tekrar deneyiniz!'})
            except:
                return render(request, self.template_name,
                              {
                                  'login_error': '%s e-maili ile ilişkili kullanıcı bulunmamaktadır. Önce siteye kayıt olunuz!' % email})

        else:
            return render(request, self.template_name, {})

class QuestionListView(LoginRequiredMixin, ListView):
    model = Questions
    template_name = "question_list.html"
    paginate_by = 10
    context_object_name = 'questions'

class QuestionDetailView(LoginRequiredMixin, DetailView):
    model = Questions
    template_name = "question_detail.html"
    context_object_name = 'question'

    def get_context_data(self, **kwargs):
        context = super(QuestionDetailView, self).get_context_data(**kwargs)
        token, created = Token.objects.get_or_create(user=self.request.user)
        context['answers'] = Answers.objects.filter(question=kwargs['object'])
        context['token'] = token
        context['form'] = QuoteForm()
        return context

class HealthCheckView(TemplateView):
    template_name = "version.html"

    def get(self):
        return render(self.request, self.template_name, {'version': Version})

class QuestionApiView(
                      mixins.DestroyModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
                      mixins.ListModelMixin,
                      mixins.CreateModelMixin,
                      generics.GenericAPIView):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Questions.objects.all()
    serializer_class = QuestionSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, BasicAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

class ListdirApiView(
                      mixins.DestroyModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
                      mixins.ListModelMixin,
                      mixins.CreateModelMixin,
                      generics.GenericAPIView):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = ""
    serializer_class = ListdirSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication, BasicAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        folder_name = self.request.POST.get('folder_name')

        try:

            special_char_check = re.compile('[@!#$%^&*()<>?/\|}{~:]')
            if special_char_check.search(folder_name):
                content = {"msg": "Folder name contains special char!"}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            folders = [x[0].split('/')[-1] for x in os.walk(os.getcwd())]
            if folder_name in folders:
                list_files = next(os.walk(folder_name), (None, None, []))[2]
                sleep(5)
                return Response({"list_files": list_files})
            else:
                content = {"msg": "Folder doesn't exist!"}
                return Response(content, status=status.HTTP_404_NOT_FOUND)

        except Exception as e: # 500 error
            raise APIException('500 Custom exception message!')



