from django.urls import path, include
from django.contrib.auth import views as auth_views
from .views import QuestionDetailView, PasswordChangeSuccessView, ListdirApiView,\
    RegistrationAPI, LoginAPI, LogoutAPI, ChangePasswordView

urlpatterns = [
    path('listdir/', ListdirApiView.as_view()),
    path('register/', RegistrationAPI.as_view()),
    path('login/', LoginAPI.as_view()),
    path('logout/', LogoutAPI.as_view()),
    path('change-password/', ChangePasswordView.as_view()),
    path('question-detail/<int:pk>/', QuestionDetailView.as_view(), name='question_detail'),
    path('password-reset/', auth_views.PasswordResetView.as_view(template_name = "auth/password_reset_form.html"), name ='password-reset'),
    path('reset_password_sent/',auth_views.PasswordResetDoneView.as_view(template_name = "auth/password_reset_done.html"), name ='password_reset_done'),
    path('reset/<uidb64>/<token>', auth_views.PasswordResetConfirmView.as_view(template_name = "auth/password_reset_confirm.html"), name ='password_reset_confirm'),
    path('password_reset_complete/', PasswordChangeSuccessView.as_view(), name='password_reset_complete'),

]