from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import User, Answers
from django.forms import DateTimeField


class QuoteForm(forms.ModelForm):
	class Meta:
		model = Answers
		fields = ('answer',)

class SignupForm(UserCreationForm):
	email = forms.EmailField(max_length = 254, required = True)

	class Meta:
		model = User
		fields = ('email',)
