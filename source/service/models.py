from django.db import models
from datetime import datetime
from django.contrib.auth.models import User, Group
from django.shortcuts import reverse
from django.dispatch import receiver
from django.urls import reverse


class Questions(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200 , default="No Title")
    question = models.TextField(max_length=10000)
    date = models.DateField(auto_now=datetime.now())

    class Meta:
        ordering = ['-date']

    def get_absolute_url(self):
        """Returns the url to access a particular instance of MyModelName."""
        return reverse('question_detail', args=[str(self.id)])

    def __str__(self):
        """String for representing the MyModelName object (in Admin site etc.)."""
        return self.title

class Answers(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    question = models.ManyToManyField(Questions)
    answer = models.TextField(default="Test Answer")
    date = models.DateField(auto_now=datetime.now())




