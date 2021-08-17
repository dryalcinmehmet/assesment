from django.contrib import admin
from .models import Questions, Answers


class QuestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'question','date')

class AnswerAdmin(admin.ModelAdmin):
    list_display = ('id', 'answer','date')

admin.site.register(Questions, QuestionAdmin)
admin.site.register(Answers, AnswerAdmin)

# Register your models here.
