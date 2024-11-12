# lock/forms.py
from django import forms
from django.contrib.auth.models import User
from .models import AdminSettings

class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    class Meta:
        model = User
        fields = ['username', 'password']

class AdminRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    



class AdminSettingsForm(forms.ModelForm):

    class Meta:
        model = AdminSettings
        fields = ['restricted_start', 'restricted_end']
        widgets = {
            'restricted_start': forms.TimeInput(format='%H:%M', attrs={'type': 'time'}),
            'restricted_end': forms.TimeInput(format='%H:%M', attrs={'type': 'time'}),
        }
        labels = {
            'restricted_start': 'Restricted Start Time',
            'restricted_end': 'Restricted End Time',
        }