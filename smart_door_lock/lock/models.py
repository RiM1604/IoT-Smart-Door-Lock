
# lock/models.py
from django.contrib.auth.models import User
from django.db import models
import pickle
from datetime import time


class AdminSettings(models.Model):
    restricted_start = models.TimeField(default=time(0,0))
    restricted_end = models.TimeField(default=time(0,0))

    @staticmethod
    def get_settings():
        # Get the existing AdminSettings instance or create a new one
        return AdminSettings.objects.first() or AdminSettings.objects.create()
    


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    face_encoding = models.BinaryField(null=True, blank=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)

    def get_face_encoding(self):
        if self.face_encoding:
            return pickle.loads(self.face_encoding)
        return None

class AccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=10)  # 'open' or 'close'
    timestamp = models.DateTimeField(auto_now_add=True)