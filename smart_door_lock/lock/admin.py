from django.contrib import admin
from .models import AdminSettings, AccessLog
# Register your models here.


admin.site.register(AdminSettings)
admin.site.register(AccessLog)