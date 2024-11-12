# lock/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('register_user/', views.register_user, name='register_user'),
    path('unlock_door/', views.unlock_door, name='unlock_door'),
    path('lock_door/', views.lock_door, name='lock_door'),
    path('account_login/', views.account_login, name='account_login'),
    path('account_logout/',views.account_logout, name='account_logout'),
    path('user_dashboard',views.user_dashboard,name='user_dashboard'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin_dashboard/edit/<int:restriction_id>/',views.update_restriction, name='update_restriction'),
    path('admin_dashboard/remove/<int:restriction_id>/', views.remove_restriction, name='remove_restriction'),
    path('admin_dashboard/add/',views.add_restriction, name='add_restriction'),
    path('access_logs/', views.access_logs_view, name='access_logs'),
    path('status/', views.lock_status, name='lock_status'),
    path('rfid_access/', views.rfid_access, name='rfid_access'),
]
