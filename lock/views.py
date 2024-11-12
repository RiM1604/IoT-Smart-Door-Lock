# lock/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import  AccessLog, AdminSettings
from .forms import UserRegistrationForm
from django.utils import timezone
import paho.mqtt.client as mqtt
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import logout
from .models import AdminSettings
import json
from django.utils.dateparse import parse_time
import requests
from django.conf import settings




# Adafruit IO MQTT configuration
client = mqtt.Client()

client.username_pw_set(settings.MQTT_USERNAME, settings.MQTT_KEY)
client.connect("io.adafruit.com", 1883, 60)
client.loop_start()

def publish_lock_command(command):
    client.publish(settings.MQTT_FEED, command)

def register_user(request):
    if request.user.is_superuser:
        if request.method == "POST":
            form = UserRegistrationForm(request.POST)
            if form.is_valid():
                user = form.save(commit=False)
                user.set_password(form.cleaned_data["password"])
                user.save()
                
                return redirect('account_login')
            else:   

                error_message = "\n".join([f"{field}: {', '.join(errors)}" for field, errors in form.errors.items()])
                message = "Form information not valid!"
                return render(request, 'lock/user_login.html', {'message':error_message})

        else:
            form = UserRegistrationForm()
        return render(request, 'lock/register_user.html', {'form': form})
    return redirect('user_dashboard')


def account_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        
        # Authenticate user credentials
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # User is authenticated, log them in
            auth_login(request, user)
            if user.is_superuser:
                return redirect('admin_dashboard')
            else:
                return redirect('user_dashboard')  # Redirect to your desired page
        else:
            # Invalid credentials, display error message
            message = "Invalid username or password."
            return render(request, 'lock/user_login.html', {'message': message})
    else:
        # Display login form
        return render(request, 'lock/user_login.html')


@login_required
def user_dashboard(request):
    # Get the current user and admin restriction settings
    user = request.user
    admin_settings = AdminSettings.objects.first()
    
    # Get access logs for the user dashboard (could be all or limited to recent entries)
    access_logs = AccessLog.objects.all().order_by('-timestamp')[:10]  # Showing last 10 actions

    return render(request, 'lock/user_dashboard.html', {
        'access_logs': access_logs,
        'restricted_start': admin_settings.restricted_start if admin_settings else None,
        'restricted_end': admin_settings.restricted_end if admin_settings else None,
    })


@login_required
def unlock_door(request):
    now = timezone.localtime().time()
    
    # Get the admin settings, and handle the case when it doesn't exist
    admin_settings = AdminSettings.objects.first()
    if admin_settings is None:
        # Handle the case where there are no admin settings
        publish_lock_command("OFF")
        AccessLog.objects.create(user=request.user, action="unlock", timestamp=now)
        return JsonResponse({"message": "Door unlocked"})
    
    # Check if the user is a superuser or if the current time is outside the restricted window
    if request.user.is_superuser or not (admin_settings.restricted_start <= now <= admin_settings.restricted_end):
        # Publish the unlock command and log the action
        publish_lock_command("OFF")
        AccessLog.objects.create(user=request.user, action="unlock", timestamp=now)
        return JsonResponse({"message": "Door unlocked"})
    
    # If access is restricted
    return JsonResponse({"error": "Access restricted"}, status=403)


@login_required
def account_logout(request):
    logout(request)
    return redirect('account_login')


@login_required
def lock_door(request):
    publish_lock_command("ON")
    current_time = timezone.localtime()
    AccessLog.objects.create(user=request.user, action="lock", timestamp=current_time)
    return JsonResponse({"message": "Door locked"})

# views for enabling the admin to create a restricted time.

@login_required
def admin_dashboard(request):
    access_logs = AccessLog.objects.all().order_by('-timestamp')[:10]
    restrictions = AdminSettings.objects.all()

    return render(request, 'lock/admin_dashboard.html', {
        'restrictions': restrictions,
        'access_logs': access_logs,
    })


@login_required
def access_logs_view(request):
    if request.method == "GET":
        # Retrieve the latest access logs
        access_logs = AccessLog.objects.all().order_by('-timestamp')[:10]  # Limit to the latest 10 logs
        logs_data = [
            {
                "user": {
                    "username": log.user.username
                },
                "action": log.action,
                "timestamp": timezone.localtime(log.timestamp).strftime("%b. %d, %Y, %I:%M %p").title()
            }
            for log in access_logs
        ]
        return JsonResponse({"access_logs": logs_data}, safe=False)


@login_required
def remove_restriction(request, restriction_id):
    if request.method == "POST":
        restriction = get_object_or_404(AdminSettings, id=restriction_id)
        restriction.delete()
        return JsonResponse({"success": True})
    return JsonResponse({"success": False}, status=405)


def update_restriction(request, restriction_id):
    restriction = get_object_or_404(AdminSettings, id=restriction_id)
    if request.method == "POST":
        data = json.loads(request.body)
        
        # Parse the time values from the request data
        restricted_start = parse_time(data.get("restricted_start"))
        restricted_end = parse_time(data.get("restricted_end"))
        
        # Update the restriction times if valid
        if restricted_start is not None and restricted_end is not None:
            restriction.restricted_start = restricted_start
            restriction.restricted_end = restricted_end
            restriction.save()
            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "error": "Invalid time format"}, status=400)

    return JsonResponse({"success": False}, status=405)

@login_required
def add_restriction(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        restricted_start = data.get('restricted_start')
        restricted_end = data.get('restricted_end')
        
        # Save new restriction
        AdminSettings.objects.create(
            restricted_start=restricted_start,
            restricted_end=restricted_end
        )
        return JsonResponse({'success': True})
    return JsonResponse({'success': False})




@login_required
def lock_status(request):
    # Adafruit IO URL for the lock feed
    adafruit_url = f"https://io.adafruit.com/api/v2/{settings.MQTT_USERNAME}/feeds/lock/data/last"

    # Fetch the latest feed data from Adafruit IO
    try:
        response = requests.get(
            adafruit_url,
            headers={"X-AIO-Key": settings.MQTT_KEY}
        )
        response.raise_for_status()  # Raise an error for bad responses

        # Parse the response JSON
        feed_data = response.json()
        feed_value = feed_data.get("value", "").upper()  # Expecting "ON" or "OFF"

        # Determine lock status based on the feed value
        if feed_value == "ON":
            status = "Locked"
        elif feed_value == "OFF":
            status = "Unlocked"
        else:
            status = "Unknown"  # Default when the feed value is unrecognized

    except requests.RequestException as e:
        # Handle any request-related errors
        print("Error fetching data from Adafruit IO:", e)
        status = "Error"  # Indicate an error status

    return JsonResponse({"status": status})

@login_required
def rfid_access(request):
    # Fetch the latest messages from Adafruit IO's rfidaccess feed
    url = f"https://io.adafruit.com/api/v2/{settings.MQTT_USERNAME}/feeds/rfidaccess/data"
    headers = {"X-AIO-Key": settings.MQTT_KEY}
    response = requests.get(url, headers=headers)
    
    rfid_data = response.json() if response.status_code == 200 else []
    
    # Render the page and pass the fetched data to the template
    return render(request, 'lock/rfid_access.html', {
        'rfid_data': rfid_data,
    })