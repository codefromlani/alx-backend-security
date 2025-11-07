from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit

@csrf_exempt
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    """
    Example sensitive view (e.g., login) protected by rate limiting.
    Authenticated users: 10 requests/min
    Anonymous users: 5 requests/min
    """
    if request.method == 'POST':
        # Simulate login logic
        return JsonResponse({"message": "Login attempt received."})
    return JsonResponse({"error": "POST required"}, status=405)
