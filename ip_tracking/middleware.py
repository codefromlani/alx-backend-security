from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class RequestLogMiddleware:
    """
    Middleware that logs requests and blocks IPs on the blacklist.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')

        # Block if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP has been blocked.")

        # Log the request
        RequestLog.objects.create(ip_address=ip, path=request.path)

        response = self.get_response(request)
        return response
