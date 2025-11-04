from .models import RequestLog

class RequestLogMiddleware:
    """
    Middleware to log IP address, timestamp, and path of each incoming request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP address
        ip = request.META.get('REMOTE_ADDR')

        # Save log to the database
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path
        )

        response = self.get_response(request)
        return response
