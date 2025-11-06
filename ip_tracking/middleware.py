from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP


class RequestLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')

        # Block if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP has been blocked.")

        # Try to get cached geolocation
        cached_geo = cache.get(ip)
        if cached_geo:
            country, city = cached_geo
        else:
            # Get geolocation from django-ip-geolocation middleware
            geo = getattr(request, 'geolocation', None)
            if geo:
                country = geo.get('country_name', '') or ''
                city = geo.get('city', '') or ''
            else:
                country = ''
                city = ''

            # Cache result for 24 hours (86400 seconds)
            cache.set(ip, (country, city), 60 * 60 * 24)

        # Log the request
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=country,
            city=city
        )

        return self.get_response(request)
