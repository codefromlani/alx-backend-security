from datetime import timedelta
from django.utils import timezone
from django.db import models
from celery import shared_task
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_activity():
    """
    Detect IPs exceeding 100 requests/hour or accessing sensitive paths.
    Flags them in SuspiciousIP.
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # Count requests per IP in the last hour
    ip_counts = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=models.Count('id'))
    )

    for entry in ip_counts:
        ip = entry['ip_address']
        count = entry['request_count']

        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': f'High request volume: {count} requests/hour'}
            )

    # Check for sensitive path access
    sensitive_logs = RequestLog.objects.filter(
        path__in=SENSITIVE_PATHS, timestamp__gte=one_hour_ago
    )

    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f'Accessed sensitive path: {log.path}'}
        )
