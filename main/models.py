from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
import re
from django.conf import settings
# Create your models here.

class LinkMapping(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete = models.CASCADE,
        related_name = 'links',
        null = True, blank = True,
    )
    original_url = models.CharField(max_length=2000)
    hash = models.CharField(max_length=30, unique= True, db_index= True)
    creation_date = models.DateTimeField(auto_now_add=True)
    is_custom = models.BooleanField(default=False)
    owner_token = models.CharField(max_length=64, null=True, blank=True, db_index=True)

    # NEW
    is_active = models.BooleanField(default=True)         # deactivate/activate
    expires_at = models.DateTimeField(null=True, blank=True)  # expiry timer
    click_count = models.PositiveIntegerField(default=0)       # quick counter

    def clean(self):
        if self.is_custom and not re.match(r'^[a-zA-Z0-9_-]+$', self.hash):
            raise ValidationError("Custom URL can only contain letters, numbers, hyphens, and underscores.")

    @property
    def is_expired(self):
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    def __str__(self):
        return f"{self.original_url} → {self.hash}"
    
# NEW: detailed click logs
class ClickLog(models.Model):
    link = models.ForeignKey(LinkMapping, on_delete=models.CASCADE, related_name='clicks')
    clicked_at = models.DateTimeField(auto_now_add=True, db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    referrer = models.URLField(max_length=2000, blank=True)

# URL Class
class URL(models.Model):
    original_url = models.TextField()
    short_code = models.CharField(max_length=20, unique=True)
    clicks = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)