# from datetime import timezone
import random 
import string
from django.http import Http404
from django.utils import timezone
from .models import LinkMapping 
from django.core.exceptions import ValidationError
from django.core.cache import cache
def shorten(url, custom_hash=None):
    if custom_hash:
    # check if custom hash is already exists
        if LinkMapping.objects.filter(hash=custom_hash).exists():
            raise ValidationError("This custom URL is already taken. Please choose another.")

        
        mapping = LinkMapping(original_url=url, hash=custom_hash, creation_date=timezone.now())
        mapping.save()
        return custom_hash

    else:
        while True:
            random_hash = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(7))

            if not LinkMapping.objects.filter(hash=random_hash).exists():
                mapping = LinkMapping(original_url = url, hash=random_hash, creation_date=timezone.now())
                mapping.save()
                return random_hash
def load_url(url_hash):
    cached_mapping = cache.get(f'url_{url_hash}')
    if cached_mapping:
        return cached_mapping
    try:
        mapping =  LinkMapping.objects.get(hash=url_hash)
    except LinkMapping.DoesNotExist:
        raise Http404("URL not found")
    
    cache.set(f'url_{url_hash}', mapping, 3600)
    return mapping