# main/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from django.db.models import F
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.conf import settings
from .models import LinkMapping, ClickLog
from datetime import timedelta
from . import service
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
import qrcode
import base64
from io import BytesIO
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator
from django.core.cache import cache
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, logout
from django.db import IntegrityError
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver 
import logging
import secrets

logger = logging.getLogger(__name__)


# -------------------------
# Helper utilities
# -------------------------
def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _user_can_access_link(request, link: LinkMapping):
    """
    Return True if request user or session or passed token authorizes access to link.
    """
    # Owner by account
    if request.user.is_authenticated and link.user_id == getattr(request.user, "id", None):
        return True

    # Owner by session token saved at creation time
    sess_token = request.session.get(f'link_owner_{link.hash}')
    if sess_token and link.owner_token and sess_token == link.owner_token:
        return True

    # Owner by explicit token in querystring
    passed = request.GET.get('owner_token')
    if passed and link.owner_token and passed == link.owner_token:
        # optionally store in session for future convenience
        request.session[f'link_owner_{link.hash}'] = passed
        return True

    return False


# -------------------------
# Index / Home
# -------------------------
def index(request):
    # ensure user sees the form; index.html must include a form for shortening
    return render(request, 'main/index.html')


# -------------------------
# Shorten logic (public)
# -------------------------
def shorten(request, url):
    """
    Core shorten logic. URL string is passed in; request.POST used for optional fields.
    """
    custom_hash = request.POST.get('custom_hash', None)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        shortened_url_hash = service.shorten(url, custom_hash)

        # expiry
        expire_days = request.POST.get('expire_days')
        expires_at = None
        if expire_days:
            try:
                expires_at = timezone.now() + timedelta(days=int(expire_days))
            except ValueError:
                expires_at = None

        # Prepare defaults; attach user if authenticated
        defaults = {'original_url': url}
        if request.user.is_authenticated:
            defaults['user'] = request.user

        lm, created = LinkMapping.objects.get_or_create(hash=shortened_url_hash, defaults=defaults)

        lm.is_active = True
        if expires_at:
            lm.expires_at = expires_at

        # If anonymous, ensure owner_token exists and store it in session so the same browser can access stats
        if request.user.is_authenticated:

            if lm.user_id != request.user.id:
                lm.user = request.user
            # If it had an owner_token from anonymous creation, clear it since user now owns it
            if lm.owner_token is not None:
                lm.owner_token = None
            # Persist only the changed/important fields
            save_fields = ['is_active']
            if expires_at:
                save_fields.append('expires_at')
            # include user/owner_token only if we changed them
            save_fields.extend(f for f in ('user', 'owner_token') if f in save_fields or getattr(lm, f, None) is not None)
            # Simpler: explicitly call save with the fields we know we may have changed
            lm.save(update_fields=['is_active', 'expires_at', 'owner_token', 'user'] if expires_at else ['is_active', 'owner_token', 'user'])
        else:
            if not lm.owner_token:
                lm.owner_token = secrets.token_urlsafe(24)
            # Save necessary fields (owner_token + is_active + expires_at if set)
            if expires_at:
                lm.save(update_fields=['owner_token', 'is_active', 'expires_at'])
            else:
                lm.save(update_fields=['owner_token', 'is_active'])
            # store token in session for browser convenience
            request.session[f'link_owner_{lm.hash}'] = lm.owner_token
        # else:
        #     # authenticated user
        #     lm.save(update_fields=['is_active', 'expires_at'] if expires_at else ['is_active'])

        shortened_url = request.build_absolute_uri(reverse('redirect', args=[shortened_url_hash]))

        # QR generation
        qr = qrcode.QRCode(version=1,
                           error_correction=qrcode.constants.ERROR_CORRECT_L,
                           box_size=10, border=4)
        qr.add_data(shortened_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_img = base64.b64encode(buffer.getvalue()).decode()

        lm.refresh_from_db()
        context = {
            'shortened_url': shortened_url,
            'original_url': url,
            'hash': shortened_url_hash,
            'qr_img': qr_img,
            'click_count': lm.click_count,
            'owner_token': lm.owner_token if not request.user.is_authenticated else None,
        }

        messages.success(request, "🎉 Your link has been shortened successfully!")
        return render(request, 'main/link.html', context)

    except ValidationError as e:
        messages.error(request, f"❌ {e.messages[0]}")
        return render(request, 'main/index.html', {
            'url': url,
            'custom_hash': custom_hash
        })
    except Exception as exc:
        logger.exception("shorten failed: %s", exc)
        messages.error(request, "Failed to shorten URL. Please try again.")
        return redirect('index')


def shorten_post(request):
    """
    Receives POST from the client-side shorten form.
    Make sure template includes {% csrf_token %}.
    """
    return shorten(request, request.POST.get('url', '').strip())


# -------------------------
# Dashboard (user's links)
# -------------------------
@login_required(login_url='/login/')
def dashboard(request):
    qs = LinkMapping.objects.filter(user=request.user).order_by('-creation_date')
    paginator = Paginator(qs, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'main/dashboard.html', {'page_obj': page_obj})


# -------------------------
# Register (fixed + auto-claim)
# -------------------------
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
            except IntegrityError:
                form.add_error('username', 'A user with that username already exists.')
                return render(request, 'main/register.html', {'form': form})
            # login(request, user)
            messages.success(request, "Welcome! Your account has been created.")

            # Auto-claim session-owned links for this user
            claimed = 0
            # iterate copy of keys to avoid runtime modif issues
            for key in list(request.session.keys()):
                if key.startswith('link_owner_'):
                    link_hash = key.split('link_owner_', 1)[1]
                    token = request.session.get(key)
                    if not token:
                        continue
                    try:
                        lm = LinkMapping.objects.get(hash=link_hash, owner_token=token, user__isnull=True)
                    except LinkMapping.DoesNotExist:
                        continue
                    lm.user = user
                    lm.owner_token = None
                    lm.save(update_fields=['user', 'owner_token'])
                    claimed += 1
                    # remove from session
                    try:
                        del request.session[key]
                    except KeyError:
                        pass

            if claimed:
                messages.success(request, f"{claimed} link(s) were added to your dashboard.")

            return redirect(f"{reverse('login')}?next={reverse('dashboard')}")
    else:
        form = UserCreationForm()
    return render(request, 'main/register.html', {'form': form})


# -------------------------
# Stats (access checked: session token OR logged-in owner OR passed token)
# -------------------------

# @login_required(login_url='/login/')
def stats(request, url_hash):
    """
    Show stats if:
    - Logged-in user is owner, OR
    - Session contains 'link_owner_<hash>' token that matches, OR
    - URL contains ?owner_token=... that matches (and then we store it in session).
    Otherwise redirect to login with next param.
    """
    # lm = get_object_or_404(LinkMapping, hash=url_hash, user=request.user)
    lm = get_object_or_404(LinkMapping, hash=url_hash)

    if not _user_can_access_link(request, lm):
        # redirect to login and preserve next -> user can login to claim/see stats
        return redirect(f"{reverse('login')}?next={reverse('stats', args=[url_hash])}")

    # authorized: render stats
    # logs = lm.clicks.only('clicked_at', 'ip', 'user_agent', 'referrer').order_by('-clicked_at')[:25]
    logs = lm.clicks.order_by('-clicked_at')[:25]
    shortened_url = request.build_absolute_uri(reverse('redirect', args=[lm.hash]))

    qr = qrcode.QRCode(version=1,
                       error_correction=qrcode.constants.ERROR_CORRECT_L,
                       box_size=10, border=4)
    qr.add_data(shortened_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_img = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'main/stats.html', {
        'link': lm,
        'logs': logs,
        'shortened_url': shortened_url,
        'qr_img': qr_img,
    })


# -------------------------
# Redirect handler (counts clicks)
# -------------------------
@never_cache
def redirect_hash(request, url_hash):
    lm = get_object_or_404(LinkMapping, hash=url_hash)
    if not lm.is_active or lm.is_expired:
        return render(request, 'main/deactivated.html', {'link': lm}, status=410)

    # Log click
    ClickLog.objects.create(
        link=lm,
        ip=_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        referrer=request.META.get('HTTP_REFERER', '')
    )

    LinkMapping.objects.filter(pk=lm.pk).update(click_count=F('click_count') + 1)
    return redirect(lm.original_url)


# -------------------------
# Activate / Deactivate
# -------------------------
@require_POST
@login_required(login_url='/login/')
def deactivate_link(request, url_hash):
    qs = LinkMapping.objects.filter(hash=url_hash)
    
    if not request.user.is_staff:
        qs = qs.filter(user=request.user)

    updated = qs.update(is_active=False)
    cache.delete(f'url_{url_hash}')

    next_action_url = reverse('activate_link', args=[url_hash])
    is_ajax = (request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest') or ('application/json' in request.headers.get('Accept', ''))

    if is_ajax:
        return JsonResponse({'status': 'ok' if updated else 'not_found', 'is_active': False, 'next_action_url': next_action_url})

    if updated:
        messages.warning(request, "⚠️ Link has been deactivated.")
        return redirect('dashboard')
    return HttpResponseForbidden('Not allowed or link not found')


@require_POST
@login_required(login_url="/login/")
def activate_link(request, url_hash):
    qs = LinkMapping.objects.filter(hash=url_hash)
    if not request.user.is_staff:
        qs = qs.filter(user=request.user)

    updated = qs.update(is_active=True)
    cache.delete(f'url_{url_hash}')

    next_action_url = reverse('deactivate_link', args=[url_hash])
    is_ajax = (request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest') or ('application/json' in request.headers.get('Accept', ''))

    if is_ajax:
        return JsonResponse({'status': 'ok' if updated else 'not_found', 'is_active': True, 'next_action_url': next_action_url})

    if updated:
        messages.success(request, "✅ Link has been activated successfully!")
        return redirect('dashboard')
    return HttpResponseForbidden('Not allowed or link not found')


# -------------------------
# Claim link view (optional)
# -------------------------
@login_required
def claim_link(request):
    if request.method == 'POST':
        link_hash = request.POST.get('hash')
        token = request.POST.get('owner_token')
        if not link_hash or not token:
            messages.error(request, "Please provide both link hash and owner token.")
            return redirect('dashboard')
        try:
            lm = LinkMapping.objects.get(hash=link_hash, owner_token=token)
        except LinkMapping.DoesNotExist:
            messages.error(request, "Invalid link or token.")
            return redirect('dashboard')
        lm.user = request.user
        lm.owner_token = None
        lm.save(update_fields=['user', 'owner_token'])
        messages.success(request, "Link claimed successfully and added to your dashboard.")
        return redirect('stats', url_hash=lm.hash)
    return render(request, 'main/claim.html')


@receiver(user_logged_in)
def claim_links_on_login(sender, user, request, **kwargs):
    """
    When a user logs in, check session keys like 'link_owner_<hash>' and
    claim matching LinkMapping rows that are anonymous (user__isnull=True) and
    owner_token matches. This moves those links into the newly-logged-in account.
    """
    # iterate over a snapshot of keys to avoid runtime modification issues
    for key in list(request.session.keys()):
        if not key.startswith('link_owner_'):
            continue
        link_hash = key.split('link_owner_', 1)[1]
        token = request.session.get(key)
        if not token:
            continue
        try:
            lm = LinkMapping.objects.get(hash=link_hash, owner_token=token, user__isnull=True)
        except LinkMapping.DoesNotExist:
            # nothing to claim
            try:
                del request.session[key]
            except KeyError:
                pass
            continue
        # claim
        lm.user = user
        lm.owner_token = None
        lm.save(update_fields=['user', 'owner_token'])
        # remove session key after successful claim
        try:
            del request.session[key]
        except KeyError:
            pass

def logout_view(request):
    """Log out the user and redirect to login."""
    logout(request)
    return redirect('login')