from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("shorten", views.shorten_post, name="shorten_post"),
    path("shorten/<str:url>", views.shorten, name="shorten"),
    path("<str:url_hash>", views.redirect_hash, name="redirect"),
    path('login/', auth_views.LoginView.as_view(template_name='main/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register, name='register'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path("stats/<str:url_hash>/", views.stats, name="stats"),
    path("deactivate/<str:url_hash>/", views.deactivate_link, name="deactivate_link"),
    path("activate/<str:url_hash>/", views.activate_link, name="activate_link"),
    path("claim/", views.claim_link, name="claim_link"),
]
