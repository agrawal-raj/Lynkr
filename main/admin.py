# main/admin.py
from django.contrib import admin
from .models import LinkMapping, ClickLog

@admin.register(LinkMapping)
class LinkMappingAdmin(admin.ModelAdmin):
    list_display = ('hash','original_url','is_active','expires_at','click_count','creation_date')
    list_filter = ('is_active',)
    search_fields = ('hash','original_url')

@admin.register(ClickLog)
class ClickLogAdmin(admin.ModelAdmin):
    list_display = ('link','clicked_at','ip')
    search_fields = ('link__hash','ip')
