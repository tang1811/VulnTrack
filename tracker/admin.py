from django.contrib import admin

from .models import Asset, ImportLog, StatusHistory, Vulnerability, VulnCategory


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip_address', 'asset_type', 'location', 'is_active')
    list_filter = ('asset_type', 'location', 'is_active')
    search_fields = ('hostname', 'ip_address')


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'title', 'severity', 'category', 'asset', 'status', 'assigned_to', 'fixed_by', 'found_at')
    list_filter = ('severity', 'status', 'category')
    search_fields = ('cve_id', 'title', 'asset__hostname')


@admin.register(VulnCategory)
class VulnCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'sort_order', 'is_active')
    list_editable = ('sort_order', 'is_active')


admin.site.register(StatusHistory)
admin.site.register(ImportLog)
