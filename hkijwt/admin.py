from django.contrib import admin
from parler.admin import TranslatableAdmin

from .models import (
    Api, ApiPermission, ApiPermissionTranslation, AppToAppPermission)


class DontRequireIdentifier(object):
    def formfield_for_dbfield(self, db_field, request, **kwargs):
        field = super(DontRequireIdentifier, self).formfield_for_dbfield(
            db_field, request, **kwargs)
        print(field)
        if db_field.name == 'identifier':
            field.required = False
        return field


@admin.register(Api)
class ApiAdmin(admin.ModelAdmin):
    list_display = ['identifier', 'audience', 'scopes_string']


@admin.register(ApiPermission)
class ApiPermissionAdmin(DontRequireIdentifier, TranslatableAdmin):
    list_display = ['identifier', 'api', 'specifier', 'name', 'description']
    search_fields = ['identifier', 'api__identifier', 'specifier',
                     'translations__name', 'translations__description']
    readonly_fields = ['identifier']
    fieldsets = (
         (None, {
             'fields': ('identifier', 'api', 'specifier',
                        'name', 'description', 'allowed_apps'),
         }),
    )


@admin.register(ApiPermissionTranslation)
class ApiPermissionTranslationAdmin(admin.ModelAdmin):
    list_filter = ['master', 'language_code']
    list_display = ['master', 'language_code', 'name', 'description']


class AppToAppPermissionAdmin(admin.ModelAdmin):
    pass
admin.site.register(AppToAppPermission, AppToAppPermissionAdmin)
