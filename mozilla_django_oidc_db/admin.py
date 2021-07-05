from django.contrib import admin

from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from solo.admin import SingletonModelAdmin

from .models import OpenIDConnectConfig


@admin.register(OpenIDConnectConfig)
class OpenIDConnectConfigAdmin(DynamicArrayMixin, SingletonModelAdmin):
    pass
