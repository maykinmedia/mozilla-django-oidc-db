from django.contrib import admin

from django_better_admin_arrayfield.admin.mixins import DynamicArrayMixin
from solo.admin import SingletonModelAdmin

from .forms import OpenIDConnectConfigForm
from .models import OpenIDConnectConfig


@admin.register(OpenIDConnectConfig)
class OpenIDConnectConfigAdmin(DynamicArrayMixin, SingletonModelAdmin):
    form = OpenIDConnectConfigForm
