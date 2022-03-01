# `classproperty` was moved to another module in Django 3.1
# See https://github.com/django/django/blob/ca9872905559026af82000e46cde6f7dedc897b6/docs/releases/3.1.txt#L649
try:
    from django.utils.functional import classproperty
except ImportError:
    from django.utils.decorators import classproperty
