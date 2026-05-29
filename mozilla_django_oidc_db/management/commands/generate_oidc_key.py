from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        "Generate a new Fernet encryption key suitable for OIDC_DB_ENCRYPTION_KEY. "
        "Add the printed value to your Django settings."
    )

    def handle(self, *args, **options):
        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()
        self.stdout.write(key)
