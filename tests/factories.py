import factory


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = "auth.User"


class StaffUserFactory(UserFactory):
    is_staff = True
