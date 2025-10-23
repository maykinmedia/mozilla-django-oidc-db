import factory


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:  # pyright: ignore[reportIncompatibleVariableOverride]
        model = "auth.User"


class StaffUserFactory(UserFactory):
    is_staff = True
