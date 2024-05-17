from typing import Any

import pytest

from mozilla_django_oidc_db.config import dynamic_setting


class ConfigProvider:
    def get_settings(self, attr: str, *args: Any) -> Any: ...

    SETTING_WITHOUT_DEFAULT = dynamic_setting[str]()
    SETTING_WITH_DEFAULT = dynamic_setting(default=123)


@pytest.mark.parametrize(
    "attribute,expected",
    [
        ("SETTING_WITHOUT_DEFAULT", "<dynamic_setting SETTING_WITHOUT_DEFAULT>"),
        (
            "SETTING_WITH_DEFAULT",
            "<dynamic_setting SETTING_WITH_DEFAULT (default: 123)>",
        ),
    ],
)
def test_representation_class_attribute(attribute: str, expected: str):
    setting = getattr(ConfigProvider, attribute)

    assert repr(setting) == expected


def test_dynamic_settings_are_data_descriptors():
    instance = ConfigProvider()

    with pytest.raises(AttributeError):
        instance.SETTING_WITHOUT_DEFAULT = "something else"
