from sphinx.application import Sphinx
from sphinx.util.typing import ExtensionMetadata

from .directives import ModelFieldsDirective
from .roles import ModelFieldRole


def setup(app: Sphinx) -> ExtensionMetadata:
    app.add_role("model_field", ModelFieldRole())
    app.add_directive("model_fields", ModelFieldsDirective)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
