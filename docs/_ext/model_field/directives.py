from __future__ import annotations

from django.utils.module_loading import import_string

from docutils import nodes
from sphinx.util.docutils import SphinxDirective

from .utils import get_field_representation


class ModelFieldsDirective(SphinxDirective):
    """Displays a model's fields with their name, helptext and default in a list"""

    required_arguments = 1
    has_content = True

    def run(self) -> list[nodes.Node]:

        model_path = self.arguments[0]
        model = import_string(model_path)

        field_list = []

        for line in self.content:
            field = model._meta.get_field(line)
            node = nodes.paragraph("", "", *get_field_representation(field))
            field_list.append(nodes.list_item("", node))

        bullet_list = nodes.bullet_list("", *field_list)

        return [bullet_list]
