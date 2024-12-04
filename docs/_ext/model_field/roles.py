from django.utils.module_loading import import_string

from docutils import nodes
from sphinx.util.docutils import SphinxRole

from .utils import get_field_representation


class ModelFieldRole(SphinxRole):
    """Displays a model field's name, helptext and default inline"""

    def run(self) -> tuple[list[nodes.Node], list[nodes.system_message]]:

        field_split = len(self.text) - self.text[::-1].index(".") - 1
        model_path = self.text[:field_split]
        field_name = self.text[field_split + 1 :]

        model = import_string(model_path)
        field = model._meta.get_field(field_name)

        field_nodes = get_field_representation(field)
        return field_nodes, []
