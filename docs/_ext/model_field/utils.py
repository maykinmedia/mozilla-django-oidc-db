from django.db.models.fields import Field

from docutils import nodes


def get_field_representation(field: Field) -> list[nodes.literal | nodes.Text]:

    name = nodes.literal("", nodes.Text(field.name))
    description = nodes.Text(f": {field.help_text}.")

    field_nodes = [name, description]

    # Should it include blank that default to empty string?
    if field.has_default():
        field_nodes.append(nodes.Text(" Defaults to "))
        field_nodes.append(nodes.literal("", nodes.Text(field.get_default())))
    else:
        field_nodes.append(nodes.Text(" No default."))

    return field_nodes
