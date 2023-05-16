from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def is_analyst_staff(context):
    user = context["request"].user
    if user.role == "Analyst" and user.is_staff:
        return True
    return False
