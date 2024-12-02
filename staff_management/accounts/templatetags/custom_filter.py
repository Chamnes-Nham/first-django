from django import template

register = template.Library()  # Register the library of filters

@register.filter(name='get_item')
def get_item(dictionary, key):
    """Custom filter to access dictionary values by key."""
    try:
        return dictionary.get(key, None)
    except AttributeError:
        return None
