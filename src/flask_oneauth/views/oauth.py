from flask import redirect, url_for, current_app

from flask_oneauth import helpers, ImproperlyConfigured


@current_app.route("/<name>")
def provider_oauth(name):
    provider = validate_provider(name)
    if not provider.authorized:
        return redirect(url_for(f"{name}.login"))
    resp = provider.get("/user")
    assert resp.ok
    return "You are @{login} on {provider}"\
        .format(provider=name, login=resp.json()["login"])


def validate_provider(name, raise_exc=True):
    try:
        provider = helpers.import_attr(f"flask_dance.contrib.{name}.{name}")
    except ImportError as e:
        if raise_exc:
            raise ImproperlyConfigured(f"No such provider {name}")
        provider = None
    return provider
