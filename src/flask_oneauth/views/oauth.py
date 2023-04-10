from flask import redirect, url_for, current_app

from flask_oneauth import helpers


@current_app.route("/<provider>")
def facebook_oauth(provider):
    proxy = helpers.import_attr(f"flask_dance.contrib.{provider}.{provider}")
    if not proxy.authorized:
        return redirect(url_for("facebook.login"))
    resp = proxy.get("/user")
    assert resp.ok
    return "You are @{login} on GitHub".format(login=resp.json()["login"])






