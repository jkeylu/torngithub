#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
#
# Copyright 2013 jKey Lu
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re
import functools
import tornado.httpclient

from tornado.auth import OAuth2Mixin, _auth_return_future, AuthError
from tornado.escape import to_basestring, parse_qs_bytes, native_str
from tornado.log import gen_log
from tornado.httputil import url_concat
from tornado.util import ObjectDict
from tornado.concurrent import chain_future

try:
    import ujson as json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        import json

def json_encode(value):
    return json.dumps(value).replace("</", "<\\/")

def json_decode(value):
    return json.loads(to_basestring(value))

GITHUB_API_URL = "https://api.github.com"

class GithubMixin(OAuth2Mixin):
    """Github authentication using OAuth2."""

    _OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                               code, callback, extra_fields=None):
        """Handles the login for the Github user, queries /user
        and returns a user object

        Example usage::

            class GithubLoginHandler(LoginHandler, torngithub.GithubMixin):
                @tornado.web.asynchronous
                @tornado.gen.coroutine
                def get(self):
                    if self.get_argument("code", False):
                        self.get_authenticated_user(
                            redirect_uri="/auth/github/",
                            client_id=self.settings["github_client_id"],
                            client_secret=self.settings["github_client_secret"],
                            code=self.get_argument("code"),
                            callback=self.async_callback(self._on_login))
                    else:
                        self.authorize_redirect(
                            redirect_uri="/auth/github/",
                            client_id=self.settings["github_client_id"],
                            extra_params={"scope", "user"})

                def _on_login(self, user):
                    # Save the user with e.g. set_secure_cookie
        """
        http = self.get_auth_http_client()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        fields = set(["id", "login", "name", "email", "avatar_url"])

        if extra_fields:
            fields.update(extra_fields)

        http.fetch(self._oauth_request_token_url(**args),
                   self.async_callback(self._on_access_token, redirect_uri,
                                       client_id, client_secret, callback, fields))

    def _on_access_token(self, redirect_uri, client_id, client_secret,
                         future, fields, response):
        if response.error:
            future.set_exception(
                AuthError("Github auth error: %s" % str(response)))
            return

        args = parse_qs_bytes(native_str(response.body))

        if "error" in args:
            future.set_exception(
                AuthError("Github auth error: %s" % args["error"][-1]))
            return

        session = {
            "access_token": args["access_token"][-1],
        }

        self.github_request(path="/user",
                            callback=self.async_callback(
                                self._on_get_user_info, future, session, fields),
                            access_token=session["access_token"])

    def _on_get_user_info(self, future, session, fields, res):
        if res.body is None:
            future.set_result(None)
            return

        fieldmap = {}
        for field in fields:
            fieldmap[field] = res.body.get(field)

        fieldmap.update({"access_token": session["access_token"]})
        future.set_result(fieldmap)

    @_auth_return_future
    def github_request(self, path, callback, access_token=None,
                       method="GET", body=None, **args):
        """Fetches the given relative API path, e.g., "/user/starred"

        Example usage::

            class MainHandler(tornado.web.RequestHandler, torngithub.GithubMixin):
                @tornado.web.authenticated
                @tornado.web.asynchronous
                def get(self):
                    self.github_request(
                        "/user/starred",
                        callback=_on_get_user_starred,
                        access_token=self.current_user["access_token"])

                def _on_get_user_starred(self, stars):
                    self.write(str(stars))
                    self.finish()
        """
        chain_future(github_request(self.get_auth_http_client(),
                                    path, None, access_token,
                                    method, body, **args), callback)

    def get_auth_http_client(self):
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overriddent by subclasses to use an HTTP client other than
        the default.
        """
        return tornado.httpclient.AsyncHTTPClient()

@_auth_return_future
def github_request(http_client, path, callback, access_token=None,
                   method="GET", body=None, **args):
    url = GITHUB_API_URL + path

    all_args = {}
    if access_token:
        all_args["access_token"] = access_token
    all_args.update(args)

    if all_args:
        url = url_concat(url, all_args)

    callback = functools.partial(_on_github_request, callback)

    if body is not None:
        body = json_encode(body)
    http_client.fetch(url, callback=callback, method=method, body=body)


def _on_github_request(future, response):
    """ Parse the JSON from the API """
    if response.error:
        print response.error
        future.set_exception(
            AuthError("Error response %s fetching %s" %
                      (response.error, response.request.url)))
        return

    result = ObjectDict(code=response.code, headers=response.headers, body=None)

    try:
        result.body = json_decode(response.body)
    except Exception:
        gen_log.warning("Invalid JSON from Github: %r", response.body)
        future.set_result(result)
        return
    future.set_result(result)


def parse_link(link):
    linkmap = {}
    for s in link.split(","):
        s = s.strip();
        linkmap[s[-5:-1]] = s.split(";")[0].rstrip()[1:-1]
    return linkmap

def get_last_page_num(link):
    linkmap = parse_link(link)
    matches = re.search(r"[?&]page=(\d+)", linkmap["last"])
    return int(matches.group(1))
