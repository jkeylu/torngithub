#!/usr/bin/env python
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

import tornado.auth
import tornado.escape
import tornado.httpclient
import tornado.httputil

from tornado.log import gen_log

class GithubMixin(tornado.auth.OAuth2Mixin):
    """Github authentication using OAuth2."""

    _OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
    _GITHUB_API_URL = "https://api.github.com"

    @tornado.auth._auth_return_future
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
                tornado.auth.AuthError('Github auth error: %s' % str(response)))
            return

        args = tornado.escape.parse_qs_bytes(
            tornado.escape.native_str(response.body))

        if 'error' in args:
            future.set_exception(
                tornado.auth.AuthError('Github auth error: %s' % args['error'][-1]))
            return

        session = {
            "access_token": args["access_token"][-1],
        }

        self.github_request(
            path="/user",
            callback=self.async_callback(self._on_get_user_info,
                                         future, session, fields),
            access_token=session["access_token"]
        )

    def _on_get_user_info(self, future, session, fields, user):
        if user is None:
            future.set_result(None)
            return

        fieldmap = {}
        for field in fields:
            fieldmap[field] = user.get(field)

        fieldmap.update({"access_token": session["access_token"]})
        future.set_result(fieldmap)

    @tornado.auth._auth_return_future
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
        url = self._GITHUB_API_URL + path

        all_args = {}
        if access_token:
            all_args["access_token"] = access_token
        all_args.update(args)

        if all_args:
            url = tornado.httputil.url_concat(url, all_args)

        callback = self.async_callback(self._on_github_request, callback)

        http = self.get_auth_http_client()
        if body is not None:
            body = tornado.escape.json_encode(body)
        http.fetch(url, callback=callback, method=method, body=body)

    def _on_github_request(self, future, response):
        """ Parse the JSON from the API """
        if response.error:
            future.set_exception(
                tornado.auth.AuthError("Error response %s fetching %s" %
                                       (response.error, response.request.url)))
            return
        try:
            json = tornado.escape.json_decode(response.body)
        except Exception:
            gen_log.warning("Invalid JSON from Github: %r", response.body)
            future.set_result(None)
            return
        future.set_result(json)

    def get_auth_http_client(self):
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overriddent by subclasses to use an HTTP client other than
        the default.
        """
        return tornado.httpclient.AsyncHTTPClient()
