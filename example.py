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

import tornado.httpclient
import tornado.ioloop
import tornado.web
import tornado.options
import tornado.gen
import logging
import re
import time

from tornado.options import define, options
from tornado.httputil import url_concat
from tornado.concurrent import return_future

import torngithub
from torngithub import json_encode, json_decode

log = logging.getLogger("github.demo")

define("port", default=8088, help="run on the given port", type=int)
define("github_client_id", help="your Github application Client ID",
       default="ae63fe642fd528d90bdd")
define("github_client_secret", help="your Github application Client Secret",
       default="1c3acadf6179db7e9fba6d2c6f052f898c00d88b")
define("github_callback_path", help="your Github application Callback",
       default="/oauth")
define("github_scope", help="github scope", default="")

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json:
            return None
        return json_decode(user_json)

class MainHandler(BaseHandler, torngithub.GithubMixin):
    def get(self):
        if self.current_user:
            self.write('Login User: ' + self.current_user["name"]
                       + ' <a href="/stars">My Stars</a> '
                       + ' <a href="/logout">Logout</a>')
        else:
            self.write('<a href="'
                       + self.settings["github_callback_path"] + '">Login</a>')


class GithubLoginHandler(tornado.web.RequestHandler, torngithub.GithubMixin):
    @tornado.gen.coroutine
    def get(self):
        # we can append next to the redirect uri, so the user gets the
        # correct URL on login
        redirect_uri = url_concat(self.request.protocol
                                  + "://" + self.request.host
                                  + self.settings["github_callback_path"],
                                  {"next": self.get_argument('next', '/')})

        # if we have a code, we have been authorized so we can log in
        if self.get_argument("code", False):
            user = yield self.get_authenticated_user(
                redirect_uri=redirect_uri,
                client_id=self.settings["github_client_id"],
                client_secret=self.settings["github_client_secret"],
                code=self.get_argument("code"))
            if user:
                log.info('logged in user from github: ' + str(user))
                self.set_secure_cookie("user", json_encode(user))
            else:
                self.clear_cookie("user")
            self.redirect(self.get_argument("next","/"))
            return

        # otherwise we need to request an authorization code
        yield self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.settings["github_client_id"],
            extra_params={"scope": self.settings['github_scope'], "foo":1})

def parse_link(link):
    linkmap = {}
    for s in link.split(","):
        s = s.strip();
        linkmap[s[-5:-1]] = s.split(";")[0].rstrip()[1:-1]
    return linkmap

def get_last_page_num(link):
    if not link:
        return 0
    linkmap = parse_link(link)
    matches = re.search(r"[?&]page=(\d+)", linkmap["last"])
    return int(matches.group(1))

@tornado.gen.coroutine
def get_my_stars(http_client, access_token):
    data = []
    first_page = yield torngithub.github_request(
        http_client, '/user/starred?page=1&per_page=100',
        access_token=access_token)
    log.info(first_page.headers.get('Link', ''))
    data.extend(first_page.body)
    max_pages = get_last_page_num(first_page.headers.get('Link', ''))

    ress = yield [torngithub.github_request(
        http_client, '/user/starred?per_page=100&page=' + str(i),
        access_token=access_token) for i in range(2, max_pages + 1)]

    for res in ress:
        data.extend(res.body)

    raise tornado.gen.Return(data)

class StarsHandler(BaseHandler, torngithub.GithubMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self):
        starttime = time.time()
        log.info(starttime)

        data = yield get_my_stars(self.get_auth_http_client(),
                                  self.current_user['access_token'])

        endtime = time.time()
        log.info(endtime)
        log.info(endtime - starttime)

        self.write(json_encode(data))
        self.finish()

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))

def main():
    tornado.options.parse_command_line()
    handlers = [
        (r"/", MainHandler),
        (r"/stars", StarsHandler),
        (options.github_callback_path, GithubLoginHandler),
        (r"/logout", LogoutHandler)
    ]

    settings = dict(
        cookie_secret="asdf",
        login_url=options.github_callback_path,
        xsrf_cookies=True,
        github_client_id=options.github_client_id,
        github_client_secret=options.github_client_secret,
        github_callback_path=options.github_callback_path,
        github_scope=options.github_scope,
        debug=True,
        autoescape=None
    )

    tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

    application = tornado.web.Application(handlers, **settings)
    application.listen(options.port)
    tornado.ioloop.IOLoop().instance().start()

if __name__ == "__main__":
    main()
