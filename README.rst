Torngithub
==========

Torngithub is the Github OAuth2 authentication for tornado.

Installation
============

    pip install torngithub

In Tornado 4.4.2 the default, SimpleAysncHTTPClient, fails with Github OAUTH
getting HTTP 403 errors when requesting the user information after the log in.
The Curl based library doesn't so it suggested to use that. To do configure
the HTTP client at start up:

    tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")


License
=======

Copyright 2013 jKey Lu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
