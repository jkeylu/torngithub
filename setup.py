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

import distutils.core

version = '0.1.3'

distutils.core.setup(
    name='torngithub',
    version=version,
    py_modules=['torngithub'],
    author='jKey Lu',
    author_email='jkeylu@gmail.com',
    url='https://github.com/jkeylu/torngithub',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description='Github authentication for tornado'
)
