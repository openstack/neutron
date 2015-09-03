# Copyright (c) 2015 Cloudbase Solutions.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

import eventlet


def monkey_patch():
    if os.name == 'nt':
        # eventlet monkey patching the os and thread modules causes
        # subprocess.Popen to fail on Windows when using pipes due
        # to missing non-blocking IO support.
        #
        # bug report on eventlet:
        # https://bitbucket.org/eventlet/eventlet/issue/132/
        #       eventletmonkey_patch-breaks
        eventlet.monkey_patch(os=False, thread=False)
    else:
        eventlet.monkey_patch()
