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


IS_MONKEY_PATCHED = False


def monkey_patch():
    global IS_MONKEY_PATCHED
    if not IS_MONKEY_PATCHED:
        # This environment variable will be used in eventlet 0.39.0
        # https://github.com/eventlet/eventlet/commit/
        # b754135b045306022a537b5797f2cb2cf47ba49b
        if os.getenv('EVENTLET_MONKEYPATCH') == '1':
            IS_MONKEY_PATCHED = True
            return

        eventlet.monkey_patch()

        # pylint: disable=import-outside-toplevel
        from oslo_utils import importutils
        p_c_e = importutils.import_module('pyroute2.config.asyncio')
        p_c_e.asyncio_config()
        IS_MONKEY_PATCHED = True
