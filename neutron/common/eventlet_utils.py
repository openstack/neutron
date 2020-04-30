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
from oslo_utils import importutils


def monkey_patch():
    # NOTE(slaweq): to workaround issue with import cycles in
    # eventlet < 0.22.0;
    # This issue is fixed in eventlet with patch
    # https://github.com/eventlet/eventlet/commit/b756447bab51046dfc6f1e0e299cc997ab343701
    # For details please check https://bugs.launchpad.net/neutron/+bug/1745013
    hub = eventlet.hubs.get_hub()
    hub.is_available = lambda: True
    if os.name != 'nt':
        eventlet.monkey_patch()

        p_c_e = importutils.import_module('pyroute2.config.asyncio')
        p_c_e.asyncio_config()
    else:
        # eventlet monkey patching the os module causes subprocess.Popen to
        # fail on Windows when using pipes due to missing non-blocking IO
        # support.
        eventlet.monkey_patch(os=False)
    # Monkey patch the original current_thread to use the up-to-date _active
    # global variable. See https://bugs.launchpad.net/bugs/1863021 and
    # https://github.com/eventlet/eventlet/issues/592
    import __original_module_threading as orig_threading
    import threading  # noqa
    orig_threading.current_thread.__globals__['_active'] = threading._active
