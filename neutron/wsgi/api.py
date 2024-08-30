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

"""WSGI application entry-point for Neutron API."""

# NOTE: the WSGI module needs to monkey patch the libraries before any other
# module loads them. That will prevent the recursion error in the SSL library
# reported in LP#2075147
# pylint: disable=wrong-import-position
from neutron.common import eventlet_utils
eventlet_utils.monkey_patch()

import threading  # noqa:E402

from neutron import server  # noqa:E402
from neutron.server import api_eventlet  # noqa:E402

application = None
lock = threading.Lock()
with lock:
    if application is None:
        application = server.boot_server(api_eventlet.eventlet_api_server)
