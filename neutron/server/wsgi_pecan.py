#!/usr/bin/env python
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log

from neutron._i18n import _LI
from neutron.pecan_wsgi import app as pecan_app
from neutron.server import wsgi_eventlet
from neutron import service

LOG = log.getLogger(__name__)


def pecan_wsgi_server():
    LOG.info(_LI("Pecan WSGI server starting..."))
    application = pecan_app.setup_app()
    neutron_api = service.run_wsgi_app(application)
    wsgi_eventlet.start_api_and_rpc_workers(neutron_api)
