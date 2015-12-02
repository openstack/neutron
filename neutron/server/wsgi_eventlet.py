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

import eventlet

from oslo_log import log

from neutron._i18n import _LI
from neutron import server
from neutron import service

LOG = log.getLogger(__name__)


def _eventlet_wsgi_server():
    pool = eventlet.GreenPool()

    neutron_api = service.serve_wsgi(service.NeutronApiService)
    api_thread = pool.spawn(neutron_api.wait)

    try:
        neutron_rpc = service.serve_rpc()
    except NotImplementedError:
        LOG.info(_LI("RPC was already started in parent process by "
                     "plugin."))
    else:
        rpc_thread = pool.spawn(neutron_rpc.wait)

        plugin_workers = service.start_plugin_workers()
        for worker in plugin_workers:
            pool.spawn(worker.wait)

        # api and rpc should die together.  When one dies, kill the other.
        rpc_thread.link(lambda gt: api_thread.kill())
        api_thread.link(lambda gt: rpc_thread.kill())

    pool.waitall()


def main():
    server.boot_server(_eventlet_wsgi_server)
