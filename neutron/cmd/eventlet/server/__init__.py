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

from oslo_config import cfg

from neutron import server
from neutron.server import rpc_eventlet
from neutron.server import wsgi_eventlet
from neutron.server import wsgi_pecan


def main():
    server.boot_server(_main_neutron_server)


def _main_neutron_server():
    if cfg.CONF.web_framework == 'legacy':
        wsgi_eventlet.eventlet_wsgi_server()
    else:
        wsgi_pecan.pecan_wsgi_server()


def main_rpc_eventlet():
    server.boot_server(rpc_eventlet.eventlet_rpc_server)
