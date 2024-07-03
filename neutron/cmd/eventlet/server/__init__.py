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

from neutron import server
from neutron.server import api_eventlet
from neutron.server import ovn_maintenance
from neutron.server import periodic_eventlet
from neutron.server import rpc_eventlet
from neutron.server import wsgi_eventlet


def main():
    server.boot_server(wsgi_eventlet.eventlet_wsgi_server)


def main_rpc_eventlet():
    server.boot_server(rpc_eventlet.eventlet_rpc_server)


def main_api_eventlet():
    return server.boot_server(api_eventlet.eventlet_api_server)


def main_periodic_eventlet():
    server.boot_server(periodic_eventlet.eventlet_periodic_workers)


def main_ovn_maintenance_eventlet():
    return server.boot_server(ovn_maintenance.eventlet_ovn_maintenance_worker)
