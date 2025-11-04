# Copyright (c) 2025 Red Hat Inc.
# All rights reserved.
#
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

# NOTE(ralonsoh): remove once the default backend is ``BackendType.THREADING``
from oslo_service import backend as oslo_service_backend
oslo_service_backend.init_backend(oslo_service_backend.BackendType.THREADING)

# pylint: disable=wrong-import-position
from neutron import server  # noqa: E402
from neutron.server import api  # noqa: E402
from neutron.server import ovn_maintenance  # noqa: E402
from neutron.server import periodic  # noqa: E402
from neutron.server import rpc  # noqa: E402


def main_api_uwsgi():
    return server.boot_server(api.api_server)


def main_ovn_maintenance():
    return server.boot_server(ovn_maintenance.ovn_maintenance_worker)


def main_rpc():
    server.boot_server(rpc.rpc_server)


def main_periodic():
    server.boot_server(periodic.periodic_workers)
