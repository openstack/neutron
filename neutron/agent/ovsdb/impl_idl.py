# Copyright (c) 2015 Red Hat, Inc.
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

from debtcollector import moves
from oslo_config import cfg
from ovsdbapp.schema.open_vswitch import impl_idl

from neutron.agent.ovsdb.native import connection
from neutron.agent.ovsdb.native import vlog
from neutron.conf.agent import ovs_conf

NeutronOVSDBTransaction = moves.moved_class(
    impl_idl.OvsVsctlTransaction,
    'NeutronOVSDBTransaction',
    __name__)

VswitchdInterfaceAddException = moves.moved_class(
    impl_idl.VswitchdInterfaceAddException,
    'VswitchdInterfaceAddException',
    __name__)

ovs_conf.register_ovs_agent_opts()

_connection = connection.Connection(idl_factory=connection.idl_factory,
                                    timeout=cfg.CONF.ovs_vsctl_timeout)


def api_factory(context):
    return NeutronOvsdbIdl(_connection)


class NeutronOvsdbIdl(impl_idl.OvsdbIdl):
    def __init__(self, connection):
        vlog.use_python_logger()
        super(NeutronOvsdbIdl, self).__init__(connection)
