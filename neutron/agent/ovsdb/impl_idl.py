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
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import transaction
from ovsdbapp.backend.ovs_idl import vlog
from ovsdbapp.schema.open_vswitch import impl_idl

from neutron.agent.ovsdb.native import connection as n_connection
from neutron.conf.agent import ovs_conf

NeutronOVSDBTransaction = moves.moved_class(
    impl_idl.OvsVsctlTransaction,
    'NeutronOVSDBTransaction',
    __name__)

VswitchdInterfaceAddException = moves.moved_class(
    impl_idl.VswitchdInterfaceAddException,
    'VswitchdInterfaceAddException',
    __name__)

Transaction = moves.moved_class(transaction.Transaction,
                                'Transaction', __name__)

ovs_conf.register_ovs_agent_opts()
_connection = None


def api_factory(context):
    global _connection
    if _connection is None:
        try:
            _connection = connection.Connection(
                idl=n_connection.idl_factory(),
                timeout=cfg.CONF.ovs_vsctl_timeout)
        except TypeError:
            #pylint: disable=unexpected-keyword-arg,no-value-for-parameter
            _connection = connection.Connection(
                idl_factory=n_connection.idl_factory,  # noqa
                timeout=cfg.CONF.ovs_vsctl_timeout)
    return NeutronOvsdbIdl(_connection)


class NeutronOvsdbIdl(impl_idl.OvsdbIdl):
    def __init__(self, connection):
        vlog.use_python_logger()
        super(NeutronOvsdbIdl, self).__init__(connection)
