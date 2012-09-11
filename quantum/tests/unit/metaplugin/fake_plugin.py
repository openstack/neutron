# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

from quantum.common import exceptions as q_exc
from quantum.common.utils import find_config_file
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import l3_db
from quantum.db import models_v2


class Fake1(db_base_plugin_v2.QuantumDbPluginV2,
            l3_db.L3_NAT_db_mixin):
    supported_extension_aliases = ['router']

    def fake_func(self):
        return 'fake1'

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(Fake1, self).create_network(context, network)
            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_l3(context, net)
        return net

    def update_network(self, context, id, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(Fake1, self).update_network(context, id,
                                                    network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_l3(context, net)
        return net

    def delete_network(self, context, id):
        return super(Fake1, self).delete_network(context, id)

    def create_port(self, context, port):
        port = super(Fake1, self).create_port(context, port)
        return port

    def create_subnet(self, context, subnet):
        subnet = super(Fake1, self).create_subnet(context, subnet)
        return subnet

    def update_port(self, context, id, port):
        port = super(Fake1, self).update_port(context, id, port)
        return port

    def delete_port(self, context, id, l3_port_check=True):
        return super(Fake1, self).delete_port(context, id)


class Fake2(Fake1):
    def fake_func(self):
        return 'fake2'

    def fake_func2(self):
        return 'fake2'
