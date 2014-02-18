# Copyright 2013 VMware, Inc.  All rights reserved.
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
#

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.extensions import maclearning as mac

LOG = logging.getLogger(__name__)


class MacLearningState(model_base.BASEV2):

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    mac_learning_enabled = sa.Column(sa.Boolean(), nullable=False)

    # Add a relationship to the Port model using the backref attribute.
    # This will instruct SQLAlchemy to eagerly load this association.
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("mac_learning_state", lazy='joined',
                            uselist=False, cascade='delete'))


class MacLearningDbMixin(object):
    """Mixin class for mac learning."""

    def _make_mac_learning_state_dict(self, port, fields=None):
        res = {'port_id': port['port_id'],
               mac.MAC_LEARNING: port[mac.MAC_LEARNING]}
        return self._fields(res, fields)

    def _extend_port_mac_learning_state(self, port_res, port_db):
        state = port_db.mac_learning_state
        if state and state.mac_learning_enabled:
            port_res[mac.MAC_LEARNING] = state.mac_learning_enabled

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_extend_port_mac_learning_state'])

    def _update_mac_learning_state(self, context, port_id, enabled):
        try:
            query = self._model_query(context, MacLearningState)
            state = query.filter(MacLearningState.port_id == port_id).one()
            state.update({mac.MAC_LEARNING: enabled})
        except exc.NoResultFound:
            self._create_mac_learning_state(context,
                                            {'id': port_id,
                                             mac.MAC_LEARNING: enabled})

    def _create_mac_learning_state(self, context, port):
        with context.session.begin(subtransactions=True):
            enabled = port[mac.MAC_LEARNING]
            state = MacLearningState(port_id=port['id'],
                                     mac_learning_enabled=enabled)
            context.session.add(state)
        return self._make_mac_learning_state_dict(state)
