# Copyright 2013 IBM Corp.
# All Rights Reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import portbindings_base
from neutron.extensions import portbindings


class PortBindingPort(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False)
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("portbinding",
                            lazy='joined', uselist=False,
                            cascade='delete'))


class PortBindingMixin(portbindings_base.PortBindingBaseMixin):
    extra_binding_dict = None

    def _port_model_hook(self, context, original_model, query):
        query = query.outerjoin(PortBindingPort,
                                (original_model.id ==
                                 PortBindingPort.port_id))
        return query

    def _port_result_filter_hook(self, query, filters):
        values = filters and filters.get(portbindings.HOST_ID, [])
        if not values:
            return query
        query = query.filter(PortBindingPort.host.in_(values))
        return query

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Port,
        "portbindings_port",
        '_port_model_hook',
        None,
        '_port_result_filter_hook')

    def _process_portbindings_create_and_update(self, context, port_data,
                                                port):
        binding_profile = port.get(portbindings.PROFILE)
        binding_profile_set = attributes.is_attr_set(binding_profile)
        if not binding_profile_set and binding_profile is not None:
            del port[portbindings.PROFILE]

        binding_vnic = port.get(portbindings.VNIC_TYPE)
        binding_vnic_set = attributes.is_attr_set(binding_vnic)
        if not binding_vnic_set and binding_vnic is not None:
            del port[portbindings.VNIC_TYPE]
        # REVISIT(irenab) Add support for vnic_type for plugins that
        # can handle more than one type.
        # Currently implemented for ML2 plugin that does not use
        # PortBindingMixin.

        host = port_data.get(portbindings.HOST_ID)
        host_set = attributes.is_attr_set(host)
        with context.session.begin(subtransactions=True):
            bind_port = context.session.query(
                PortBindingPort).filter_by(port_id=port['id']).first()
            if host_set:
                if not bind_port:
                    context.session.add(PortBindingPort(port_id=port['id'],
                                                        host=host))
                else:
                    bind_port.host = host
            else:
                host = bind_port.host if bind_port else None
        self._extend_port_dict_binding_host(port, host)

    def get_port_host(self, context, port_id):
        with context.session.begin(subtransactions=True):
            bind_port = context.session.query(
                PortBindingPort).filter_by(port_id=port_id).first()
            return bind_port.host if bind_port else None

    def _extend_port_dict_binding_host(self, port_res, host):
        super(PortBindingMixin, self).extend_port_dict_binding(
            port_res, None)
        port_res[portbindings.HOST_ID] = host

    def extend_port_dict_binding(self, port_res, port_db):
        host = port_db.portbinding.host if port_db.portbinding else None
        self._extend_port_dict_binding_host(port_res, host)


def _extend_port_dict_binding(plugin, port_res, port_db):
    if not isinstance(plugin, PortBindingMixin):
        return
    plugin.extend_port_dict_binding(port_res, port_db)


# Register dict extend functions for ports
db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
    attributes.PORTS, [_extend_port_dict_binding])
