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

from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings
from neutron_lib.api import validators
from neutron_lib.plugins import directory

from neutron.db import _model_query as model_query
from neutron.db import _resource_extend as resource_extend
from neutron.db import api as db_api
from neutron.db.models import portbinding as pmodels
from neutron.db import models_v2
from neutron.db import portbindings_base


def _port_model_hook(context, original_model, query):
    query = query.outerjoin(
        pmodels.PortBindingPort,
        (original_model.id == pmodels.PortBindingPort.port_id))
    return query


def _port_result_filter_hook(query, filters):
    values = filters and filters.get(portbindings.HOST_ID, [])
    if not values:
        return query
    query = query.filter(pmodels.PortBindingPort.host.in_(values))
    return query


@resource_extend.has_resource_extenders
class PortBindingMixin(portbindings_base.PortBindingBaseMixin):

    def __new__(cls, *args, **kwargs):
        model_query.register_hook(
            models_v2.Port,
            "portbindings_port",
            query_hook=_port_model_hook,
            filter_hook=None,
            result_filters=_port_result_filter_hook)
        return super(PortBindingMixin, cls).__new__(cls, *args, **kwargs)

    def _process_portbindings_create_and_update(self, context, port_data,
                                                port):
        binding_profile = port.get(portbindings.PROFILE)
        binding_profile_set = validators.is_attr_set(binding_profile)
        if not binding_profile_set and binding_profile is not None:
            del port[portbindings.PROFILE]

        binding_vnic = port.get(portbindings.VNIC_TYPE)
        binding_vnic_set = validators.is_attr_set(binding_vnic)
        if not binding_vnic_set and binding_vnic is not None:
            del port[portbindings.VNIC_TYPE]
        # REVISIT(irenab) Add support for vnic_type for plugins that
        # can handle more than one type.
        # Currently implemented for ML2 plugin that does not use
        # PortBindingMixin.

        host = port_data.get(portbindings.HOST_ID)
        host_set = validators.is_attr_set(host)
        with db_api.context_manager.writer.using(context):
            bind_port = context.session.query(
                pmodels.PortBindingPort).filter_by(port_id=port['id']).first()
            if host_set:
                if not bind_port:
                    context.session.add(
                        pmodels.PortBindingPort(port_id=port['id'], host=host))
                else:
                    bind_port.host = host
            else:
                host = bind_port.host if bind_port else None
        self._extend_port_dict_binding_host(port, host)

    def get_port_host(self, context, port_id):
        with db_api.context_manager.reader.using(context):
            bind_port = (
                context.session.query(pmodels.PortBindingPort.host).
                filter_by(port_id=port_id).
                first()
            )
            return bind_port.host if bind_port else None

    def _extend_port_dict_binding_host(self, port_res, host):
        super(PortBindingMixin, self).extend_port_dict_binding(
            port_res, None)
        port_res[portbindings.HOST_ID] = host

    def extend_port_dict_binding(self, port_res, port_db):
        host = port_db.portbinding.host if port_db.portbinding else None
        self._extend_port_dict_binding_host(port_res, host)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_dict_binding(port_res, port_db):
        plugin = directory.get_plugin()
        if not isinstance(plugin, PortBindingMixin):
            return
        plugin.extend_port_dict_binding(port_res, port_db)
