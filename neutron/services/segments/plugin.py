# Copyright 2016 Hewlett Packard Enterprise Development, LP
#
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

from sqlalchemy.orm import session

from neutron.api.v2 import attributes
from neutron.db import common_db_mixin
from neutron.db import models_v2
from neutron.extensions import ip_allocation
from neutron.extensions import segment
from neutron import manager
from neutron.services.segments import db


def _extend_subnet_dict_binding(plugin, subnet_res, subnet_db):
    subnet_res['segment_id'] = subnet_db.get('segment_id')


def _extend_port_dict_binding(plugin, port_res, port_db):
    if not manager.NeutronManager.get_service_plugins().get('segments'):
        return

    value = ip_allocation.IP_ALLOCATION_IMMEDIATE
    if not port_res.get('fixed_ips'):
        # NOTE Only routed network ports have deferred allocation. Check if it
        # is routed by looking for subnets associated with segments.
        object_session = session.Session.object_session(port_db)
        query = object_session.query(models_v2.Subnet)
        query = query.filter_by(network_id=port_db.network_id)
        query = query.filter(models_v2.Subnet.segment_id.isnot(None))
        if query.count():
            value = ip_allocation.IP_ALLOCATION_DEFERRED
    port_res[ip_allocation.IP_ALLOCATION] = value


class Plugin(db.SegmentDbMixin, segment.SegmentPluginBase):

    _instance = None

    supported_extension_aliases = ["segment", "ip_allocation"]

    def __init__(self):
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            attributes.SUBNETS, [_extend_subnet_dict_binding])
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            attributes.PORTS, [_extend_port_dict_binding])

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
