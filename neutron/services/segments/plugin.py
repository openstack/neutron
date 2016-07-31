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

from neutron._i18n import _
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import common_db_mixin
from neutron.db import models_v2
from neutron.extensions import ip_allocation
from neutron.extensions import l2_adjacency
from neutron.extensions import segment
from neutron import manager
from neutron.services.segments import db
from neutron.services.segments import exceptions


def _extend_network_dict_binding(plugin, network_res, network_db):
    if not manager.NeutronManager.get_service_plugins().get('segments'):
        return

    # TODO(carl_baldwin) Make this work with service subnets when it's a thing.
    is_adjacent = (not network_db.subnets
                   or not network_db.subnets[0].segment_id)
    network_res[l2_adjacency.L2_ADJACENCY] = is_adjacent


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

    supported_extension_aliases = ["segment", "ip_allocation", "l2_adjacency"]

    def __init__(self):
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            attributes.NETWORKS, [_extend_network_dict_binding])
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            attributes.SUBNETS, [_extend_subnet_dict_binding])
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            attributes.PORTS, [_extend_port_dict_binding])

        registry.subscribe(
            self._prevent_segment_delete_with_subnet_associated,
            resources.SEGMENT,
            events.BEFORE_DELETE)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _prevent_segment_delete_with_subnet_associated(
            self, resource, event, trigger, context, segment):
        """Raise exception if there are any subnets associated with segment."""
        segment_id = segment['id']
        query = context.session.query(models_v2.Subnet.id)
        query = query.filter(models_v2.Subnet.segment_id == segment_id)
        subnet_ids = [s[0] for s in query]
        if subnet_ids:
            reason = _("The segment is still associated with subnet(s) "
                       "%s") % ", ".join(subnet_ids)
            raise exceptions.SegmentInUse(segment_id=segment_id, reason=reason)
