# Copyright 2021 Huawei, Inc.
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

import contextlib

from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import local_ip as lip_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron._i18n import _
from neutron.extensions import local_ip as lip_ext
from neutron.objects import base as base_obj
from neutron.objects import local_ip as lip_obj
from neutron.objects import ports as port_obj


LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class LocalIPDbMixin(lip_ext.LocalIPPluginBase):
    """Mixin class to add Local IPs to db_base_plugin_v2."""

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    @staticmethod
    def _make_local_ip_dict(local_ip, fields=None):
        res = local_ip.to_dict()
        return db_utils.resource_fields(res, fields)

    def _get_local_ip(self, context, id):
        obj = lip_obj.LocalIP.get_object(context, id=id)
        if obj is None:
            raise lip_exc.LocalIPNotFound(id=id)
        return obj

    def _create_local_port(self, context, network_id, ip_address):
        net_db = self._core_plugin._get_network(context, network_id)

        if not any(s.ip_version == constants.IP_VERSION_4 for
                   s in net_db.subnets):
            msg = _("Network %s does not contain any IPv4 subnet") % network_id
            raise lib_exc.BadRequest(resource='local_ip', msg=msg)

        # This local port is never exposed to the tenant.
        # it is used purely for internal system and admin use when
        # managing Local IPs.
        port = {'project_id': '',  # project intentionally not set
                'network_id': network_id,
                'admin_state_up': True,
                'device_id': 'PENDING',
                'device_owner': constants.DEVICE_OWNER_LOCAL_IP,
                'status': constants.PORT_STATUS_NOTAPPLICABLE}

        # If requested ip_address is not in the subnet,
        # InvalidIpForSubnet exception will be raised.
        if validators.is_attr_set(ip_address):
            port['fixed_ips'] = [{'ip_address': ip_address}]

        # 'status' in port dict could not be updated by default, use
        # check_allow_post to stop the verification of system
        return plugin_utils.create_port(
            self._core_plugin, context.elevated(),
            {'port': port}, check_allow_post=False)

    def _get_local_ip_address(self, port, requested_ip):
        fixed_ips = port.fixed_ips
        if len(fixed_ips) == 0:
            raise lip_exc.LocalIPNoIP(port_id=port.id)
        if len(fixed_ips) == 1:
            fixed_ip = str(fixed_ips[0].ip_address)
            if (validators.is_attr_set(requested_ip) and
                    (requested_ip != fixed_ip)):
                raise lip_exc.LocalIPRequestedIPNotFound(
                    port_id=port.id, ip=requested_ip)
            return fixed_ip
        if validators.is_attr_set(requested_ip):
            for fixed_ip in fixed_ips:
                if str(fixed_ip.ip_address) == requested_ip:
                    return requested_ip
            raise lip_exc.LocalIPRequestedIPNotFound(
                port_id=port.id, ip=requested_ip)
        raise lip_exc.LocalIPNoRequestedIP(port_id=port.id)

    @db_api.retry_if_session_inactive()
    def create_local_ip(self, context, local_ip):
        """Create a Local IP."""
        fields = local_ip['local_ip']
        local_port_id = fields.get('local_port_id')
        local_ip_address = fields.get('local_ip_address')
        network_id = fields.get('network_id')
        new_local_port = False
        if validators.is_attr_set(local_port_id):
            local_port = port_obj.Port.get_object(context, id=local_port_id)
            if not local_port:
                msg = _("Port %s not found") % local_port_id
                raise lib_exc.BadRequest(resource='local_ip', msg=msg)
            local_ip_address = self._get_local_ip_address(local_port,
                                                          local_ip_address)
        elif validators.is_attr_set(network_id):
            local_port = self._create_local_port(context, network_id,
                                                 local_ip_address)
            local_port_id = local_port['id']
            local_ip_address = local_port['fixed_ips'][0]['ip_address']
            new_local_port = True
        else:
            raise lip_exc.LocalIPPortOrNetworkRequired()

        if new_local_port:
            ctx_mgr = plugin_utils.delete_port_on_error(
                self._core_plugin, context.elevated(),
                local_port_id)
        else:
            ctx_mgr = contextlib.suppress()

        with ctx_mgr, db_api.CONTEXT_WRITER.using(context):
            args = {'id': uuidutils.generate_uuid(),
                    'name': fields['name'],
                    'description': fields['description'],
                    'project_id': fields['project_id'],
                    'local_port_id': local_port_id,
                    'network_id': local_port['network_id'],
                    'local_ip_address': local_ip_address,
                    'ip_mode': fields['ip_mode']}
            lip = lip_obj.LocalIP(context, **args)
            lip.create()

        if new_local_port:
            self._core_plugin.update_port(
                context.elevated(), local_port_id,
                {'port': {'device_id': lip.id,
                          'project_id': lip.project_id}})
        return self._make_local_ip_dict(lip)

    @db_api.retry_if_session_inactive()
    def update_local_ip(self, context, lip_id, local_ip):
        fields = local_ip['local_ip']
        lip = self._get_local_ip(context, lip_id)
        lip.update_fields(fields)
        lip.update()
        lip_dict = self._make_local_ip_dict(lip)
        return lip_dict

    def get_local_ip(self, context, lip_id, fields=None):
        lip = self._get_local_ip(context, lip_id)
        return self._make_local_ip_dict(lip, fields)

    def get_local_ips(self, context, filters=None, fields=None,
                      sorts=None, limit=None, marker=None,
                      page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        lips = lip_obj.LocalIP.get_objects(
            context, _pager=pager, **filters)
        return [
            self._make_local_ip_dict(lip, fields)
            for lip in lips
        ]

    @db_api.retry_if_session_inactive()
    def delete_local_ip(self, context, lip_id):
        with db_api.CONTEXT_WRITER.using(context):
            if lip_obj.LocalIPAssociation.get_objects(context.elevated(),
                                                      local_ip_id=lip_id):
                raise lip_exc.LocalIPInUse(id=lip_id)
            lip = self._get_local_ip(context, lip_id)
            local_port = port_obj.Port.get_object(
                context, id=lip.local_port_id)
            lip.delete()
        if local_port.device_owner == constants.DEVICE_OWNER_LOCAL_IP:
            self._core_plugin.delete_port(context.elevated(),
                                          local_port.id)

    @staticmethod
    def _make_local_ip_assoc_dict(local_ip_association, fields=None):
        res = local_ip_association.to_dict()
        res = db_utils.resource_fields(res, fields)

        fixed_port = local_ip_association.db_obj.port
        res['local_ip_address'] = (
            local_ip_association.local_ip.local_ip_address)
        if fixed_port.port_bindings:
            res['host'] = fixed_port.port_bindings[0].host
        else:
            res['host'] = ''
        return res

    @db_api.CONTEXT_WRITER
    def _create_local_ip_port_association(self, context, local_ip_id,
                                          port_association):
        fields = port_association['port_association']
        fixed_port = port_obj.Port.get_object(
            context, id=fields['fixed_port_id'])
        if not fixed_port:
            msg = _("Port %s not found") % fixed_port.id
            raise lib_exc.BadRequest(
                resource='local_ip_port_association', msg=msg)
        requested_ip = fields['fixed_ip']
        if validators.is_attr_set(requested_ip):
            for ip in fixed_port.fixed_ips:
                if str(ip.ip_address) == requested_ip:
                    break
            else:
                raise lip_exc.LocalIPRequestedIPNotFound(
                    port_id=fixed_port.id, ip=requested_ip)
        else:
            if not fixed_port.fixed_ips:
                raise lip_exc.LocalIPNoIP(port_id=fixed_port.id)
            if len(fixed_port.fixed_ips) > 1:
                raise lip_exc.LocalIPNoRequestedIP(port_id=fixed_port.id)
            requested_ip = fixed_port.fixed_ips[0]['ip_address']

        args = {'local_ip_id': local_ip_id,
                'fixed_port_id': fixed_port.id,
                'fixed_ip': requested_ip}
        lip_assoc = lip_obj.LocalIPAssociation(context, **args)
        try:
            lip_assoc.create()
        except obj_exc.NeutronDbObjectDuplicateEntry:
            LOG.error("Local IP  %(lip)s association to port "
                      "%(port)s already exists.",
                      {'lip': local_ip_id,
                       'port': fixed_port.id})
            return

        return lip_assoc

    def create_local_ip_port_association(self, context, local_ip_id,
                                         port_association):
        lip_assoc = self._create_local_ip_port_association(
            context, local_ip_id, port_association)
        return self._make_local_ip_assoc_dict(lip_assoc)

    def get_local_ip_port_association(self, context, fixed_port_id,
                                      local_ip_id, fields=None):
        assoc = lip_obj.LocalIPAssociation.get_object(
            context, local_ip_id=local_ip_id, fixed_port_id=fixed_port_id)
        if assoc is None:
            raise lip_exc.LocalIPAssociationNotFound(
                local_ip_id=local_ip_id, port_id=fixed_port_id)
        return self._make_local_ip_assoc_dict(assoc, fields)

    def get_local_ip_port_associations(self, context, local_ip_id,
                                       filters=None, fields=None,
                                       sorts=None, limit=None,
                                       marker=None, page_reverse=False):
        # TODO(obondarev): fix bug that 'id' sort is added for subresources
        sorts.remove(('id', True))
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        lip_associations = lip_obj.LocalIPAssociation.get_objects(
            context, _pager=pager, local_ip_id=local_ip_id, **filters)
        return [
            self._make_local_ip_assoc_dict(lip_assoc, fields)
            for lip_assoc in lip_associations]

    @db_api.CONTEXT_WRITER
    def delete_local_ip_port_association(self, context, fixed_port_id,
                                         local_ip_id):
        assoc = lip_obj.LocalIPAssociation.get_object(
            context, local_ip_id=local_ip_id, fixed_port_id=fixed_port_id)
        if not assoc:
            raise lip_exc.LocalIPAssociationNotFound(local_ip_id=local_ip_id,
                                                     port_id=fixed_port_id)
        assoc.delete()
        return assoc

    @staticmethod
    @registry.receives(resources.PORT, [events.BEFORE_DELETE])
    def _prevent_local_port_delete_callback(resource, event,
                                            trigger, payload=None):
        port_id = payload.resource_id
        if lip_obj.LocalIP.count(payload.context, local_port_id=port_id):
            reason = _('still referenced by Local IPs')
            raise lib_exc.ServicePortInUse(port_id=port_id,
                                           reason=reason)
