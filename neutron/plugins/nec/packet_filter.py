# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012-2013 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec.db import packetfilter as pf_db


LOG = logging.getLogger(__name__)


class PacketFilterMixin(pf_db.PacketFilterDbMixin):
    """Mixin class to add packet filter to NECPluginV2."""

    @property
    def packet_filter_enabled(self):
        if not hasattr(self, '_packet_filter_enabled'):
            self._packet_filter_enabled = (
                config.OFC.enable_packet_filter and
                self.ofc.driver.filter_supported())
        return self._packet_filter_enabled

    def remove_packet_filter_extension_if_disabled(self, aliases):
        if not self.packet_filter_enabled:
            LOG.debug(_('Disabled packet-filter extension.'))
            aliases.remove('packet-filter')

    def create_packet_filter(self, context, packet_filter):
        """Create a new packet_filter entry on DB, then try to activate it."""
        LOG.debug(_("create_packet_filter() called, packet_filter=%s ."),
                  packet_filter)

        pf = super(PacketFilterMixin, self).create_packet_filter(
            context, packet_filter)

        return self.activate_packet_filter_if_ready(context, pf)

    def update_packet_filter(self, context, id, packet_filter):
        """Update packet_filter entry on DB, and recreate it if changed.

        If any rule of the packet_filter was changed, recreate it on OFC.
        """
        LOG.debug(_("update_packet_filter() called, "
                    "id=%(id)s packet_filter=%(packet_filter)s ."),
                  {'id': id, 'packet_filter': packet_filter})

        # validate ownership
        pf_old = self.get_packet_filter(context, id)

        pf = super(PacketFilterMixin, self).update_packet_filter(
            context, id, packet_filter)

        def _packet_filter_changed(old_pf, new_pf):
            for key in new_pf:
                if key not in ('id', 'name', 'tenant_id', 'network_id',
                               'in_port', 'status'):
                    if old_pf[key] != new_pf[key]:
                        return True
            return False

        if _packet_filter_changed(pf_old, pf):
            pf = self.deactivate_packet_filter(context, pf)
            pf = self.activate_packet_filter_if_ready(context, pf)

        return pf

    def delete_packet_filter(self, context, id):
        """Deactivate and delete packet_filter."""
        LOG.debug(_("delete_packet_filter() called, id=%s ."), id)

        # validate ownership
        pf = self.get_packet_filter(context, id)

        pf = self.deactivate_packet_filter(context, pf)
        if pf['status'] == pf_db.PF_STATUS_ERROR:
            msg = _("Failed to delete packet_filter id=%s which remains in "
                    "error status.") % id
            LOG.error(msg)
            raise nexc.OFCException(reason=msg)

        super(PacketFilterMixin, self).delete_packet_filter(context, id)

    def activate_packet_filter_if_ready(self, context, packet_filter):
        """Activate packet_filter by creating filter on OFC if ready.

        Conditions to create packet_filter on OFC are:
            * packet_filter admin_state is UP
            * (if 'in_port' is specified) portinfo is available
        """
        LOG.debug(_("activate_packet_filter_if_ready() called, "
                    "packet_filter=%s."), packet_filter)

        pf_id = packet_filter['id']
        in_port_id = packet_filter.get('in_port')
        current = packet_filter['status']

        pf_status = current
        if not packet_filter['admin_state_up']:
            LOG.debug(_("activate_packet_filter_if_ready(): skip pf_id=%s, "
                        "packet_filter.admin_state_up is False."), pf_id)
        elif in_port_id and not ndb.get_portinfo(context.session, in_port_id):
            LOG.debug(_("activate_packet_filter_if_ready(): skip "
                        "pf_id=%s, no portinfo for the in_port."), pf_id)
        elif self.ofc.exists_ofc_packet_filter(context, packet_filter['id']):
            LOG.debug(_("_activate_packet_filter_if_ready(): skip, "
                        "ofc_packet_filter already exists."))
        else:
            LOG.debug(_("activate_packet_filter_if_ready(): create "
                        "packet_filter id=%s on OFC."), pf_id)
            try:
                self.ofc.create_ofc_packet_filter(context, pf_id,
                                                  packet_filter)
                pf_status = pf_db.PF_STATUS_ACTIVE
            except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
                LOG.error(_("Failed to create packet_filter id=%(id)s on "
                            "OFC: %(exc)s"), {'id': pf_id, 'exc': str(exc)})
                pf_status = pf_db.PF_STATUS_ERROR

        if pf_status != current:
            self._update_resource_status(context, "packet_filter", pf_id,
                                         pf_status)
            packet_filter.update({'status': pf_status})

        return packet_filter

    def deactivate_packet_filter(self, context, packet_filter):
        """Deactivate packet_filter by deleting filter from OFC if exixts."""
        LOG.debug(_("deactivate_packet_filter_if_ready() called, "
                    "packet_filter=%s."), packet_filter)
        pf_id = packet_filter['id']
        current = packet_filter['status']

        pf_status = current
        if self.ofc.exists_ofc_packet_filter(context, pf_id):
            LOG.debug(_("deactivate_packet_filter(): "
                        "deleting packet_filter id=%s from OFC."), pf_id)
            try:
                self.ofc.delete_ofc_packet_filter(context, pf_id)
                pf_status = pf_db.PF_STATUS_DOWN
            except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
                LOG.error(_("Failed to delete packet_filter id=%(id)s from "
                            "OFC: %(exc)s"), {'id': pf_id, 'exc': str(exc)})
                pf_status = pf_db.PF_STATUS_ERROR
        else:
            LOG.debug(_("deactivate_packet_filter(): skip, "
                        "Not found OFC Mapping for packet_filter id=%s."),
                      pf_id)

        if pf_status != current:
            self._update_resource_status(context, "packet_filter", pf_id,
                                         pf_status)
            packet_filter.update({'status': pf_status})

        return packet_filter

    def activate_packet_filters_by_port(self, context, port_id):
        if not self.packet_filter_enabled:
            return

        filters = {'in_port': [port_id], 'admin_state_up': [True],
                   'status': [pf_db.PF_STATUS_DOWN]}
        pfs = self.get_packet_filters(context, filters=filters)
        for pf in pfs:
            self.activate_packet_filter_if_ready(context, pf)

    def deactivate_packet_filters_by_port(self, context, port_id):
        if not self.packet_filter_enabled:
            return

        filters = {'in_port': [port_id], 'status': [pf_db.PF_STATUS_ACTIVE]}
        pfs = self.get_packet_filters(context, filters=filters)
        for pf in pfs:
            self.deactivate_packet_filter(context, pf)
