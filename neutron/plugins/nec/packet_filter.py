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

from oslo_utils import excutils

from neutron.i18n import _LE
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import exceptions as nexc
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
            LOG.debug('Disabled packet-filter extension.')
            aliases.remove('packet-filter')

    def create_packet_filter(self, context, packet_filter):
        """Create a new packet_filter entry on DB, then try to activate it."""
        LOG.debug("create_packet_filter() called, packet_filter=%s .",
                  packet_filter)

        if hasattr(self.ofc.driver, 'validate_filter_create'):
            pf = packet_filter['packet_filter']
            self.ofc.driver.validate_filter_create(context, pf)
        pf = super(PacketFilterMixin, self).create_packet_filter(
            context, packet_filter)

        return self.activate_packet_filter_if_ready(context, pf)

    def update_packet_filter(self, context, id, packet_filter):
        """Update packet_filter entry on DB, and recreate it if changed.

        If any rule of the packet_filter was changed, recreate it on OFC.
        """
        LOG.debug("update_packet_filter() called, "
                  "id=%(id)s packet_filter=%(packet_filter)s .",
                  {'id': id, 'packet_filter': packet_filter})

        pf_data = packet_filter['packet_filter']
        if hasattr(self.ofc.driver, 'validate_filter_update'):
            self.ofc.driver.validate_filter_update(context, pf_data)

        # validate ownership
        pf_old = self.get_packet_filter(context, id)

        pf = super(PacketFilterMixin, self).update_packet_filter(
            context, id, packet_filter)

        def _packet_filter_changed(old_pf, new_pf):
            LOG.debug('old_pf=%(old_pf)s, new_pf=%(new_pf)s',
                      {'old_pf': old_pf, 'new_pf': new_pf})
            # When the status is ERROR, force sync to OFC.
            if old_pf['status'] == pf_db.PF_STATUS_ERROR:
                LOG.debug('update_packet_filter: Force filter update '
                          'because the previous status is ERROR.')
                return True
            for key in new_pf:
                if key in ('id', 'name', 'tenant_id', 'network_id',
                           'in_port', 'status'):
                    continue
                if old_pf[key] != new_pf[key]:
                    return True
            return False

        if _packet_filter_changed(pf_old, pf):
            if hasattr(self.ofc.driver, 'update_filter'):
                # admin_state is changed
                if pf_old['admin_state_up'] != pf['admin_state_up']:
                    LOG.debug('update_packet_filter: admin_state '
                              'is changed to %s', pf['admin_state_up'])
                    if pf['admin_state_up']:
                        self.activate_packet_filter_if_ready(context, pf)
                    else:
                        self.deactivate_packet_filter(context, pf)
                elif pf['admin_state_up']:
                    LOG.debug('update_packet_filter: admin_state is '
                              'unchanged (True)')
                    if self.ofc.exists_ofc_packet_filter(context, id):
                        pf = self._update_packet_filter(context, pf, pf_data)
                    else:
                        pf = self.activate_packet_filter_if_ready(context, pf)
                else:
                    LOG.debug('update_packet_filter: admin_state is unchanged '
                              '(False). No need to update OFC filter.')
            else:
                pf = self.deactivate_packet_filter(context, pf)
                pf = self.activate_packet_filter_if_ready(context, pf)

        return pf

    def _update_packet_filter(self, context, new_pf, pf_data):
        pf_id = new_pf['id']
        prev_status = new_pf['status']
        try:
            # If previous status is ERROR, try to sync all attributes.
            pf = new_pf if prev_status == pf_db.PF_STATUS_ERROR else pf_data
            self.ofc.update_ofc_packet_filter(context, pf_id, pf)
            new_status = pf_db.PF_STATUS_ACTIVE
            if new_status != prev_status:
                self._update_resource_status(context, "packet_filter",
                                             pf_id, new_status)
                new_pf['status'] = new_status
            return new_pf
        except Exception as exc:
            with excutils.save_and_reraise_exception():
                if (isinstance(exc, nexc.OFCException) or
                    isinstance(exc, nexc.OFCConsistencyBroken)):
                    LOG.error(_LE("Failed to create packet_filter id=%(id)s "
                                  "on OFC: %(exc)s"),
                              {'id': pf_id, 'exc': exc})
                new_status = pf_db.PF_STATUS_ERROR
                if new_status != prev_status:
                    self._update_resource_status(context, "packet_filter",
                                                 pf_id, new_status)

    def delete_packet_filter(self, context, id):
        """Deactivate and delete packet_filter."""
        LOG.debug("delete_packet_filter() called, id=%s .", id)

        # validate ownership
        pf = self.get_packet_filter(context, id)

        # deactivate_packet_filter() raises an exception
        # if an error occurs during processing.
        pf = self.deactivate_packet_filter(context, pf)

        super(PacketFilterMixin, self).delete_packet_filter(context, id)

    def activate_packet_filter_if_ready(self, context, packet_filter):
        """Activate packet_filter by creating filter on OFC if ready.

        Conditions to create packet_filter on OFC are:
            * packet_filter admin_state is UP
            * (if 'in_port' is specified) portinfo is available
        """
        LOG.debug("activate_packet_filter_if_ready() called, "
                  "packet_filter=%s.", packet_filter)

        pf_id = packet_filter['id']
        current = packet_filter['status']

        pf_status = current
        if not packet_filter['admin_state_up']:
            LOG.debug("activate_packet_filter_if_ready(): skip pf_id=%s, "
                      "packet_filter.admin_state_up is False.", pf_id)
        elif self.ofc.exists_ofc_packet_filter(context, packet_filter['id']):
            LOG.debug("_activate_packet_filter_if_ready(): skip, "
                      "ofc_packet_filter already exists.")
        else:
            LOG.debug("activate_packet_filter_if_ready(): create "
                      "packet_filter id=%s on OFC.", pf_id)
            try:
                self.ofc.create_ofc_packet_filter(context, pf_id,
                                                  packet_filter)
                pf_status = pf_db.PF_STATUS_ACTIVE
            except nexc.PortInfoNotFound:
                LOG.debug("Skipped to create a packet filter pf_id=%s "
                          "on OFC, no portinfo for the in_port.", pf_id)
            except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
                LOG.error(_LE("Failed to create packet_filter id=%(id)s on "
                              "OFC: %(exc)s"), {'id': pf_id, 'exc': exc})
                pf_status = pf_db.PF_STATUS_ERROR

        if pf_status != current:
            self._update_resource_status(context, "packet_filter", pf_id,
                                         pf_status)
            packet_filter.update({'status': pf_status})

        return packet_filter

    def deactivate_packet_filter(self, context, packet_filter):
        """Deactivate packet_filter by deleting filter from OFC if exixts."""
        LOG.debug("deactivate_packet_filter_if_ready() called, "
                  "packet_filter=%s.", packet_filter)
        pf_id = packet_filter['id']

        if not self.ofc.exists_ofc_packet_filter(context, pf_id):
            LOG.debug("deactivate_packet_filter(): skip, "
                      "Not found OFC Mapping for packet_filter id=%s.",
                      pf_id)
            return packet_filter

        LOG.debug("deactivate_packet_filter(): "
                  "deleting packet_filter id=%s from OFC.", pf_id)
        try:
            self.ofc.delete_ofc_packet_filter(context, pf_id)
            self._update_resource_status_if_changed(
                context, "packet_filter", packet_filter, pf_db.PF_STATUS_DOWN)
            return packet_filter
        except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete packet_filter id=%(id)s "
                              "from OFC: %(exc)s"),
                          {'id': pf_id, 'exc': exc})
                self._update_resource_status_if_changed(
                    context, "packet_filter", packet_filter,
                    pf_db.PF_STATUS_ERROR)

    def activate_packet_filters_by_port(self, context, port_id):
        if not self.packet_filter_enabled:
            return

        filters = {'in_port': [port_id], 'admin_state_up': [True],
                   'status': [pf_db.PF_STATUS_DOWN]}
        pfs = self.get_packet_filters(context, filters=filters)
        for pf in pfs:
            self.activate_packet_filter_if_ready(context, pf)

    def deactivate_packet_filters_by_port(self, context, port_id,
                                          raise_exc=True):
        if not self.packet_filter_enabled:
            return

        filters = {'in_port': [port_id], 'status': [pf_db.PF_STATUS_ACTIVE]}
        pfs = self.get_packet_filters(context, filters=filters)
        error = False
        for pf in pfs:
            try:
                self.deactivate_packet_filter(context, pf)
            except (nexc.OFCException, nexc.OFCMappingNotFound):
                error = True
        if raise_exc and error:
            raise nexc.OFCException(_('Error occurred while disabling packet '
                                      'filter(s) for port %s'), port_id)

    def get_packet_filters_for_port(self, context, port):
        if self.packet_filter_enabled:
            return super(PacketFilterMixin,
                         self).get_packet_filters_for_port(context, port)
