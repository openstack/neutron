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

from oslo_log import log

from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import constants as ovsdbapp_const

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron import manager
from neutron.objects import port_forwarding as port_forwarding_obj
from neutron.services.portforwarding import constants as pf_const

LOG = log.getLogger(__name__)


class OVNPortForwardingHandler(object):
    @staticmethod
    def _get_lb_protocol(pf_obj):
        return pf_const.LB_PROTOCOL_MAP[pf_obj.protocol]

    @staticmethod
    def lb_name(fip_id, proto, external_port=''):
        if external_port:
            external_port = '-%s' % external_port
        return "{}-{}-{}{}".format(
            pf_const.PORT_FORWARDING_PREFIX, fip_id, proto, external_port)

    @classmethod
    def lb_names(cls, fip_id):
        return [cls.lb_name(fip_id, proto)
                for proto in pf_const.LB_PROTOCOL_MAP.values()]

    @classmethod
    def _get_lb_attributes(cls, pf_obj, is_range=False):
        external_port = pf_obj.external_port if is_range else ''
        lb_name = cls.lb_name(pf_obj.floatingip_id,
                              cls._get_lb_protocol(pf_obj),
                              external_port)
        vip = "{}:{}".format(pf_obj.floating_ip_address, pf_obj.external_port)
        internal_ip = "{}:{}".format(pf_obj.internal_ip_address,
                                     pf_obj.internal_port)
        rtr_name = 'neutron-{}'.format(pf_obj.router_id)
        return lb_name, vip, [internal_ip], rtr_name

    def _get_lbs_and_ls(self, nb_ovn, payload):
        rtr_name = ovn_utils.ovn_name(payload.resource_id)
        ovn_lr = nb_ovn.get_lrouter(rtr_name)
        if ovn_lr:
            ext_id_key = ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY
            # Filter only lbs managed by port forwarding plugin
            lr_lbs = [lr for lr in ovn_lr.load_balancer
                      if lr.external_ids.get(ext_id_key) ==
                      pf_const.PORT_FORWARDING_PLUGIN]
            r_port = payload.metadata.get('port')

            if r_port:
                ls_name = ovn_utils.ovn_name(r_port['network_id'])
                ovn_ls = nb_ovn.get_lswitch(ls_name)
                ls_lbs = ovn_ls.load_balancer
                return lr_lbs, ls_lbs, ls_name
        return [], [], None

    def _add_lb_on_ls(self, ovn_txn, nb_ovn, payload):
        lr_lbs, ls_lbs, ls_name = self._get_lbs_and_ls(nb_ovn, payload)
        for lb in lr_lbs:
            if lb not in ls_lbs:
                ovn_txn.add(nb_ovn.ls_lb_add(ls_name, lb.name, may_exist=True))

    def _del_lb_on_ls(self, ovn_txn, nb_ovn, payload):
        lr_lbs, ls_lbs, ls_name = self._get_lbs_and_ls(nb_ovn, payload)
        for lb in lr_lbs:
            if lb in ls_lbs:
                ovn_txn.add(nb_ovn.ls_lb_del(ls_name, lb.name))

    def _port_forwarding_created(self, ovn_txn, nb_ovn, pf_obj,
                                 is_range=False):
        # Add vip to its corresponding load balancer. There can be multiple
        # vips, so load balancer may already be present.
        lb_name, vip, internal_ips, rtr_name = self._get_lb_attributes(
            pf_obj, is_range=is_range)
        external_ids = {
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                pf_const.PORT_FORWARDING_PLUGIN,
            ovn_const.OVN_FIP_EXT_ID_KEY: pf_obj.floatingip_id,
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: rtr_name,
        }
        ovn_txn.add(
            nb_ovn.lb_add(lb_name, vip, internal_ips,
                          self._get_lb_protocol(pf_obj), may_exist=True,
                          external_ids=external_ids))
        # Ensure logical router has load balancer configured.
        ovn_txn.add(nb_ovn.lr_lb_add(rtr_name, lb_name, may_exist=True))
        # Ensure logical switches on logical router have load balancer
        # configured, can be removed this handling if in future ovn
        # supports auto handling of lbs on ls rhbz#2043543
        ovn_lr = nb_ovn.get_lrouter(rtr_name)
        if ovn_lr:
            ext_id_key = ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY
            ovn_lss = [port.external_ids.get(ext_id_key)
                       for port in ovn_lr.ports
                       if port.external_ids.get(ext_id_key) and
                       not port.gateway_chassis]
            for ls_name in ovn_lss:
                try:
                    ovn_txn.add(nb_ovn.ls_lb_add(ls_name, lb_name,
                                                 may_exist=True))
                except idlutils.RowNotFound:
                    # If one or more logical_switches are deleted
                    # log warning for those and continue with the rest.
                    LOG.warning("Addition of Load Balancer %s to Logical "
                                "Switch %s failed as it is not found",
                                lb_name, ls_name)

    def port_forwarding_created(self, ovn_txn, nb_ovn, pf_obj):
        pf_objs = pf_obj.unroll_port_ranges()
        is_range = len(pf_objs) > 1
        for pf_obj in pf_objs:
            LOG.info("CREATE for port-forwarding %s vip %s:%s to %s:%s",
                     pf_obj.protocol,
                     pf_obj.floating_ip_address, pf_obj.external_port,
                     pf_obj.internal_ip_address, pf_obj.internal_port)
            self._port_forwarding_created(ovn_txn, nb_ovn, pf_obj,
                                          is_range=is_range)

    def port_forwarding_updated(self, ovn_txn, nb_ovn, pf_obj, orig_pf_obj):
        orig_pf_objs = orig_pf_obj.unroll_port_ranges()
        is_range = len(orig_pf_objs) > 1
        for orig_pf_obj in orig_pf_objs:
            self._port_forwarding_deleted(ovn_txn, nb_ovn, orig_pf_obj,
                                          is_range=is_range)
        pf_objs = pf_obj.unroll_port_ranges()
        is_range = len(pf_objs) > 1
        for pf_obj in pf_objs:
            LOG.info("UPDATE for port-forwarding %s vip %s:%s to %s:%s",
                     pf_obj.protocol,
                     pf_obj.floating_ip_address, pf_obj.external_port,
                     pf_obj.internal_ip_address, pf_obj.internal_port)
            self._port_forwarding_created(ovn_txn, nb_ovn, pf_obj,
                                          is_range=is_range)

    def _port_forwarding_deleted(self, ovn_txn, nb_ovn, pf_obj,
                                 is_range=False):
        # NOTE: load balancer instance is expected to be removed by api once
        #       last vip is removed.
        #       Since router has weak ref to the lb, that gets taken care
        #       automatically, but that it is not best practice to rely on
        #       that. Unfortunately, we would need to add extra logic that
        #       ensures that the lr_lb_del is invoked only after the last
        #       vip was removed. So...
        # TODO(flaviof): see about enhancing lb_del so that removal of lb
        # can optionally take a logical router, which explicitly dissociates
        # router from removed lb.
        pf_objs = pf_obj.unroll_port_ranges()
        is_range = is_range or len(pf_objs) > 1
        for pf_obj in pf_objs:
            lb_name, vip, _internal_ips, _rtr = self._get_lb_attributes(
                pf_obj, is_range=is_range)
            ovn_txn.add(nb_ovn.lb_del(lb_name, vip, if_exists=True))

    def port_forwarding_deleted(self, ovn_txn, nb_ovn, pf_obj):
        pf_objs = pf_obj.unroll_port_ranges()
        is_range = len(pf_objs) > 1
        for pf_obj in pf_objs:
            LOG.info("DELETE for port-forwarding %s vip %s:%s to %s:%s",
                     pf_obj.protocol,
                     pf_obj.floating_ip_address, pf_obj.external_port,
                     pf_obj.internal_ip_address, pf_obj.internal_port)
            self._port_forwarding_deleted(ovn_txn, nb_ovn, pf_obj,
                                          is_range=is_range)


@registry.has_registry_receivers
class OVNPortForwarding(object):

    def __init__(self, l3_plugin):
        self._l3_plugin = l3_plugin
        self._pf_plugin_property = None
        self._handler = OVNPortForwardingHandler()

    @property
    def _pf_plugin(self):
        if self._pf_plugin_property is None:
            self._pf_plugin_property = directory.get_plugin(
                plugin_constants.PORTFORWARDING)
            if not self._pf_plugin_property:
                self._pf_plugin_property = (
                    manager.NeutronManager.load_class_for_provider(
                        'neutron.service_plugins', 'port_forwarding')())
        return self._pf_plugin_property

    def _get_pf_objs(self, context, fip_id):
        pf_dicts = self._pf_plugin.get_floatingip_port_forwardings(
            context, fip_id)
        return [port_forwarding_obj.PortForwarding(context=context, **pf_dict)
                for pf_dict in pf_dicts]

    def _get_fip_objs(self, context, payload):
        floatingip_ids = set()
        for fip in payload.states:
            floatingip_ids.add(fip.floatingip_id)
        return {fip_id: self._l3_plugin.get_floatingip(context, fip_id)
                for fip_id in floatingip_ids}

    def _add_check_rev(self, ovn_txn, ovn_nb, fip_id, fip_obj):
        """Updating revision number of OVN lb entries based on floatingip id

           A single floating ip maps to 1 or 2 OVN load balancer entries,
           because while multiple vips can exist in a single OVN LB row,
           they represent one protocol. So, to handle all port forwardings
           for a given floating ip, OVN will have up to two LB entries: one
           for udp and one for tcp. These 2 LB entries are expected to have
           the same revision number, in sync with the revision of the floating
           ip. And that is set via this function.
        """
        check_rev_tuples = []
        for lb_name in self._handler.lb_names(fip_id):
            check_rev_cmd = ovn_nb.check_revision_number(
                lb_name, fip_obj, ovn_const.TYPE_FLOATINGIPS, if_exists=True)
            ovn_txn.add(check_rev_cmd)
            check_rev_tuples.append((check_rev_cmd, fip_obj))
        return check_rev_tuples

    def _do_db_rev_bump_revision(self, context, check_rev_tuples):
        if not all(check_rev_cmd.result == ovn_const.TXN_COMMITTED
                   for check_rev_cmd, _fip_obj in check_rev_tuples):
            return
        for _check_rev_cmd, fip_obj in check_rev_tuples:
            db_rev.bump_revision(context, fip_obj, ovn_const.TYPE_FLOATINGIPS)

    def _handle_notification(self, _resource, event_type, _pf_plugin, payload):
        if not payload:
            return
        context = payload.context
        ovn_nb = self._l3_plugin._nb_ovn
        with ovn_nb.transaction(check_error=True) as ovn_txn:
            if event_type == events.AFTER_CREATE:
                self._handler.port_forwarding_created(ovn_txn, ovn_nb,
                                                      payload.latest_state)
                self._l3_plugin.update_floatingip_status(
                    context, payload.latest_state.floatingip_id,
                    const.FLOATINGIP_STATUS_ACTIVE)
            elif event_type == events.AFTER_UPDATE:
                self._handler.port_forwarding_updated(
                    ovn_txn, ovn_nb,
                    payload.latest_state, payload.states[0])
            elif event_type == events.AFTER_DELETE:
                pfs = _pf_plugin.get_floatingip_port_forwardings(
                    context, payload.states[0].floatingip_id)
                self._handler.port_forwarding_deleted(ovn_txn, ovn_nb,
                                                      payload.states[0])
                if not pfs:
                    self._l3_plugin.update_floatingip_status(
                        context, payload.states[0].floatingip_id,
                        const.FLOATINGIP_STATUS_DOWN)

            # Collect the revision numbers of all floating ips visited and
            # update the corresponding load balancer entries affected.
            # Note that there may be 2 entries for a given floatingip_id;
            # one for each protocol.
            fip_objs = self._get_fip_objs(context, payload)
            if not fip_objs:
                return
            for floatingip_id, fip_obj in fip_objs.items():
                check_rev_tuples = self._add_check_rev(
                    ovn_txn, ovn_nb, floatingip_id, fip_obj)
        # Update revision of affected floating ips. Note that even in
        # cases where port forwarding is deleted, floating ip remains.
        self._do_db_rev_bump_revision(context, check_rev_tuples)

    def _maintenance_create_update(self, context, fip_id):
        # NOTE: Since the maintenance callback is not granular to the level
        #       of the affected pfs AND the fact that pfs are all vips
        #       in a load balancer entry, it is cheap enough to simply rebuild.
        pf_objs = self._get_pf_objs(context, fip_id)
        LOG.debug("Maintenance port forwarding under fip %s : %s",
                  fip_id, pf_objs)
        ovn_nb = self._l3_plugin._nb_ovn
        with ovn_nb.transaction(check_error=True) as ovn_txn:
            for lb_name in self._handler.lb_names(fip_id):
                ovn_txn.add(ovn_nb.lb_del(lb_name, vip=None, if_exists=True))
            for pf_obj in pf_objs:
                self._handler.port_forwarding_created(
                    ovn_txn, ovn_nb, pf_obj)
            fip_obj = self._l3_plugin.get_floatingip(context, fip_id)
            check_rev_tuples = self._add_check_rev(
                ovn_txn, ovn_nb, fip_id, fip_obj)
            self._do_db_rev_bump_revision(context, check_rev_tuples)

    def maintenance_create(self, context, floatingip):
        fip_id = floatingip['id']
        LOG.info("Maintenance CREATE port-forwarding entries under fip %s",
                 fip_id)
        self._maintenance_create_update(context, fip_id)

    def maintenance_update(self, context, floatingip):
        fip_id = floatingip['id']
        LOG.info("Maintenance UPDATE port-forwarding entries under fip %s",
                 fip_id)
        self._maintenance_create_update(context, fip_id)

    def maintenance_delete(self, _context, fip_id):
        LOG.info("Maintenance DELETE port-forwarding entries under fip %s",
                 fip_id)
        ovn_nb = self._l3_plugin._nb_ovn
        with ovn_nb.transaction(check_error=True) as ovn_txn:
            for lb_name in self._handler.lb_names(fip_id):
                ovn_txn.add(ovn_nb.lb_del(lb_name, vip=None, if_exists=True))

    def db_sync_create_or_update(self, context, fip_id, ovn_txn):
        LOG.info("db_sync UPDATE entries under fip %s", fip_id)
        # NOTE: Since the db_sync callback is not granular to the level
        #       of the affected pfs AND the fact that pfs are all vips
        #       in a load balancer entry, it is cheap enough to simply rebuild.
        ovn_nb = self._l3_plugin._nb_ovn
        pf_objs = self._get_pf_objs(context, fip_id)
        LOG.debug("Db sync port forwarding under fip %s : %s", fip_id, pf_objs)
        for lb_name in self._handler.lb_names(fip_id):
            ovn_txn.add(ovn_nb.lb_del(lb_name, vip=None, if_exists=True))
        for pf_obj in pf_objs:
            self._handler.port_forwarding_created(ovn_txn, ovn_nb, pf_obj)
        fip_obj = self._l3_plugin.get_floatingip(context, fip_id)
        self._add_check_rev(ovn_txn, ovn_nb, fip_id, fip_obj)

    def db_sync_delete(self, context, fip_id, ovn_txn):
        LOG.info("db_sync DELETE entries under fip %s", fip_id)
        ovn_nb = self._l3_plugin._nb_ovn
        for lb_name in self._handler.lb_names(fip_id):
            ovn_txn.add(ovn_nb.lb_del(lb_name, vip=None, if_exists=True))

    def _handle_lb_on_ls(self, _resource, event_type, _pf_plugin, payload):
        if not payload:
            return
        ovn_nb = self._l3_plugin._nb_ovn
        with ovn_nb.transaction(check_error=True) as ovn_txn:
            if event_type == events.AFTER_CREATE:
                self._handler._add_lb_on_ls(ovn_txn, ovn_nb,
                                            payload)
            if event_type == events.AFTER_DELETE:
                self._handler._del_lb_on_ls(ovn_txn, ovn_nb,
                                            payload)

    @staticmethod
    def ovn_lb_protocol(pf_protocol):
        return pf_const.LB_PROTOCOL_MAP.get(
            pf_protocol, ovsdbapp_const.PROTO_TCP)

    @registry.receives(pf_const.PORT_FORWARDING_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        for event_type in (events.AFTER_CREATE, events.AFTER_UPDATE,
                           events.AFTER_DELETE):
            registry.subscribe(self._handle_notification,
                               pf_const.PORT_FORWARDING, event_type)
            if event_type in (events.AFTER_CREATE, events.AFTER_DELETE):
                registry.subscribe(self._handle_lb_on_ls,
                                   resources.ROUTER_INTERFACE, event_type)
