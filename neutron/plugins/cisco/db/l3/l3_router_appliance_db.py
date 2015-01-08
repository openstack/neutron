# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import copy

from oslo_concurrency import lockutils
from oslo_config import cfg
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import expression as expr

from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as n_context
from neutron.db import agents_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import portbindings_db as p_binding
from neutron.extensions import providernet as pr_net
from neutron.i18n import _LE, _LI
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.plugins.cisco.l3.rpc import l3_router_rpc_joint_agent_api

LOG = logging.getLogger(__name__)


ROUTER_APPLIANCE_OPTS = [
    cfg.IntOpt('backlog_processing_interval',
               default=10,
               help=_('Time in seconds between renewed scheduling attempts of '
                      'non-scheduled routers.')),
]

cfg.CONF.register_opts(ROUTER_APPLIANCE_OPTS, "general")


class RouterCreateInternalError(n_exc.NeutronException):
    message = _("Router could not be created due to internal error.")


class RouterInternalError(n_exc.NeutronException):
    message = _("Internal error during router processing.")


class RouterBindingInfoError(n_exc.NeutronException):
    message = _("Could not get binding information for router %(router_id)s.")


class L3RouterApplianceDBMixin(extraroute_db.ExtraRoute_dbonly_mixin):
    """Mixin class implementing Neutron's routing service using appliances."""

    # Dictionary of routers for which new scheduling attempts should
    # be made and the refresh setting and heartbeat for that.
    _backlogged_routers = {}
    _refresh_router_backlog = True
    _heartbeat = None

    @property
    def l3_cfg_rpc_notifier(self):
        if not hasattr(self, '_l3_cfg_rpc_notifier'):
            self._l3_cfg_rpc_notifier = (l3_router_rpc_joint_agent_api.
                                         L3RouterJointAgentNotifyAPI(self))
        return self._l3_cfg_rpc_notifier

    @l3_cfg_rpc_notifier.setter
    def l3_cfg_rpc_notifier(self, value):
        self._l3_cfg_rpc_notifier = value

    def create_router(self, context, router):
        with context.session.begin(subtransactions=True):
            if self.mgmt_nw_id() is None:
                raise RouterCreateInternalError()
            router_created = (super(L3RouterApplianceDBMixin, self).
                              create_router(context, router))
            r_hd_b_db = l3_models.RouterHostingDeviceBinding(
                router_id=router_created['id'],
                auto_schedule=True,
                hosting_device_id=None)
            context.session.add(r_hd_b_db)
        # backlog so this new router gets scheduled asynchronously
        self.backlog_router(r_hd_b_db['router'])
        return router_created

    def update_router(self, context, id, router):
        r = router['router']
        # Check if external gateway has changed so we may have to
        # update trunking
        o_r_db = self._get_router(context, id)
        old_ext_gw = (o_r_db.gw_port or {}).get('network_id')
        new_ext_gw = (r.get('external_gateway_info', {}) or {}).get(
            'network_id')
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            if old_ext_gw is not None and old_ext_gw != new_ext_gw:
                o_r = self._make_router_dict(o_r_db, process_extensions=False)
                # no need to schedule now since we're only doing this to
                # tear-down connectivity and there won't be any if not
                # already scheduled.
                self._add_type_and_hosting_device_info(e_context, o_r,
                                                       schedule=False)
                p_drv = self.get_hosting_device_plugging_driver()
                if p_drv is not None:
                    p_drv.teardown_logical_port_connectivity(e_context,
                                                             o_r_db.gw_port)
            router_updated = (
                super(L3RouterApplianceDBMixin, self).update_router(
                    context, id, router))
            routers = [copy.deepcopy(router_updated)]
            self._add_type_and_hosting_device_info(e_context, routers[0])
        self.l3_cfg_rpc_notifier.routers_updated(context, routers)
        return router_updated

    def delete_router(self, context, id):
        router_db = self._get_router(context, id)
        router = self._make_router_dict(router_db)
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            r_hd_binding = self._get_router_binding_info(e_context, id)
            self._add_type_and_hosting_device_info(
                e_context, router, binding_info=r_hd_binding, schedule=False)
            if router_db.gw_port is not None:
                p_drv = self.get_hosting_device_plugging_driver()
                if p_drv is not None:
                    p_drv.teardown_logical_port_connectivity(e_context,
                                                             router_db.gw_port)
            # conditionally remove router from backlog just to be sure
            self.remove_router_from_backlog(id)
            if router['hosting_device'] is not None:
                self.unschedule_router_from_hosting_device(context,
                                                           r_hd_binding)
            super(L3RouterApplianceDBMixin, self).delete_router(context, id)
        self.l3_cfg_rpc_notifier.router_deleted(context, router)

    def notify_router_interface_action(
            self, context, router_interface_info, routers, action):
        l3_method = '%s_router_interface' % action
        self.l3_cfg_rpc_notifier.routers_updated(context, routers, l3_method)

        mapping = {'add': 'create', 'remove': 'delete'}
        notifier = n_rpc.get_notifier('network')
        router_event = 'router.interface.%s' % mapping[action]
        notifier.info(context, router_event,
                      {'router_interface': router_interface_info})

    def add_router_interface(self, context, router_id, interface_info):
        with context.session.begin(subtransactions=True):
            info = (super(L3RouterApplianceDBMixin, self).
                    add_router_interface(context, router_id, interface_info))
            routers = [self.get_router(context, router_id)]
            self._add_type_and_hosting_device_info(context.elevated(),
                                                   routers[0])
        self.notify_router_interface_action(context, info, routers, 'add')
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        if 'port_id' in (interface_info or {}):
            port_db = self._core_plugin._get_port(
                context, interface_info['port_id'])
        elif 'subnet_id' in (interface_info or {}):
            subnet_db = self._core_plugin._get_subnet(
                context, interface_info['subnet_id'])
            port_db = self._get_router_port_db_on_subnet(
                context, router_id, subnet_db)
        else:
            msg = _("Either subnet_id or port_id must be specified")
            raise n_exc.BadRequest(resource='router', msg=msg)
        routers = [self.get_router(context, router_id)]
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            self._add_type_and_hosting_device_info(e_context, routers[0])
            p_drv = self.get_hosting_device_plugging_driver()
            if p_drv is not None:
                p_drv.teardown_logical_port_connectivity(e_context, port_db)
            info = (super(L3RouterApplianceDBMixin, self).
                    remove_router_interface(context, router_id,
                                            interface_info))
        self.notify_router_interface_action(context, info, routers, 'remove')
        return info

    def create_floatingip(
            self, context, floatingip,
            initial_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        with context.session.begin(subtransactions=True):
            info = super(L3RouterApplianceDBMixin, self).create_floatingip(
                context, floatingip)
            if info['router_id']:
                routers = [self.get_router(context, info['router_id'])]
                self._add_type_and_hosting_device_info(context.elevated(),
                                                       routers[0])
                self.l3_cfg_rpc_notifier.routers_updated(context, routers,
                                                         'create_floatingip')
        return info

    def update_floatingip(self, context, id, floatingip):
        orig_fl_ip = super(L3RouterApplianceDBMixin, self).get_floatingip(
            context, id)
        before_router_id = orig_fl_ip['router_id']
        with context.session.begin(subtransactions=True):
            info = super(L3RouterApplianceDBMixin, self).update_floatingip(
                context, id, floatingip)
            router_ids = []
            if before_router_id:
                router_ids.append(before_router_id)
            router_id = info['router_id']
            if router_id and router_id != before_router_id:
                router_ids.append(router_id)
            routers = []
            for router_id in router_ids:
                router = self.get_router(context, router_id)
                self._add_type_and_hosting_device_info(context.elevated(),
                                                       router)
                routers.append(router)
        self.l3_cfg_rpc_notifier.routers_updated(context, routers,
                                                 'update_floatingip')
        return info

    def delete_floatingip(self, context, id):
        floatingip_db = self._get_floatingip(context, id)
        router_id = floatingip_db['router_id']
        with context.session.begin(subtransactions=True):
            super(L3RouterApplianceDBMixin, self).delete_floatingip(
                context, id)
            if router_id:
                routers = [self.get_router(context, router_id)]
                self._add_type_and_hosting_device_info(context.elevated(),
                                                       routers[0])
                self.l3_cfg_rpc_notifier.routers_updated(context, routers,
                                                         'delete_floatingip')

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        with context.session.begin(subtransactions=True):
            router_ids = super(L3RouterApplianceDBMixin,
                               self).disassociate_floatingips(context, port_id)
            if router_ids and do_notify:
                routers = []
                for router_id in router_ids:
                    router = self.get_router(context, router_id)
                    self._add_type_and_hosting_device_info(context.elevated(),
                                                           router)
                    routers.append(router)
                self.l3_cfg_rpc_notifier.routers_updated(
                    context, routers, 'disassociate_floatingips')
                # since caller assumes that we handled notifications on its
                # behalf, return nothing
                return
            return router_ids

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def _handle_non_responding_hosting_devices(self, context, hosting_devices,
                                               affected_resources):
        """Handle hosting devices determined to be "dead".

        This function is called by the hosting device manager.
        Service plugins are supposed to extend the 'affected_resources'
        dictionary. Hence, we add the id of Neutron routers that are
        hosted in <hosting_devices>.

        param: hosting_devices - list of dead hosting devices
        param: affected_resources - dict with list of affected logical
                                    resources per hosting device:
             {'hd_id1': {'routers': [id1, id2, ...],
                         'fw': [id1, ...],
                         ...},
              'hd_id2': {'routers': [id3, id4, ...],
                         'fw': [id1, ...],
                         ...},
              ...}
        """
        LOG.debug('Processing affected routers in dead hosting devices')
        with context.session.begin(subtransactions=True):
            for hd in hosting_devices:
                hd_bindings = self._get_hosting_device_bindings(context,
                                                                hd['id'])
                router_ids = []
                for binding in hd_bindings:
                    router_ids.append(binding['router_id'])
                    if binding['auto_schedule']:
                        self.backlog_router(binding['router'])
                try:
                    affected_resources[hd['id']].update(
                        {'routers': router_ids})
                except KeyError:
                    affected_resources[hd['id']] = {'routers': router_ids}

    def get_sync_data_ext(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces.

        Adds information about hosting device as well as trunking.
        """
        with context.session.begin(subtransactions=True):
            sync_data = (super(L3RouterApplianceDBMixin, self).
                         get_sync_data(context, router_ids, active))
            for router in sync_data:
                self._add_type_and_hosting_device_info(context, router)
                plg_drv = self.get_hosting_device_plugging_driver()
                if plg_drv and router['hosting_device']:
                    self._add_hosting_port_info(context, router, plg_drv)
        return sync_data

    def schedule_router_on_hosting_device(self, context, r_hd_binding):
        LOG.info(_LI('Attempting to schedule router %s.'),
                 r_hd_binding['router']['id'])
        result = self._create_csr1kv_vm_hosting_device(context.elevated())
        if result is None:
            # CSR1kv hosting device creation was unsuccessful so backlog
            # it for another scheduling attempt later.
            self.backlog_router(r_hd_binding['router'])
            return False
        with context.session.begin(subtransactions=True):
            router = r_hd_binding['router']
            r_hd_binding.hosting_device = result
            self.remove_router_from_backlog(router['id'])
            LOG.info(_LI('Successfully scheduled router %(r_id)s to '
                       'hosting device %(d_id)s'),
                     {'r_id': r_hd_binding['router']['id'],
                      'd_id': result['id']})
        return True

    def unschedule_router_from_hosting_device(self, context, r_hd_binding):
        LOG.info(_LI('Un-schedule router %s.'),
                 r_hd_binding['router']['id'])
        hosting_device = r_hd_binding['hosting_device']
        if r_hd_binding['hosting_device'] is None:
            return False
        self._delete_service_vm_hosting_device(context.elevated(),
                                               hosting_device)

    @lockutils.synchronized('routers', 'neutron-')
    def backlog_router(self, router):
        if ((router or {}).get('id') is None or
                router['id'] in self._backlogged_routers):
            return
        LOG.info(_LI('Backlogging router %s for renewed scheduling attempt '
                   'later'), router['id'])
        self._backlogged_routers[router['id']] = router

    @lockutils.synchronized('routers', 'neutron-')
    def remove_router_from_backlog(self, id):
        self._backlogged_routers.pop(id, None)
        LOG.info(_LI('Router %s removed from backlog'), id)

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def _process_backlogged_routers(self):
        if self._refresh_router_backlog:
            self._sync_router_backlog()
        if not self._backlogged_routers:
            return
        context = n_context.get_admin_context()
        scheduled_routers = []
        LOG.info(_LI('Processing router (scheduling) backlog'))
        # try to reschedule
        for r_id, router in self._backlogged_routers.items():
            self._add_type_and_hosting_device_info(context, router)
            if router.get('hosting_device'):
                # scheduling attempt succeeded
                scheduled_routers.append(router)
                self._backlogged_routers.pop(r_id, None)
        # notify cfg agents so the scheduled routers are instantiated
        if scheduled_routers:
            self.l3_cfg_rpc_notifier.routers_updated(context,
                                                     scheduled_routers)

    def _setup_backlog_handling(self):
        self._heartbeat = loopingcall.FixedIntervalLoopingCall(
            self._process_backlogged_routers)
        self._heartbeat.start(
            interval=cfg.CONF.general.backlog_processing_interval)

    def _sync_router_backlog(self):
        LOG.info(_LI('Synchronizing router (scheduling) backlog'))
        context = n_context.get_admin_context()
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        query = query.options(joinedload('router'))
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            expr.null())
        for binding in query:
            router = self._make_router_dict(binding.router,
                                            process_extensions=False)
            self._backlogged_routers[binding.router_id] = router
        self._refresh_router_backlog = False

    def _get_router_binding_info(self, context, id, load_hd_info=True):
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        if load_hd_info:
            query = query.options(joinedload('hosting_device'))
        query = query.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                             id)
        try:
            return query.one()
        except exc.NoResultFound:
            # This should not happen
            LOG.error(_LE('DB inconsistency: No type and hosting info '
                          'associated with router %s'), id)
            raise RouterBindingInfoError(router_id=id)
        except exc.MultipleResultsFound:
            # This should not happen either
            LOG.error(_LE('DB inconsistency: Multiple type and hosting info '
                          'associated with router %s'), id)
            raise RouterBindingInfoError(router_id=id)

    def _get_hosting_device_bindings(self, context, id, load_routers=False,
                                     load_hosting_device=False):
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        if load_routers:
            query = query.options(joinedload('router'))
        if load_hosting_device:
            query = query.options(joinedload('hosting_device'))
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.hosting_device_id == id)
        return query.all()

    def _add_type_and_hosting_device_info(self, context, router,
                                          binding_info=None, schedule=True):
        """Adds type and hosting device information to a router."""
        try:
            if binding_info is None:
                binding_info = self._get_router_binding_info(context,
                                                             router['id'])
        except RouterBindingInfoError:
            LOG.error(_LE('DB inconsistency: No hosting info associated with '
                        'router %s'), router['id'])
            router['hosting_device'] = None
            return
        router['router_type'] = {
            'id': None,
            'name': 'CSR1kv_router',
            'cfg_agent_driver': (cfg.CONF.hosting_devices
                                 .csr1kv_cfgagent_router_driver)}
        if binding_info.hosting_device is None and schedule:
            # This router has not been scheduled to a hosting device
            # so we try to do it now.
            self.schedule_router_on_hosting_device(context, binding_info)
            context.session.expire(binding_info)
        if binding_info.hosting_device is None:
            router['hosting_device'] = None
        else:
            router['hosting_device'] = self.get_device_info_for_agent(
                binding_info.hosting_device)

    def _add_hosting_port_info(self, context, router, plugging_driver):
        """Adds hosting port information to router ports.

        We only populate hosting port info, i.e., reach here, if the
        router has been scheduled to a hosting device. Hence this
        a good place to allocate hosting ports to the router ports.
        """
        # cache of hosting port information: {mac_addr: {'name': port_name}}
        hosting_pdata = {}
        if router['external_gateway_info'] is not None:
            h_info, did_allocation = self._populate_hosting_info_for_port(
                context, router['id'], router['gw_port'],
                router['hosting_device'], hosting_pdata, plugging_driver)
        for itfc in router.get(l3_constants.INTERFACE_KEY, []):
            h_info, did_allocation = self._populate_hosting_info_for_port(
                context, router['id'], itfc, router['hosting_device'],
                hosting_pdata, plugging_driver)

    def _populate_hosting_info_for_port(self, context, router_id, port,
                                        hosting_device, hosting_pdata,
                                        plugging_driver):
        port_db = self._core_plugin._get_port(context, port['id'])
        h_info = port_db.hosting_info
        new_allocation = False
        if h_info is None:
            # The port does not yet have a hosting port so allocate one now
            h_info = self._allocate_hosting_port(
                context, router_id, port_db, hosting_device['id'],
                plugging_driver)
            if h_info is None:
                # This should not happen but just in case ...
                port['hosting_info'] = None
                return None, new_allocation
            else:
                new_allocation = True
        if hosting_pdata.get('mac') is None:
            p_data = self._core_plugin.get_port(
                context, h_info.hosting_port_id, ['mac_address', 'name'])
            hosting_pdata['mac'] = p_data['mac_address']
            hosting_pdata['name'] = p_data['name']
        # Including MAC address of hosting port so L3CfgAgent can easily
        # determine which VM VIF to configure VLAN sub-interface on.
        port['hosting_info'] = {'hosting_port_id': h_info.hosting_port_id,
                                'hosting_mac': hosting_pdata.get('mac'),
                                'hosting_port_name': hosting_pdata.get('name')}
        plugging_driver.extend_hosting_port_info(
            context, port_db, port['hosting_info'])
        return h_info, new_allocation

    def _allocate_hosting_port(self, context, router_id, port_db,
                               hosting_device_id, plugging_driver):
        net_data = self._core_plugin.get_network(
            context, port_db['network_id'], [pr_net.NETWORK_TYPE])
        network_type = net_data.get(pr_net.NETWORK_TYPE)
        alloc = plugging_driver.allocate_hosting_port(
            context, router_id, port_db, network_type, hosting_device_id)
        if alloc is None:
            LOG.error(_LE('Failed to allocate hosting port for port %s'),
                      port_db['id'])
            return
        with context.session.begin(subtransactions=True):
            h_info = l3_models.HostedHostingPortBinding(
                logical_resource_id=router_id,
                logical_port_id=port_db['id'],
                network_type=network_type,
                hosting_port_id=alloc['allocated_port_id'],
                segmentation_id=alloc['allocated_vlan'])
            context.session.add(h_info)
            context.session.expire(port_db)
        # allocation succeeded so establish connectivity for logical port
        context.session.expire(h_info)
        plugging_driver.setup_logical_port_connectivity(context, port_db)
        return h_info

    def _get_router_port_db_on_subnet(self, context, router_id, subnet):
        try:
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet['id']:
                    return p
        except exc.NoResultFound:
            return

    def list_active_sync_routers_on_hosting_devices(self, context, host,
                                                    router_ids=None,
                                                    hosting_device_ids=None):
        agent = self._get_agent_by_type_and_host(
            context, c_const.AGENT_TYPE_CFG, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.join(l3_models.HostingDevice)
        query = query.filter(l3_models.HostingDevice.cfg_agent_id == agent.id)
        if router_ids:
            if len(router_ids) == 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.router_id ==
                    router_ids[0])
            else:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.router_id.in_(
                        router_ids))
        if hosting_device_ids:
            if len(hosting_device_ids) == 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.hosting_device_id ==
                    hosting_device_ids[0])
            elif len(hosting_device_ids) > 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.hosting_device_id.in_(
                        hosting_device_ids))
        router_ids = [item[0] for item in query]
        if router_ids:
            return self.get_sync_data_ext(context, router_ids=router_ids,
                                          active=True)
        else:
            return []

    def get_active_routers_for_host(self, context, host):
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.join(
            models_v2.Port,
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            models_v2.Port.device_id)
        query = query.join(p_binding.PortBindingPort)
        query = query.filter(p_binding.PortBindingPort.host == host)
        query = query.filter(models_v2.Port.name == 'mgmt')
        router_ids = [item[0] for item in query]
        if router_ids:
            return self.get_sync_data_ext(context, router_ids=router_ids,
                                          active=True)
        else:
            return []

    @staticmethod
    def _agent_state_filter(check_active, last_heartbeat):
        """Filters only active agents, if requested."""
        if not check_active:
            return True
        return not agents_db.AgentDbMixin.is_agent_down(last_heartbeat)

    def get_host_for_router(self, context, router, admin_state_up=None,
                            check_active=False):
        query = context.session.query(agents_db.Agent.host,
                                      agents_db.Agent.heartbeat_timestamp)
        query = query.join(
            p_binding.PortBindingPort,
            p_binding.PortBindingPort.host == agents_db.Agent.host)
        query = query.join(
            models_v2.Port,
            models_v2.Port.id == p_binding.PortBindingPort.port_id)
        query = query.join(
            l3_models.RouterHostingDeviceBinding,
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            models_v2.Port.device_id)
        query = query.filter(
            agents_db.Agent.topic == topics.L3_AGENT,
            l3_models.RouterHostingDeviceBinding.router_id == router)
        if admin_state_up is not None:
            query = query.filter(
                agents_db.Agent.admin_state_up == admin_state_up)
        entry = query.first()
        if entry and L3RouterApplianceDBMixin._agent_state_filter(check_active,
                                                                  entry[1]):
            return entry[0]
        return ""
