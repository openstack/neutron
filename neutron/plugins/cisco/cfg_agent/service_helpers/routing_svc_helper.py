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

import collections

import eventlet
import netaddr
import oslo_messaging
from oslo_utils import excutils

from neutron.common import constants as l3_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as common_utils
from neutron import context as n_context
from neutron.i18n import _LE, _LI, _LW
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.cfg_agent import cfg_exceptions
from neutron.plugins.cisco.cfg_agent.device_drivers import driver_mgr
from neutron.plugins.cisco.cfg_agent import device_status
from neutron.plugins.cisco.common import cisco_constants as c_constants

LOG = logging.getLogger(__name__)

N_ROUTER_PREFIX = 'nrouter-'


class RouterInfo(object):
    """Wrapper class around the (neutron) router dictionary.

    Information about the neutron router is exchanged as a python dictionary
    between plugin and config agent. RouterInfo is a wrapper around that dict,
    with attributes for common parameters. These attributes keep the state
    of the current router configuration, and are used for detecting router
    state changes when an updated router dict is received.

    This is a modified version of the RouterInfo class defined in the
    (reference) l3-agent implementation, for use with cisco config agent.
    """

    def __init__(self, router_id, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.floating_ips = []
        self._router = None
        self.router = router
        self.routes = []
        self.ha_info = router.get('ha_info')

    @property
    def router(self):
        return self._router

    @property
    def id(self):
        return self.router_id

    @property
    def snat_enabled(self):
        return self._snat_enabled

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)

    def router_name(self):
        return N_ROUTER_PREFIX + self.router_id


class CiscoRoutingPluginApi(object):
    """RoutingServiceHelper(Agent) side of the  routing RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_routers(self, context, router_ids=None, hd_ids=None):
        """Make a remote process call to retrieve the sync data for routers.

        :param context: session context
        :param router_ids: list of  routers to fetch
        :param hd_ids : hosting device ids, only routers assigned to these
                        hosting devices will be returned.
        """
        cctxt = self.client.prepare(version='1.1')
        return cctxt.call(context, 'cfg_sync_routers', host=self.host,
                          router_ids=router_ids, hosting_device_ids=hd_ids)


class RoutingServiceHelper(object):

    def __init__(self, host, conf, cfg_agent):
        self.conf = conf
        self.cfg_agent = cfg_agent
        self.context = n_context.get_admin_context_without_session()
        self.plugin_rpc = CiscoRoutingPluginApi(topics.L3PLUGIN, host)
        self._dev_status = device_status.DeviceStatus()
        self._drivermgr = driver_mgr.DeviceDriverManager()

        self.router_info = {}
        self.updated_routers = set()
        self.removed_routers = set()
        self.sync_devices = set()
        self.fullsync = True
        self.topic = '%s.%s' % (c_constants.CFG_AGENT_L3_ROUTING, host)

        self._setup_rpc()

    def _setup_rpc(self):
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [self]
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    ### Notifications from Plugin ####

    def router_deleted(self, context, routers):
        """Deal with router deletion RPC message."""
        LOG.debug('Got router deleted notification for %s', routers)
        self.removed_routers.update(routers)

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug('Got routers updated notification :%s', routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            self.updated_routers.update(routers)

    def router_removed_from_agent(self, context, payload):
        LOG.debug('Got router removed from agent :%r', payload)
        self.removed_routers.add(payload['router_id'])

    def router_added_to_agent(self, context, payload):
        LOG.debug('Got router added to agent :%r', payload)
        self.routers_updated(context, payload)

    # Routing service helper public methods

    def process_service(self, device_ids=None, removed_devices_info=None):
        try:
            LOG.debug("Routing service processing started")
            resources = {}
            routers = []
            removed_routers = []
            all_routers_flag = False
            if self.fullsync:
                LOG.debug("FullSync flag is on. Starting fullsync")
                # Setting all_routers_flag and clear the global full_sync flag
                all_routers_flag = True
                self.fullsync = False
                self.updated_routers.clear()
                self.removed_routers.clear()
                self.sync_devices.clear()
                routers = self._fetch_router_info(all_routers=True)
            else:
                if self.updated_routers:
                    router_ids = list(self.updated_routers)
                    LOG.debug("Updated routers:%s", router_ids)
                    self.updated_routers.clear()
                    routers = self._fetch_router_info(router_ids=router_ids)
                if device_ids:
                    LOG.debug("Adding new devices:%s", device_ids)
                    self.sync_devices = set(device_ids) | self.sync_devices
                if self.sync_devices:
                    sync_devices_list = list(self.sync_devices)
                    LOG.debug("Fetching routers on:%s", sync_devices_list)
                    routers.extend(self._fetch_router_info(
                        device_ids=sync_devices_list))
                    self.sync_devices.clear()
                if removed_devices_info:
                    if removed_devices_info.get('deconfigure'):
                        ids = self._get_router_ids_from_removed_devices_info(
                            removed_devices_info)
                        self.removed_routers = self.removed_routers | set(ids)
                if self.removed_routers:
                    removed_routers_ids = list(self.removed_routers)
                    LOG.debug("Removed routers:%s", removed_routers_ids)
                    for r in removed_routers_ids:
                        if r in self.router_info:
                            removed_routers.append(self.router_info[r].router)

            # Sort on hosting device
            if routers:
                resources['routers'] = routers
            if removed_routers:
                resources['removed_routers'] = removed_routers
            hosting_devices = self._sort_resources_per_hosting_device(
                resources)

            # Dispatch process_services() for each hosting device
            pool = eventlet.GreenPool()
            for device_id, resources in hosting_devices.items():
                routers = resources.get('routers')
                removed_routers = resources.get('removed_routers')
                pool.spawn_n(self._process_routers, routers, removed_routers,
                             device_id, all_routers=all_routers_flag)
            pool.waitall()
            if removed_devices_info:
                for hd_id in removed_devices_info['hosting_data']:
                    self._drivermgr.remove_driver_for_hosting_device(hd_id)
            LOG.debug("Routing service processing successfully completed")
        except Exception:
            LOG.exception(_LE("Failed processing routers"))
            self.fullsync = True

    def collect_state(self, configurations):
        """Collect state from this helper.

        A set of attributes which summarizes the state of the routers and
        configurations managed by this config agent.
        :param configurations: dict of configuration values
        :return dict of updated configuration values
        """
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        num_hd_routers = collections.defaultdict(int)
        for ri in router_infos:
            ex_gw_port = ri.router.get('gw_port')
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(
                l3_constants.INTERFACE_KEY, []))
            num_floating_ips += len(ri.router.get(
                l3_constants.FLOATINGIP_KEY, []))
            hd = ri.router['hosting_device']
            if hd:
                num_hd_routers[hd['id']] += 1
        routers_per_hd = dict((hd_id, {'routers': num})
                              for hd_id, num in num_hd_routers.items())
        non_responding = self._dev_status.get_backlogged_hosting_devices()
        configurations['total routers'] = num_routers
        configurations['total ex_gw_ports'] = num_ex_gw_ports
        configurations['total interfaces'] = num_interfaces
        configurations['total floating_ips'] = num_floating_ips
        configurations['hosting_devices'] = routers_per_hd
        configurations['non_responding_hosting_devices'] = non_responding
        return configurations

    # Routing service helper internal methods

    def _fetch_router_info(self, router_ids=None, device_ids=None,
                           all_routers=False):
        """Fetch router dict from the routing plugin.

        :param router_ids: List of router_ids of routers to fetch
        :param device_ids: List of device_ids whose routers to fetch
        :param all_routers:  If True fetch all the routers for this agent.
        :return: List of router dicts of format:
                 [ {router_dict1}, {router_dict2},.....]
        """
        try:
            if all_routers:
                return self.plugin_rpc.get_routers(self.context)
            if router_ids:
                return self.plugin_rpc.get_routers(self.context,
                                                   router_ids=router_ids)
            if device_ids:
                return self.plugin_rpc.get_routers(self.context,
                                                   hd_ids=device_ids)
        except oslo_messaging.MessagingException:
            LOG.exception(_LE("RPC Error in fetching routers from plugin"))
            self.fullsync = True

    @staticmethod
    def _get_router_ids_from_removed_devices_info(removed_devices_info):
        """Extract router_ids from the removed devices info dict.

        :param removed_devices_info: Dict of removed devices and their
               associated resources.
        Format:
                {
                  'hosting_data': {'hd_id1': {'routers': [id1, id2, ...]},
                                   'hd_id2': {'routers': [id3, id4, ...]},
                                   ...
                                  },
                  'deconfigure': True/False
                }
        :return removed_router_ids: List of removed router ids
        """
        removed_router_ids = []
        for hd_id, resources in removed_devices_info['hosting_data'].items():
            removed_router_ids += resources.get('routers', [])
        return removed_router_ids

    @staticmethod
    def _sort_resources_per_hosting_device(resources):
        """This function will sort the resources on hosting device.

        The sorting on hosting device is done by looking up the
        `hosting_device` attribute of the resource, and its `id`.

        :param resources: a dict with key of resource name
        :return dict sorted on the hosting device of input resource. Format:
        hosting_devices = {
                            'hd_id1' : {'routers':[routers],
                                        'removed_routers':[routers], .... }
                            'hd_id2' : {'routers':[routers], .. }
                            .......
                            }
        """
        hosting_devices = {}
        for key in resources.keys():
            for r in resources.get(key) or []:
                hd_id = r['hosting_device']['id']
                hosting_devices.setdefault(hd_id, {})
                hosting_devices[hd_id].setdefault(key, []).append(r)
        return hosting_devices

    def _process_routers(self, routers, removed_routers,
                         device_id=None, all_routers=False):
        """Process the set of routers.

        Iterating on the set of routers received and comparing it with the
        set of routers already in the routing service helper, new routers
        which are added are identified. Before processing check the
        reachability (via ping) of hosting device where the router is hosted.
        If device is not reachable it is backlogged.

        For routers which are only updated, call `_process_router()` on them.

        When all_routers is set to True (because of a full sync),
        this will result in the detection and deletion of routers which
        have been removed.

        Whether the router can only be assigned to a particular hosting device
        is decided and enforced by the plugin. No checks are done here.

        :param routers: The set of routers to be processed
        :param removed_routers: the set of routers which where removed
        :param device_id: Id of the hosting device
        :param all_routers: Flag for specifying a partial list of routers
        :return: None
        """
        try:
            if all_routers:
                prev_router_ids = set(self.router_info)
            else:
                prev_router_ids = set(self.router_info) & set(
                    [router['id'] for router in routers])
            cur_router_ids = set()
            for r in routers:
                try:
                    if not r['admin_state_up']:
                        continue
                    cur_router_ids.add(r['id'])
                    hd = r['hosting_device']
                    if not self._dev_status.is_hosting_device_reachable(hd):
                        LOG.info(_LI("Router: %(id)s is on an unreachable "
                                   "hosting device. "), {'id': r['id']})
                        continue
                    if r['id'] not in self.router_info:
                        self._router_added(r['id'], r)
                    ri = self.router_info[r['id']]
                    ri.router = r
                    self._process_router(ri)
                except KeyError as e:
                    LOG.exception(_LE("Key Error, missing key: %s"), e)
                    self.updated_routers.add(r['id'])
                    continue
                except cfg_exceptions.DriverException as e:
                    LOG.exception(_LE("Driver Exception on router:%(id)s. "
                                    "Error is %(e)s"), {'id': r['id'], 'e': e})
                    self.updated_routers.update(r['id'])
                    continue
            # identify and remove routers that no longer exist
            for router_id in prev_router_ids - cur_router_ids:
                self._router_removed(router_id)
            if removed_routers:
                for router in removed_routers:
                    self._router_removed(router['id'])
        except Exception:
            LOG.exception(_LE("Exception in processing routers on device:%s"),
                          device_id)
            self.sync_devices.add(device_id)

    def _process_router(self, ri):
        """Process a router, apply latest configuration and update router_info.

        Get the router dict from  RouterInfo and proceed to detect changes
        from the last known state. When new ports or deleted ports are
        detected, `internal_network_added()` or `internal_networks_removed()`
        are called accordingly. Similarly changes in ex_gw_port causes
         `external_gateway_added()` or `external_gateway_removed()` calls.
        Next, floating_ips and routes are processed. Also, latest state is
        stored in ri.internal_ports and ri.ex_gw_port for future comparisons.

        :param ri : RouterInfo object of the router being processed.
        :return:None
        :raises: neutron.plugins.cisco.cfg_agent.cfg_exceptions.DriverException
        if the configuration operation fails.
        """
        try:
            ex_gw_port = ri.router.get('gw_port')
            ri.ha_info = ri.router.get('ha_info', None)
            internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
            existing_port_ids = set([p['id'] for p in ri.internal_ports])
            current_port_ids = set([p['id'] for p in internal_ports
                                    if p['admin_state_up']])
            new_ports = [p for p in internal_ports
                         if
                         p['id'] in (current_port_ids - existing_port_ids)]
            old_ports = [p for p in ri.internal_ports
                         if p['id'] not in current_port_ids]

            for p in new_ports:
                self._set_subnet_info(p)
                self._internal_network_added(ri, p, ex_gw_port)
                ri.internal_ports.append(p)

            for p in old_ports:
                self._internal_network_removed(ri, p, ri.ex_gw_port)
                ri.internal_ports.remove(p)

            if ex_gw_port and not ri.ex_gw_port:
                self._set_subnet_info(ex_gw_port)
                self._external_gateway_added(ri, ex_gw_port)
            elif not ex_gw_port and ri.ex_gw_port:
                self._external_gateway_removed(ri, ri.ex_gw_port)

            if ex_gw_port:
                self._process_router_floating_ips(ri, ex_gw_port)

            ri.ex_gw_port = ex_gw_port
            self._routes_updated(ri)
        except cfg_exceptions.DriverException as e:
            with excutils.save_and_reraise_exception():
                self.updated_routers.update(ri.router_id)
                LOG.error(e)

    def _process_router_floating_ips(self, ri, ex_gw_port):
        """Process a router's floating ips.

        Compare current floatingips (in ri.floating_ips) with the router's
        updated floating ips (in ri.router.floating_ips) and detect
        flaoting_ips which were added or removed. Notify driver of
        the change via `floating_ip_added()` or `floating_ip_removed()`.

        :param ri:  RouterInfo object of the router being processed.
        :param ex_gw_port: Port dict of the external gateway port.
        :return: None
        :raises: neutron.plugins.cisco.cfg_agent.cfg_exceptions.DriverException
        if the configuration operation fails.
        """

        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        existing_floating_ip_ids = set(
            [fip['id'] for fip in ri.floating_ips])
        cur_floating_ip_ids = set([fip['id'] for fip in floating_ips])

        id_to_fip_map = {}

        for fip in floating_ips:
            if fip['port_id']:
                # store to see if floatingip was remapped
                id_to_fip_map[fip['id']] = fip
                if fip['id'] not in existing_floating_ip_ids:
                    ri.floating_ips.append(fip)
                    self._floating_ip_added(ri, ex_gw_port,
                                            fip['floating_ip_address'],
                                            fip['fixed_ip_address'])

        floating_ip_ids_to_remove = (existing_floating_ip_ids -
                                     cur_floating_ip_ids)
        for fip in ri.floating_ips:
            if fip['id'] in floating_ip_ids_to_remove:
                ri.floating_ips.remove(fip)
                self._floating_ip_removed(ri, ri.ex_gw_port,
                                          fip['floating_ip_address'],
                                          fip['fixed_ip_address'])
            else:
                # handle remapping of a floating IP
                new_fip = id_to_fip_map[fip['id']]
                new_fixed_ip = new_fip['fixed_ip_address']
                existing_fixed_ip = fip['fixed_ip_address']
                if (new_fixed_ip and existing_fixed_ip and
                        new_fixed_ip != existing_fixed_ip):
                    floating_ip = fip['floating_ip_address']
                    self._floating_ip_removed(ri, ri.ex_gw_port,
                                              floating_ip,
                                              existing_fixed_ip)
                    self._floating_ip_added(ri, ri.ex_gw_port,
                                            floating_ip, new_fixed_ip)
                    ri.floating_ips.remove(fip)
                    ri.floating_ips.append(new_fip)

    def _router_added(self, router_id, router):
        """Operations when a router is added.

        Create a new RouterInfo object for this router and add it to the
        service helpers router_info dictionary.  Then `router_added()` is
        called on the device driver.

        :param router_id: id of the router
        :param router: router dict
        :return: None
        """
        ri = RouterInfo(router_id, router)
        driver = self._drivermgr.set_driver(router)
        driver.router_added(ri)
        self.router_info[router_id] = ri

    def _router_removed(self, router_id, deconfigure=True):
        """Operations when a router is removed.

        Get the RouterInfo object corresponding to the router in the service
        helpers's router_info dict. If deconfigure is set to True,
        remove this router's configuration from the hosting device.
        :param router_id: id of the router
        :param deconfigure: if True, the router's configuration is deleted from
        the hosting device.
        :return: None
        """
        ri = self.router_info.get(router_id)
        if ri is None:
            LOG.warning(_LW("Info for router %s was not found. "
                       "Skipping router removal"), router_id)
            return
        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        try:
            if deconfigure:
                self._process_router(ri)
                driver = self._drivermgr.get_driver(router_id)
                driver.router_removed(ri, deconfigure)
                self._drivermgr.remove_driver(router_id)
            del self.router_info[router_id]
            self.removed_routers.discard(router_id)
        except cfg_exceptions.DriverException:
            LOG.warning(_LW("Router remove for router_id: %s was incomplete. "
                       "Adding the router to removed_routers list"), router_id)
            self.removed_routers.add(router_id)
            # remove this router from updated_routers if it is there. It might
            # end up there too if exception was thrown earlier inside
            # `_process_router()`
            self.updated_routers.discard(router_id)

    def _internal_network_added(self, ri, port, ex_gw_port):
        driver = self._drivermgr.get_driver(ri.id)
        driver.internal_network_added(ri, port)
        if ri.snat_enabled and ex_gw_port:
            driver.enable_internal_network_NAT(ri, port, ex_gw_port)

    def _internal_network_removed(self, ri, port, ex_gw_port):
        driver = self._drivermgr.get_driver(ri.id)
        driver.internal_network_removed(ri, port)
        if ri.snat_enabled and ex_gw_port:
            driver.disable_internal_network_NAT(ri, port, ex_gw_port)

    def _external_gateway_added(self, ri, ex_gw_port):
        driver = self._drivermgr.get_driver(ri.id)
        driver.external_gateway_added(ri, ex_gw_port)
        if ri.snat_enabled and ri.internal_ports:
            for port in ri.internal_ports:
                driver.enable_internal_network_NAT(ri, port, ex_gw_port)

    def _external_gateway_removed(self, ri, ex_gw_port):
        driver = self._drivermgr.get_driver(ri.id)
        if ri.snat_enabled and ri.internal_ports:
            for port in ri.internal_ports:
                driver.disable_internal_network_NAT(ri, port, ex_gw_port)
        driver.external_gateway_removed(ri, ex_gw_port)

    def _floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        driver = self._drivermgr.get_driver(ri.id)
        driver.floating_ip_added(ri, ex_gw_port, floating_ip, fixed_ip)

    def _floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        driver = self._drivermgr.get_driver(ri.id)
        driver.floating_ip_removed(ri, ex_gw_port, floating_ip, fixed_ip)

    def _routes_updated(self, ri):
        """Update the state of routes in the router.

        Compares the current routes with the (configured) existing routes
        and detect what was removed or added. Then configure the
        logical router in the hosting device accordingly.
        :param ri: RouterInfo corresponding to the router.
        :return: None
        :raises: neutron.plugins.cisco.cfg_agent.cfg_exceptions.DriverException
        if the configuration operation fails.
        """
        new_routes = ri.router['routes']
        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug("Added route entry is '%s'", route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            driver = self._drivermgr.get_driver(ri.id)
            driver.routes_updated(ri, 'replace', route)

        for route in removes:
            LOG.debug("Removed route entry is '%s'", route)
            driver = self._drivermgr.get_driver(ri.id)
            driver.routes_updated(ri, 'delete', route)
        ri.routes = new_routes

    @staticmethod
    def _set_subnet_info(port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_LE("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)
