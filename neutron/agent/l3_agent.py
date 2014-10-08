# Copyright 2012 VMware, Inc.  All rights reserved.
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
#

import sys

import datetime
import eventlet
eventlet.monkey_patch()

import netaddr
import os
from oslo.config import cfg
from oslo import messaging
import Queue

from neutron.agent.common import config
from neutron.agent import l3_ha_agent
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import ra
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import ipv6_utils
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as common_utils
from neutron import context
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common.gettextutils import _LW
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common import processutils
from neutron.openstack.common import service
from neutron.openstack.common import timeutils
from neutron import service as neutron_service
from neutron.services.firewall.agents.l3reference import firewall_l3_agent

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
SNAT_INT_DEV_PREFIX = 'sg-'
FIP_NS_PREFIX = 'fip-'
SNAT_NS_PREFIX = 'snat-'
FIP_2_ROUTER_DEV_PREFIX = 'fpr-'
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'
FIP_EXT_DEV_PREFIX = 'fg-'
FIP_LL_SUBNET = '169.254.30.0/23'
# Route Table index for FIPs
FIP_RT_TBL = 16
# Rule priority range for FIPs
FIP_PR_START = 32768
FIP_PR_END = FIP_PR_START + 40000
RPC_LOOP_INTERVAL = 1
FLOATING_IP_CIDR_SUFFIX = '/32'
# Lower value is higher priority
PRIORITY_RPC = 0
PRIORITY_SYNC_ROUTERS_TASK = 1
DELETE_ROUTER = 1


class L3PluginApi(n_rpc.RpcProxy):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.
        1.1 - Floating IP operational status updates
        1.2 - DVR support: new L3 plugin methods added.
              - get_ports_by_subnet
              - get_agent_gateway_port
              Needed by the agent when operating in DVR/DVR_SNAT mode
        1.3 - Get the list of activated services

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(L3PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        return self.call(context,
                         self.make_msg('sync_routers', host=self.host,
                                       router_ids=router_ids))

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        @raise n_rpc.RemoteError: with TooManyExternalNetworks as
                                  exc_type if there are more than one
                                  external network
        """
        return self.call(context,
                         self.make_msg('get_external_network_id',
                                       host=self.host))

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Call the plugin update floating IPs's operational status."""
        return self.call(context,
                         self.make_msg('update_floatingip_statuses',
                                       router_id=router_id,
                                       fip_statuses=fip_statuses),
                         version='1.1')

    def get_ports_by_subnet(self, context, subnet_id):
        """Retrieve ports by subnet id."""
        return self.call(context,
                         self.make_msg('get_ports_by_subnet', host=self.host,
                                       subnet_id=subnet_id),
                         topic=self.topic,
                         version='1.2')

    def get_agent_gateway_port(self, context, fip_net):
        """Get or create an agent_gateway_port."""
        return self.call(context,
                         self.make_msg('get_agent_gateway_port',
                                       network_id=fip_net, host=self.host),
                         topic=self.topic,
                         version='1.2')

    def get_service_plugin_list(self, context):
        """Make a call to get the list of activated services."""
        return self.call(context,
                         self.make_msg('get_service_plugin_list'),
                         topic=self.topic,
                         version='1.3')


class LinkLocalAddressPair(netaddr.IPNetwork):
    def __init__(self, addr):
        super(LinkLocalAddressPair, self).__init__(addr)

    def get_pair(self):
        """Builds an address pair from the first and last addresses. """
        return (netaddr.IPNetwork("%s/%s" % (self.network, self.prefixlen)),
                netaddr.IPNetwork("%s/%s" % (self.broadcast, self.prefixlen)))


class LinkLocalAllocator(object):
    """Manages allocation of link local IP addresses.

    These link local addresses are used for routing inside the fip namespaces.
    The associations need to persist across agent restarts to maintain
    consistency.  Without this, there is disruption in network connectivity
    as the agent rewires the connections with the new IP address assocations.

    Persisting these in the database is unnecessary and would degrade
    performance.
    """
    def __init__(self, state_file, subnet):
        """Read the file with previous allocations recorded.

        See the note in the allocate method for more detail.
        """
        self.state_file = state_file
        subnet = netaddr.IPNetwork(subnet)

        self.allocations = {}

        self.remembered = {}
        for line in self._read():
            key, cidr = line.strip().split(',')
            self.remembered[key] = LinkLocalAddressPair(cidr)

        self.pool = set(LinkLocalAddressPair(s) for s in subnet.subnet(31))
        self.pool.difference_update(self.remembered.values())

    def allocate(self, key):
        """Try to allocate a link local address pair.

        I expect this to work in all cases because I expect the pool size to be
        large enough for any situation.  Nonetheless, there is some defensive
        programming in here.

        Since the allocations are persisted, there is the chance to leak
        allocations which should have been released but were not.  This leak
        could eventually exhaust the pool.

        So, if a new allocation is needed, the code first checks to see if
        there are any remembered allocations for the key.  If not, it checks
        the free pool.  If the free pool is empty then it dumps the remembered
        allocations to free the pool.  This final desparate step will not
        happen often in practice.
        """
        if key in self.remembered:
            self.allocations[key] = self.remembered.pop(key)
            return self.allocations[key]

        if not self.pool:
            # Desparate times.  Try to get more in the pool.
            self.pool.update(self.remembered.values())
            self.remembered.clear()
            if not self.pool:
                # More than 256 routers on a compute node!
                raise RuntimeError(_("Cannot allocate link local address"))

        self.allocations[key] = self.pool.pop()
        self._write_allocations()
        return self.allocations[key]

    def release(self, key):
        self.pool.add(self.allocations.pop(key))
        self._write_allocations()

    def _write_allocations(self):
        current = ["%s,%s\n" % (k, v) for k, v in self.allocations.items()]
        remembered = ["%s,%s\n" % (k, v) for k, v in self.remembered.items()]
        current.extend(remembered)
        self._write(current)

    def _write(self, lines):
        with open(self.state_file, "w") as f:
            f.writelines(lines)

    def _read(self):
        if not os.path.exists(self.state_file):
            return []
        with open(self.state_file) as f:
            return f.readlines()


class RouterInfo(l3_ha_agent.RouterMixin):

    def __init__(self, router_id, root_helper, use_namespaces, router,
                 use_ipv6=False):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.snat_ports = []
        self.floating_ips = set()
        self.floating_ips_dict = {}
        self.root_helper = root_helper
        self.use_namespaces = use_namespaces
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.ns_name = NS_PREFIX + router_id if use_namespaces else None
        self.iptables_manager = iptables_manager.IptablesManager(
            root_helper=root_helper,
            use_ipv6=use_ipv6,
            namespace=self.ns_name)
        self.snat_iptables_manager = None
        self.routes = []
        # DVR Data
        # Linklocal subnet for router and floating IP namespace link
        self.rtr_fip_subnet = None
        self.dist_fip_count = 0

        super(RouterInfo, self).__init__()

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'

    def perform_snat_action(self, snat_callback, *args):
        # Process SNAT rules for attached subnets
        if self._snat_action:
            snat_callback(self, self._router.get('gw_port'),
                          *args, action=self._snat_action)
        self._snat_action = None


class RouterUpdate(object):
    """Encapsulates a router update

    An instance of this object carries the information necessary to prioritize
    and process a request to update a router.
    """
    def __init__(self, router_id, priority,
                 action=None, router=None, timestamp=None):
        self.priority = priority
        self.timestamp = timestamp
        if not timestamp:
            self.timestamp = timeutils.utcnow()
        self.id = router_id
        self.action = action
        self.router = router

    def __lt__(self, other):
        """Implements priority among updates

        Lower numerical priority always gets precedence.  When comparing two
        updates of the same priority then the one with the earlier timestamp
        gets procedence.  In the unlikely event that the timestamps are also
        equal it falls back to a simple comparison of ids meaning the
        precedence is essentially random.
        """
        if self.priority != other.priority:
            return self.priority < other.priority
        if self.timestamp != other.timestamp:
            return self.timestamp < other.timestamp
        return self.id < other.id


class ExclusiveRouterProcessor(object):
    """Manager for access to a router for processing

    This class controls access to a router in a non-blocking way.  The first
    instance to be created for a given router_id is granted exclusive access to
    the router.

    Other instances may be created for the same router_id while the first
    instance has exclusive access.  If that happens then it doesn't block and
    wait for access.  Instead, it signals to the master instance that an update
    came in with the timestamp.

    This way, a thread will not block to wait for access to a router.  Instead
    it effectively signals to the thread that is working on the router that
    something has changed since it started working on it.  That thread will
    simply finish its current iteration and then repeat.

    This class keeps track of the last time that a router data was fetched and
    processed.  The timestamp that it keeps must be before when the data used
    to process the router last was fetched from the database.  But, as close as
    possible.  The timestamp should not be recorded, however, until the router
    has been processed using the fetch data.
    """
    _masters = {}
    _router_timestamps = {}

    def __init__(self, router_id):
        self._router_id = router_id

        if router_id not in self._masters:
            self._masters[router_id] = self
            self._queue = []

        self._master = self._masters[router_id]

    def _i_am_master(self):
        return self == self._master

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._i_am_master():
            del self._masters[self._router_id]

    def _get_router_data_timestamp(self):
        return self._router_timestamps.get(self._router_id,
                                           datetime.datetime.min)

    def fetched_and_processed(self, timestamp):
        """Records the data timestamp after it is used to update the router"""
        new_timestamp = max(timestamp, self._get_router_data_timestamp())
        self._router_timestamps[self._router_id] = new_timestamp

    def queue_update(self, update):
        """Queues an update from a worker

        This is the queue used to keep new updates that come in while a router
        is being processed.  These updates have already bubbled to the front of
        the RouterProcessingQueue.
        """
        self._master._queue.append(update)

    def updates(self):
        """Processes the router until updates stop coming

        Only the master instance will process the router.  However, updates may
        come in from other workers while it is in progress.  This method loops
        until they stop coming.
        """
        if self._i_am_master():
            while self._queue:
                # Remove the update from the queue even if it is old.
                update = self._queue.pop(0)
                # Process the update only if it is fresh.
                if self._get_router_data_timestamp() < update.timestamp:
                    yield update


class RouterProcessingQueue(object):
    """Manager of the queue of routers to process."""
    def __init__(self):
        self._queue = Queue.PriorityQueue()

    def add(self, update):
        self._queue.put(update)

    def each_update_to_next_router(self):
        """Grabs the next router from the queue and processes

        This method uses a for loop to process the router repeatedly until
        updates stop bubbling to the front of the queue.
        """
        next_update = self._queue.get()

        with ExclusiveRouterProcessor(next_update.id) as rp:
            # Queue the update whether this worker is the master or not.
            rp.queue_update(next_update)

            # Here, if the current worker is not the master, the call to
            # rp.updates() will not yield and so this will essentially be a
            # noop.
            for update in rp.updates():
                yield (rp, update)


class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback,
                 l3_ha_agent.AgentMixin,
                 manager.Manager):
    """Manager for L3NatAgent

        API version history:
        1.0 initial Version
        1.1 changed the type of the routers parameter
            to the routers_updated method.
            It was previously a list of routers in dict format.
            It is now a list of router IDs only.
            Per rpc versioning rules,  it is backwards compatible.
        1.2 - DVR support: new L3 agent methods added.
              - add_arp_entry
              - del_arp_entry
              Needed by the L3 service when dealing with DVR
    """
    RPC_API_VERSION = '1.2'

    OPTS = [
        cfg.StrOpt('agent_mode', default='legacy',
                   help=_("The working mode for the agent. Allowed modes are: "
                          "'legacy' - this preserves the existing behavior "
                          "where the L3 agent is deployed on a centralized "
                          "networking node to provide L3 services like DNAT, "
                          "and SNAT. Use this mode if you do not want to "
                          "adopt DVR. 'dvr' - this mode enables DVR "
                          "functionality and must be used for an L3 agent "
                          "that runs on a compute host. 'dvr_snat' - this "
                          "enables centralized SNAT support in conjunction "
                          "with DVR.  This mode must be used for an L3 agent "
                          "running on a centralized node (or in single-host "
                          "deployments, e.g. devstack)")),
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help=_("Name of bridge used for external network "
                          "traffic.")),
        cfg.IntOpt('metadata_port',
                   default=9697,
                   help=_("TCP Port used by Neutron metadata namespace "
                          "proxy.")),
        cfg.IntOpt('send_arp_for_ha',
                   default=3,
                   help=_("Send this many gratuitous ARPs for HA setup, if "
                          "less than or equal to 0, the feature is disabled")),
        cfg.StrOpt('router_id', default='',
                   help=_("If namespaces is disabled, the l3 agent can only"
                          " configure a router that has the matching router "
                          "ID.")),
        cfg.BoolOpt('handle_internal_only_routers',
                    default=True,
                    help=_("Agent should implement routers with no gateway")),
        cfg.StrOpt('gateway_external_network_id', default='',
                   help=_("UUID of external network for routers implemented "
                          "by the agents.")),
        cfg.BoolOpt('enable_metadata_proxy', default=True,
                    help=_("Allow running metadata proxy.")),
        cfg.BoolOpt('router_delete_namespaces', default=False,
                    help=_("Delete namespace after removing a router.")),
        cfg.StrOpt('metadata_proxy_socket',
                   default='$state_path/metadata_proxy',
                   help=_('Location of Metadata Proxy UNIX domain '
                          'socket')),
    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.router_info = {}

        self._check_config_params()

        try:
            self.driver = importutils.import_object(
                self.conf.interface_driver,
                self.conf
            )
        except Exception:
            msg = _("Error importing interface driver "
                    "'%s'") % self.conf.interface_driver
            LOG.error(msg)
            raise SystemExit(1)

        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, host)
        self.fullsync = True
        self.sync_progress = False

        # Get the list of service plugins from Neutron Server
        # This is the first place where we contact neutron-server on startup
        # so retry in case its not ready to respond.
        retry_count = 5
        while True:
            retry_count = retry_count - 1
            try:
                self.neutron_service_plugins = (
                    self.plugin_rpc.get_service_plugin_list(self.context))
            except n_rpc.RemoteError as e:
                with excutils.save_and_reraise_exception() as ctx:
                    ctx.reraise = False
                    LOG.warning(_LW('l3-agent cannot check service plugins '
                                    'enabled at the neutron server when '
                                    'startup due to RPC error. It happens '
                                    'when the server does not support this '
                                    'RPC API. If the error is '
                                    'UnsupportedVersion you can ignore this '
                                    'warning. Detail message: %s'), e)
                self.neutron_service_plugins = None
            except messaging.MessagingTimeout as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if retry_count > 0:
                        ctx.reraise = False
                        LOG.warning(_LW('l3-agent cannot check service '
                                        'plugins enabled on the neutron '
                                        'server. Retrying. '
                                        'Detail message: %s'), e)
                        continue
            break

        self._clean_stale_namespaces = self.conf.use_namespaces

        # dvr data
        self.agent_gateway_port = None
        self.agent_fip_count = 0
        self.local_subnets = LinkLocalAllocator(
            os.path.join(self.conf.state_path, 'fip-linklocal-networks'),
            FIP_LL_SUBNET)
        self.fip_priorities = set(range(FIP_PR_START, FIP_PR_END))

        self._queue = RouterProcessingQueue()
        super(L3NATAgent, self).__init__(conf=self.conf)

        self.target_ex_net_id = None
        self.use_ipv6 = ipv6_utils.is_enabled()

    def _check_config_params(self):
        """Check items in configuration files.

        Check for required and invalid configuration items.
        The actual values are not verified for correctness.
        """
        if not self.conf.interface_driver:
            msg = _('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(1)

        if not self.conf.use_namespaces and not self.conf.router_id:
            msg = _('Router id is required if not using namespaces.')
            LOG.error(msg)
            raise SystemExit(1)

    def _list_namespaces(self):
        """Get a set of all router namespaces on host

        The argument routers is the list of routers that are recorded in
        the database as being hosted on this node.
        """
        try:
            root_ip = ip_lib.IPWrapper(self.root_helper)

            host_namespaces = root_ip.get_namespaces(self.root_helper)
            return set(ns for ns in host_namespaces
                       if (ns.startswith(NS_PREFIX)
                           or ns.startswith(SNAT_NS_PREFIX)))
        except RuntimeError:
            LOG.exception(_('RuntimeError in obtaining router list '
                            'for namespace cleanup.'))
            return set()

    def _cleanup_namespaces(self, router_namespaces, router_ids):
        """Destroy stale router namespaces on host when L3 agent restarts

            This routine is called when self._clean_stale_namespaces is True.

        The argument router_namespaces is the list of all routers namespaces
        The argument router_ids is the list of ids for known routers.
        """
        ns_to_ignore = set(NS_PREFIX + id for id in router_ids)
        ns_to_ignore.update(SNAT_NS_PREFIX + id for id in router_ids)
        ns_to_destroy = router_namespaces - ns_to_ignore
        self._destroy_stale_router_namespaces(ns_to_destroy)

    def _destroy_stale_router_namespaces(self, router_namespaces):
        """Destroys the stale router namespaces

        The argumenet router_namespaces is a list of stale router namespaces

        As some stale router namespaces may not be able to be deleted, only
        one attempt will be made to delete them.
        """
        for ns in router_namespaces:
            ra.disable_ipv6_ra(ns[len(NS_PREFIX):], ns, self.root_helper)
            try:
                self._destroy_namespace(ns)
            except RuntimeError:
                LOG.exception(_('Failed to destroy stale router namespace '
                                '%s'), ns)
        self._clean_stale_namespaces = False

    def _destroy_namespace(self, ns):
        if ns.startswith(NS_PREFIX):
            if self.conf.enable_metadata_proxy:
                self._destroy_metadata_proxy(ns[len(NS_PREFIX):], ns)
            self._destroy_router_namespace(ns)
        elif ns.startswith(FIP_NS_PREFIX):
            self._destroy_fip_namespace(ns)
        elif ns.startswith(SNAT_NS_PREFIX):
            self._destroy_snat_namespace(ns)

    def _delete_namespace(self, ns_ip, ns):
        try:
            ns_ip.netns.delete(ns)
        except RuntimeError:
            msg = _('Failed trying to delete namespace: %s') % ns
            LOG.exception(msg)

    def _destroy_snat_namespace(self, ns):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=ns)
        # delete internal interfaces
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(SNAT_INT_DEV_PREFIX):
                LOG.debug('Unplugging DVR device %s', d.name)
                self.driver.unplug(d.name, namespace=ns,
                                   prefix=SNAT_INT_DEV_PREFIX)

        # TODO(mrsmith): delete ext-gw-port
        LOG.debug('DVR: destroy snat ns: %s', ns)
        if self.conf.router_delete_namespaces:
            self._delete_namespace(ns_ip, ns)

    def _destroy_fip_namespace(self, ns):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=ns)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(FIP_2_ROUTER_DEV_PREFIX):
                # internal link between IRs and FIP NS
                ns_ip.del_veth(d.name)
            elif d.name.startswith(FIP_EXT_DEV_PREFIX):
                # single port from FIP NS to br-ext
                # TODO(carl) Where does the port get deleted?
                LOG.debug('DVR: unplug: %s', d.name)
                self.driver.unplug(d.name,
                                   bridge=self.conf.external_network_bridge,
                                   namespace=ns,
                                   prefix=FIP_EXT_DEV_PREFIX)
        LOG.debug('DVR: destroy fip ns: %s', ns)
        # TODO(mrsmith): add LOG warn if fip count != 0
        if self.conf.router_delete_namespaces:
            self._delete_namespace(ns_ip, ns)
        self.agent_gateway_port = None

    def _destroy_router_namespace(self, ns):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=ns)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(INTERNAL_DEV_PREFIX):
                # device is on default bridge
                self.driver.unplug(d.name, namespace=ns,
                                   prefix=INTERNAL_DEV_PREFIX)
            elif d.name.startswith(ROUTER_2_FIP_DEV_PREFIX):
                ns_ip.del_veth(d.name)
            elif d.name.startswith(EXTERNAL_DEV_PREFIX):
                self.driver.unplug(d.name,
                                   bridge=self.conf.external_network_bridge,
                                   namespace=ns,
                                   prefix=EXTERNAL_DEV_PREFIX)

        if self.conf.router_delete_namespaces:
            self._delete_namespace(ns_ip, ns)

    def _create_namespace(self, name):
        ip_wrapper_root = ip_lib.IPWrapper(self.root_helper)
        ip_wrapper = ip_wrapper_root.ensure_namespace(name)
        ip_wrapper.netns.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        if self.use_ipv6:
            ip_wrapper.netns.execute(['sysctl', '-w',
                                      'net.ipv6.conf.all.forwarding=1'])

    def _create_router_namespace(self, ri):
        self._create_namespace(ri.ns_name)

    def _fetch_external_net_id(self, force=False):
        """Find UUID of single external network for this agent."""
        if self.conf.gateway_external_network_id:
            return self.conf.gateway_external_network_id

        # L3 agent doesn't use external_network_bridge to handle external
        # networks, so bridge_mappings with provider networks will be used
        # and the L3 agent is able to handle any external networks.
        if not self.conf.external_network_bridge:
            return

        if not force and self.target_ex_net_id:
            return self.target_ex_net_id

        try:
            self.target_ex_net_id = self.plugin_rpc.get_external_network_id(
                self.context)
            return self.target_ex_net_id
        except n_rpc.RemoteError as e:
            with excutils.save_and_reraise_exception() as ctx:
                if e.exc_type == 'TooManyExternalNetworks':
                    ctx.reraise = False
                    msg = _(
                        "The 'gateway_external_network_id' option must be "
                        "configured for this agent as Neutron has more than "
                        "one external network.")
                    raise Exception(msg)

    def _router_added(self, router_id, router):
        ri = RouterInfo(router_id, self.root_helper,
                        self.conf.use_namespaces, router,
                        use_ipv6=self.use_ipv6)
        self.router_info[router_id] = ri
        if self.conf.use_namespaces:
            self._create_router_namespace(ri)
        for c, r in self.metadata_filter_rules():
            ri.iptables_manager.ipv4['filter'].add_rule(c, r)
        for c, r in self.metadata_nat_rules():
            ri.iptables_manager.ipv4['nat'].add_rule(c, r)
        ri.iptables_manager.apply()
        self.process_router_add(ri)

        if ri.is_ha:
            self.process_ha_router_added(ri)

        if self.conf.enable_metadata_proxy:
            if ri.is_ha:
                self._add_keepalived_notifiers(ri)
            else:
                self._spawn_metadata_proxy(ri.router_id, ri.ns_name)

    def _router_removed(self, router_id):
        ri = self.router_info.get(router_id)
        if ri is None:
            LOG.warn(_("Info for router %s were not found. "
                       "Skipping router removal"), router_id)
            return

        if ri.is_ha:
            self.process_ha_router_removed(ri)

        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        self.process_router(ri)
        for c, r in self.metadata_filter_rules():
            ri.iptables_manager.ipv4['filter'].remove_rule(c, r)
        for c, r in self.metadata_nat_rules():
            ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
        ri.iptables_manager.apply()
        if self.conf.enable_metadata_proxy:
            self._destroy_metadata_proxy(ri.router_id, ri.ns_name)
        del self.router_info[router_id]
        self._destroy_router_namespace(ri.ns_name)

    def _get_metadata_proxy_callback(self, router_id):

        def callback(pid_file):
            metadata_proxy_socket = cfg.CONF.metadata_proxy_socket
            proxy_cmd = ['neutron-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         '--metadata_proxy_socket=%s' % metadata_proxy_socket,
                         '--router_id=%s' % router_id,
                         '--state_path=%s' % self.conf.state_path,
                         '--metadata_port=%s' % self.conf.metadata_port]
            proxy_cmd.extend(config.get_log_args(
                cfg.CONF, 'neutron-ns-metadata-proxy-%s.log' %
                router_id))
            return proxy_cmd

        return callback

    def _get_metadata_proxy_process_manager(self, router_id, ns_name):
        return external_process.ProcessManager(
            self.conf,
            router_id,
            self.root_helper,
            ns_name)

    def _spawn_metadata_proxy(self, router_id, ns_name):
        callback = self._get_metadata_proxy_callback(router_id)
        pm = self._get_metadata_proxy_process_manager(router_id, ns_name)
        pm.enable(callback)

    def _destroy_metadata_proxy(self, router_id, ns_name):
        pm = self._get_metadata_proxy_process_manager(router_id, ns_name)
        pm.disable()

    def _set_subnet_arp_info(self, ri, port):
        """Set ARP info retrieved from Plugin for existing ports."""
        if 'id' not in port['subnet'] or not ri.router['distributed']:
            return
        subnet_id = port['subnet']['id']
        subnet_ports = (
            self.plugin_rpc.get_ports_by_subnet(self.context,
                                                subnet_id))

        for p in subnet_ports:
            if (p['device_owner'] not in (
                l3_constants.DEVICE_OWNER_ROUTER_INTF,
                l3_constants.DEVICE_OWNER_DVR_INTERFACE)):
                for fixed_ip in p['fixed_ips']:
                    self._update_arp_entry(ri, fixed_ip['ip_address'],
                                           p['mac_address'],
                                           subnet_id, 'add')

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def _get_existing_devices(self, ri):
        ip_wrapper = ip_lib.IPWrapper(root_helper=self.root_helper,
                                      namespace=ri.ns_name)
        ip_devs = ip_wrapper.get_devices(exclude_loopback=True)
        return [ip_dev.name for ip_dev in ip_devs]

    @common_utils.exception_logger()
    def process_router(self, ri):
        # TODO(mrsmith) - we shouldn't need to check here
        if 'distributed' not in ri.router:
            ri.router['distributed'] = False
        ri.iptables_manager.defer_apply_on()
        ex_gw_port = self._get_ex_gw_port(ri)
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        snat_ports = ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]

        new_ipv6_port = False
        old_ipv6_port = False
        for p in new_ports:
            self._set_subnet_info(p)
            self.internal_network_added(ri, p)
            ri.internal_ports.append(p)
            self._set_subnet_arp_info(ri, p)
            if (not new_ipv6_port and
                    netaddr.IPNetwork(p['subnet']['cidr']).version == 6):
                new_ipv6_port = True

        for p in old_ports:
            self.internal_network_removed(ri, p)
            ri.internal_ports.remove(p)
            if (not old_ipv6_port and
                    netaddr.IPNetwork(p['subnet']['cidr']).version == 6):
                old_ipv6_port = True

        if new_ipv6_port or old_ipv6_port:
            ra.enable_ipv6_ra(ri.router_id,
                              ri.ns_name,
                              internal_ports,
                              self.get_internal_device_name,
                              self.root_helper)

        existing_devices = self._get_existing_devices(ri)
        current_internal_devs = set([n for n in existing_devices
                                     if n.startswith(INTERNAL_DEV_PREFIX)])
        current_port_devs = set([self.get_internal_device_name(id) for
                                 id in current_port_ids])
        stale_devs = current_internal_devs - current_port_devs
        for stale_dev in stale_devs:
            LOG.debug(_('Deleting stale internal router device: %s'),
                      stale_dev)
            self.driver.unplug(stale_dev,
                               namespace=ri.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

        # TODO(salv-orlando): RouterInfo would be a better place for
        # this logic too
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                         ri.ex_gw_port and ri.ex_gw_port['id'])

        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port:
            def _gateway_ports_equal(port1, port2):
                def _get_filtered_dict(d, ignore):
                    return dict((k, v) for k, v in d.iteritems()
                                if k not in ignore)

                keys_to_ignore = set(['binding:host_id'])
                port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
                port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
                return port1_filtered == port2_filtered

            self._set_subnet_info(ex_gw_port)
            if not ri.ex_gw_port:
                self.external_gateway_added(ri, ex_gw_port, interface_name)
            elif not _gateway_ports_equal(ex_gw_port, ri.ex_gw_port):
                self.external_gateway_updated(ri, ex_gw_port, interface_name)
        elif not ex_gw_port and ri.ex_gw_port:
            self.external_gateway_removed(ri, ri.ex_gw_port, interface_name)

        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX)
                      and dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug(_('Deleting stale external router device: %s'),
                      stale_dev)
            self.driver.unplug(stale_dev,
                               bridge=self.conf.external_network_bridge,
                               namespace=ri.ns_name,
                               prefix=EXTERNAL_DEV_PREFIX)

        # Process static routes for router
        self.routes_updated(ri)
        # Process SNAT rules for external gateway
        if (not ri.router['distributed'] or
            ex_gw_port and ri.router['gw_port_host'] == self.host):
            # Get IPv4 only internal CIDRs
            internal_cidrs = [p['ip_cidr'] for p in ri.internal_ports
                              if netaddr.IPNetwork(p['ip_cidr']).version == 4]
            ri.perform_snat_action(self._handle_router_snat_rules,
                                   internal_cidrs, interface_name)

        # Process SNAT/DNAT rules for floating IPs
        fip_statuses = {}
        try:
            if ex_gw_port:
                existing_floating_ips = ri.floating_ips
                self.process_router_floating_ip_nat_rules(ri)
                ri.iptables_manager.defer_apply_off()
                # Once NAT rules for floating IPs are safely in place
                # configure their addresses on the external gateway port
                fip_statuses = self.process_router_floating_ip_addresses(
                    ri, ex_gw_port)
        except Exception:
            # TODO(salv-orlando): Less broad catching
            # All floating IPs must be put in error state
            for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
                fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR

        if ex_gw_port:
            # Identify floating IPs which were disabled
            ri.floating_ips = set(fip_statuses.keys())
            for fip_id in existing_floating_ips - ri.floating_ips:
                fip_statuses[fip_id] = l3_constants.FLOATINGIP_STATUS_DOWN
            # Update floating IP status on the neutron server
            self.plugin_rpc.update_floatingip_statuses(
                self.context, ri.router_id, fip_statuses)

        # Update ex_gw_port and enable_snat on the router info cache
        ri.ex_gw_port = ex_gw_port
        ri.snat_ports = snat_ports
        ri.enable_snat = ri.router.get('enable_snat')

        if ri.is_ha:
            if ri.ha_port:
                ri.spawn_keepalived()
            else:
                ri.disable_keepalived()

    def _handle_router_snat_rules(self, ri, ex_gw_port, internal_cidrs,
                                  interface_name, action):
        # Remove all the rules
        # This is safe because if use_namespaces is set as False
        # then the agent can only configure one router, otherwise
        # each router's SNAT rules will be in their own namespace
        if not ri.router['distributed']:
            iptables_manager = ri.iptables_manager
        elif ri.snat_iptables_manager:
            iptables_manager = ri.snat_iptables_manager
        else:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        iptables_manager.ipv4['nat'].empty_chain('snat')

        if not ri.router['distributed']:
            # Add back the jump to float-snat
            iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        # And add them back if the action is add_rules
        if action == 'add_rules' and ex_gw_port:
            # ex_gw_port should not be None in this case
            # NAT rules are added only if ex_gw_port has an IPv4 address
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                if netaddr.IPAddress(ex_gw_ip).version == 4:
                    rules = self.external_gateway_nat_rules(ex_gw_ip,
                                                            internal_cidrs,
                                                            interface_name)
                    for rule in rules:
                        iptables_manager.ipv4['nat'].add_rule(*rule)
                    break
        iptables_manager.apply()

    def _handle_router_fip_nat_rules(self, ri, interface_name, action):
        """Configures NAT rules for Floating IPs for DVR.

           Remove all the rules. This is safe because if
           use_namespaces is set as False then the agent can
           only configure one router, otherwise each router's
           NAT rules will be in their own namespace.
        """
        ri.iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        ri.iptables_manager.ipv4['nat'].empty_chain('snat')

        # Add back the jump to float-snat
        ri.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        # And add them back if the action is add_rules
        if action == 'add_rules' and interface_name:
            rule = ('POSTROUTING', '! -i %(interface_name)s '
                    '! -o %(interface_name)s -m conntrack ! '
                    '--ctstate DNAT -j ACCEPT' %
                    {'interface_name': interface_name})
            ri.iptables_manager.ipv4['nat'].add_rule(*rule)
        ri.iptables_manager.apply()

    def process_router_floating_ip_nat_rules(self, ri):
        """Configure NAT rules for the router's floating IPs.

        Configures iptables rules for the floating ips of the given router
        """
        # Clear out all iptables rules for floating ips
        ri.iptables_manager.ipv4['nat'].clear_rules_by_tag('floating_ip')

        floating_ips = self.get_floating_ips(ri)
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            # Rebuild iptables rules for the floating ip.
            fixed = fip['fixed_ip_address']
            fip_ip = fip['floating_ip_address']
            for chain, rule in self.floating_forward_rules(fip_ip, fixed):
                ri.iptables_manager.ipv4['nat'].add_rule(chain, rule,
                                                         tag='floating_ip')

        ri.iptables_manager.apply()

    def _get_external_device_interface_name(self, ri, ex_gw_port,
                                            floating_ips):
        if ri.router['distributed']:
            # filter out only FIPs for this host/agent
            floating_ips = [i for i in floating_ips if i['host'] == self.host]
            if floating_ips and self.agent_gateway_port is None:
                self._create_agent_gateway_port(ri, floating_ips[0]
                                                ['floating_network_id'])

            if self.agent_gateway_port:
                if floating_ips and ri.dist_fip_count == 0:
                    self.create_rtr_2_fip_link(ri, floating_ips[0]
                                               ['floating_network_id'])
                return self.get_rtr_int_device_name(ri.router_id)
            else:
                # there are no fips or agent port, no work to do
                return None

        return self.get_external_device_name(ex_gw_port['id'])

    def _add_floating_ip(self, ri, fip, interface_name, device):
        fip_ip = fip['floating_ip_address']
        ip_cidr = str(fip_ip) + FLOATING_IP_CIDR_SUFFIX

        if ri.is_ha:
            self._add_vip(ri, ip_cidr, interface_name)
        else:
            net = netaddr.IPNetwork(ip_cidr)
            try:
                device.addr.add(net.version, ip_cidr, str(net.broadcast))
            except (processutils.UnknownArgumentError,
                    processutils.ProcessExecutionError):
                # any exception occurred here should cause the floating IP
                # to be set in error state
                LOG.warn(_("Unable to configure IP address for "
                           "floating IP: %s"), fip['id'])
                return l3_constants.FLOATINGIP_STATUS_ERROR
            if ri.router['distributed']:
                # Special Handling for DVR - update FIP namespace
                # and ri.namespace to handle DVR based FIP
                self.floating_ip_added_dist(ri, fip)
            else:
                # As GARP is processed in a distinct thread the call below
                # won't raise an exception to be handled.
                self._send_gratuitous_arp_packet(
                    ri.ns_name, interface_name, fip_ip)
            return l3_constants.FLOATINGIP_STATUS_ACTIVE

    def _remove_floating_ip(self, ri, device, ip_cidr):
        if ri.is_ha:
            self._remove_vip(ri, ip_cidr)
        else:
            net = netaddr.IPNetwork(ip_cidr)
            device.addr.delete(net.version, ip_cidr)
            self.driver.delete_conntrack_state(root_helper=self.root_helper,
                                               namespace=ri.ns_name,
                                               ip=ip_cidr)
            if ri.router['distributed']:
                self.floating_ip_removed_dist(ri, ip_cidr)

    def process_router_floating_ip_addresses(self, ri, ex_gw_port):
        """Configure IP addresses on router's external gateway interface.

        Ensures addresses for existing floating IPs and cleans up
        those that should not longer be configured.
        """

        fip_statuses = {}
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        interface_name = self._get_external_device_interface_name(
            ri, ex_gw_port, floating_ips)
        if interface_name is None:
            return fip_statuses

        device = ip_lib.IPDevice(interface_name, self.root_helper,
                                 namespace=ri.ns_name)
        existing_cidrs = set([addr['cidr'] for addr in device.addr.list()])
        new_cidrs = set()

        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            fip_ip = fip['floating_ip_address']
            ip_cidr = str(fip_ip) + FLOATING_IP_CIDR_SUFFIX
            new_cidrs.add(ip_cidr)
            fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ACTIVE
            if ip_cidr not in existing_cidrs:
                fip_statuses[fip['id']] = self._add_floating_ip(
                    ri, fip, interface_name, device)

        fips_to_remove = (
            ip_cidr for ip_cidr in existing_cidrs - new_cidrs if
            ip_cidr.endswith(FLOATING_IP_CIDR_SUFFIX))
        for ip_cidr in fips_to_remove:
            self._remove_floating_ip(ri, device, ip_cidr)

        return fip_statuses

    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def _arping(self, ns_name, interface_name, ip_address, distributed=False):
        if distributed:
            device = ip_lib.IPDevice(interface_name, self.root_helper,
                                     namespace=ns_name)
            ip_cidr = str(ip_address) + FLOATING_IP_CIDR_SUFFIX
            net = netaddr.IPNetwork(ip_cidr)
            device.addr.add(net.version, ip_cidr, str(net.broadcast))

        arping_cmd = ['arping', '-A',
                      '-I', interface_name,
                      '-c', self.conf.send_arp_for_ha,
                      ip_address]
        try:
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          namespace=ns_name)
            ip_wrapper.netns.execute(arping_cmd, check_exit_code=True)
        except Exception as e:
            LOG.error(_("Failed sending gratuitous ARP: %s"), str(e))
        if distributed:
            device.addr.delete(net.version, ip_cidr)

    def _send_gratuitous_arp_packet(self, ns_name, interface_name, ip_address,
                                    distributed=False):
        if self.conf.send_arp_for_ha > 0:
            eventlet.spawn_n(self._arping, ns_name, interface_name, ip_address,
                             distributed)

    def get_internal_port(self, ri, subnet_id):
        """Return internal router port based on subnet_id."""
        router_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        for port in router_ports:
            fips = port['fixed_ips']
            for f in fips:
                if f['subnet_id'] == subnet_id:
                    return port

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_fip_ext_device_name(self, port_id):
        return (FIP_EXT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_rtr_int_device_name(self, router_id):
        return (ROUTER_2_FIP_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]

    def get_fip_int_device_name(self, router_id):
        return (FIP_2_ROUTER_DEV_PREFIX + router_id)[:self.driver.DEV_NAME_LEN]

    def get_snat_int_device_name(self, port_id):
        return (SNAT_INT_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_fip_ns_name(self, ext_net_id):
        return (FIP_NS_PREFIX + ext_net_id)

    def get_snat_ns_name(self, router_id):
        return (SNAT_NS_PREFIX + router_id)

    def get_snat_interfaces(self, ri):
        return ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])

    def get_floating_ips(self, ri):
        """Filter Floating IPs to be hosted on this agent."""
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        if ri.router['distributed']:
            floating_ips = [i for i in floating_ips if i['host'] == self.host]
        return floating_ips

    def _map_internal_interfaces(self, ri, int_port, snat_ports):
        """Return the SNAT port for the given internal interface port."""
        fixed_ip = int_port['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        match_port = [p for p in snat_ports if
                      p['fixed_ips'][0]['subnet_id'] == subnet_id]
        if match_port:
            return match_port[0]
        else:
            LOG.error(_('DVR: no map match_port found!'))

    def _create_dvr_gateway(self, ri, ex_gw_port, gw_interface_name,
                            snat_ports):
        """Create SNAT namespace."""
        snat_ns_name = self.get_snat_ns_name(ri.router['id'])
        self._create_namespace(snat_ns_name)
        # connect snat_ports to br_int from SNAT namespace
        for port in snat_ports:
            # create interface_name
            self._set_subnet_info(port)
            interface_name = self.get_snat_int_device_name(port['id'])
            self._internal_network_added(snat_ns_name, port['network_id'],
                                         port['id'], port['ip_cidr'],
                                         port['mac_address'], interface_name,
                                         SNAT_INT_DEV_PREFIX)
        self._external_gateway_added(ri, ex_gw_port, gw_interface_name,
                                     snat_ns_name, preserve_ips=[])
        ri.snat_iptables_manager = iptables_manager.IptablesManager(
            root_helper=self.root_helper,
            namespace=snat_ns_name,
            use_ipv6=self.use_ipv6)
        # kicks the FW Agent to add rules for the snat namespace
        self.process_router_add(ri)

    def external_gateway_added(self, ri, ex_gw_port, interface_name):
        if ri.router['distributed']:
            ip_wrapr = ip_lib.IPWrapper(self.root_helper, namespace=ri.ns_name)
            ip_wrapr.netns.execute(['sysctl', '-w',
                                   'net.ipv4.conf.all.send_redirects=0'])
            snat_ports = self.get_snat_interfaces(ri)
            for p in ri.internal_ports:
                gateway = self._map_internal_interfaces(ri, p, snat_ports)
                id_name = self.get_internal_device_name(p['id'])
                if gateway:
                    self._snat_redirect_add(ri, gateway['fixed_ips'][0]
                                            ['ip_address'], p, id_name)

            if (self.conf.agent_mode == 'dvr_snat' and
                ri.router['gw_port_host'] == self.host):
                self._create_dvr_gateway(ri, ex_gw_port, interface_name,
                                         snat_ports)
            for port in snat_ports:
                for ip in port['fixed_ips']:
                    self._update_arp_entry(ri, ip['ip_address'],
                                           port['mac_address'],
                                           ip['subnet_id'], 'add')
            return

        # Compute a list of addresses this router is supposed to have.
        # This avoids unnecessarily removing those addresses and
        # causing a momentarily network outage.
        floating_ips = self.get_floating_ips(ri)
        preserve_ips = [ip['floating_ip_address'] + FLOATING_IP_CIDR_SUFFIX
                        for ip in floating_ips]

        self._external_gateway_added(ri, ex_gw_port, interface_name,
                                     ri.ns_name, preserve_ips)

        if ri.is_ha:
            self._ha_external_gateway_added(ri, ex_gw_port, interface_name)

    def external_gateway_updated(self, ri, ex_gw_port, interface_name):
        preserve_ips = []
        if ri.router['distributed']:
            if (self.conf.agent_mode == 'dvr_snat' and
                ri.router['gw_port_host'] == self.host):
                ns_name = self.get_snat_ns_name(ri.router['id'])
            else:
                # no centralized SNAT gateway for this node/agent
                LOG.debug("not hosting snat for router: %s", ri.router['id'])
                return
        else:
            ns_name = ri.ns_name
            floating_ips = self.get_floating_ips(ri)
            preserve_ips = [ip['floating_ip_address'] + FLOATING_IP_CIDR_SUFFIX
                            for ip in floating_ips]

        self._external_gateway_added(ri, ex_gw_port, interface_name,
                                     ns_name, preserve_ips)

        if ri.is_ha:
            self._ha_external_gateway_updated(ri, ex_gw_port, interface_name)

    def _external_gateway_added(self, ri, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ns_name,
                             prefix=EXTERNAL_DEV_PREFIX)

        if not ri.is_ha:
            self.driver.init_l3(
                interface_name, [ex_gw_port['ip_cidr']], namespace=ns_name,
                gateway=ex_gw_port['subnet'].get('gateway_ip'),
                extra_subnets=ex_gw_port.get('extra_subnets', []),
                preserve_ips=preserve_ips)
            ip_address = ex_gw_port['ip_cidr'].split('/')[0]
            self._send_gratuitous_arp_packet(ns_name,
                                             interface_name, ip_address)

    def agent_gateway_added(self, ns_name, ex_gw_port,
                            interface_name):
        """Add Floating IP gateway port to FIP namespace."""
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ns_name,
                             prefix=FIP_EXT_DEV_PREFIX)

        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ns_name)
        ip_address = ex_gw_port['ip_cidr'].split('/')[0]
        self._send_gratuitous_arp_packet(ns_name, interface_name, ip_address)

        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if gw_ip:
            ipd = ip_lib.IPDevice(interface_name, self.root_helper,
                                  namespace=ns_name)
            ipd.route.add_gateway(gw_ip)

        cmd = ['sysctl', '-w', 'net.ipv4.conf.%s.proxy_arp=1' % interface_name]
        ip_wrapper = ip_lib.IPWrapper(self.root_helper, namespace=ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def internal_ns_interface_added(self, ip_cidr,
                                    interface_name, ns_name):
        ip_wrapper = ip_lib.IPWrapper(self.root_helper, namespace=ns_name)
        ip_wrapper.netns.execute(['ip', 'addr', 'add',
                                  ip_cidr, 'dev', interface_name])

    def external_gateway_removed(self, ri, ex_gw_port, interface_name):
        if ri.router['distributed']:
            for p in ri.internal_ports:
                internal_interface = self.get_internal_device_name(p['id'])
                self._snat_redirect_remove(ri, p, internal_interface)

            if self.conf.agent_mode == 'dvr_snat' and (
                ri.router['gw_port_host'] == self.host):
                ns_name = self.get_snat_ns_name(ri.router['id'])
            else:
                # not hosting agent - no work to do
                LOG.debug('DVR: CSNAT not hosted: %s', ex_gw_port)
                return
        else:
            ns_name = ri.ns_name

        if ri.is_ha:
            self._ha_external_gateway_removed(ri, interface_name)

        self.driver.unplug(interface_name,
                           bridge=self.conf.external_network_bridge,
                           namespace=ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)
        if ri.router['distributed']:
            self._destroy_snat_namespace(ns_name)

    def metadata_filter_rules(self):
        rules = []
        if self.conf.enable_metadata_proxy:
            rules.append(('INPUT', '-s 0.0.0.0/0 -d 127.0.0.1 '
                          '-p tcp -m tcp --dport %s '
                          '-j ACCEPT' % self.conf.metadata_port))
        return rules

    def metadata_nat_rules(self):
        rules = []
        if self.conf.enable_metadata_proxy:
            rules.append(('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                          '-p tcp -m tcp --dport 80 -j REDIRECT '
                          '--to-port %s' % self.conf.metadata_port))
        return rules

    def external_gateway_nat_rules(self, ex_gw_ip, internal_cidrs,
                                   interface_name):
        rules = [('POSTROUTING', '! -i %(interface_name)s '
                  '! -o %(interface_name)s -m conntrack ! '
                  '--ctstate DNAT -j ACCEPT' %
                  {'interface_name': interface_name})]
        for cidr in internal_cidrs:
            rules.extend(self.internal_network_nat_rules(ex_gw_ip, cidr))
        return rules

    def _snat_redirect_add(self, ri, gateway, sn_port, sn_int):
        """Adds rules and routes for SNAT redirection."""
        try:
            snat_idx = netaddr.IPNetwork(sn_port['ip_cidr']).value
            ns_ipr = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, self.root_helper,
                                     namespace=ri.ns_name)
            ns_ipd.route.add_gateway(gateway, table=snat_idx)
            ns_ipr.add_rule_from(sn_port['ip_cidr'], snat_idx, snat_idx)
            ns_ipr.netns.execute(['sysctl', '-w', 'net.ipv4.conf.%s.'
                                 'send_redirects=0' % sn_int])
        except Exception:
            LOG.exception(_('DVR: error adding redirection logic'))

    def _snat_redirect_remove(self, ri, sn_port, sn_int):
        """Removes rules and routes for SNAT redirection."""
        try:
            snat_idx = netaddr.IPNetwork(sn_port['ip_cidr']).value
            ns_ipr = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, self.root_helper,
                                     namespace=ri.ns_name)
            ns_ipd.route.delete_gateway(table=snat_idx)
            ns_ipr.delete_rule_priority(snat_idx)
        except Exception:
            LOG.exception(_('DVR: removed snat failed'))

    def _internal_network_added(self, ns_name, network_id, port_id,
                                internal_cidr, mac_address,
                                interface_name, prefix, is_ha=False):
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ns_name):
            self.driver.plug(network_id, port_id, interface_name, mac_address,
                             namespace=ns_name,
                             prefix=prefix)

        if not is_ha:
            self.driver.init_l3(interface_name, [internal_cidr],
                                namespace=ns_name)
            ip_address = internal_cidr.split('/')[0]
            self._send_gratuitous_arp_packet(ns_name, interface_name,
                                             ip_address)

    def internal_network_added(self, ri, port):
        network_id = port['network_id']
        port_id = port['id']
        internal_cidr = port['ip_cidr']
        mac_address = port['mac_address']

        interface_name = self.get_internal_device_name(port_id)

        self._internal_network_added(ri.ns_name, network_id, port_id,
                                     internal_cidr, mac_address,
                                     interface_name, INTERNAL_DEV_PREFIX,
                                     ri.is_ha)

        if ri.is_ha:
            self._add_vip(ri, internal_cidr, interface_name)

        ex_gw_port = self._get_ex_gw_port(ri)
        if ri.router['distributed'] and ex_gw_port:
            snat_ports = self.get_snat_interfaces(ri)
            sn_port = self._map_internal_interfaces(ri, port, snat_ports)
            if sn_port:
                self._snat_redirect_add(ri, sn_port['fixed_ips'][0]
                                        ['ip_address'], port, interface_name)
                if (self.conf.agent_mode == 'dvr_snat' and
                    ri.router['gw_port_host'] == self.host):
                    ns_name = self.get_snat_ns_name(ri.router['id'])
                    self._set_subnet_info(sn_port)
                    interface_name = (
                          self.get_snat_int_device_name(sn_port['id']))
                    self._internal_network_added(ns_name,
                                                 sn_port['network_id'],
                                                 sn_port['id'],
                                                 sn_port['ip_cidr'],
                                                 sn_port['mac_address'],
                                                 interface_name,
                                                 SNAT_INT_DEV_PREFIX)

    def internal_network_removed(self, ri, port):
        port_id = port['id']
        interface_name = self.get_internal_device_name(port_id)
        if ri.router['distributed'] and ri.ex_gw_port:
            # DVR handling code for SNAT
            self._snat_redirect_remove(ri, port, interface_name)
            if self.conf.agent_mode == 'dvr_snat' and (
                ri.ex_gw_port['binding:host_id'] == self.host):
                snat_port = self._map_internal_interfaces(ri, port,
                                                          ri.snat_ports)
                if snat_port:
                    snat_interface = (
                        self.get_snat_int_device_name(snat_port['id'])
                    )
                    ns_name = self.get_snat_ns_name(ri.router['id'])
                    prefix = SNAT_INT_DEV_PREFIX
                    if ip_lib.device_exists(snat_interface,
                                            root_helper=self.root_helper,
                                            namespace=ns_name):
                        self.driver.unplug(snat_interface, namespace=ns_name,
                                           prefix=prefix)

        if ip_lib.device_exists(interface_name,
                                root_helper=self.root_helper,
                                namespace=ri.ns_name):
            if ri.is_ha:
                self._clear_vips(ri, interface_name)
            self.driver.unplug(interface_name, namespace=ri.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def internal_network_nat_rules(self, ex_gw_ip, internal_cidr):
        rules = [('snat', '-s %s -j SNAT --to-source %s' %
                 (internal_cidr, ex_gw_ip))]
        return rules

    def _create_agent_gateway_port(self, ri, network_id):
        """Create Floating IP gateway port.

           Request port creation from Plugin then creates
           Floating IP namespace and adds gateway port.
        """
        self.agent_gateway_port = (
            self.plugin_rpc.get_agent_gateway_port(
                self.context, network_id))
        if 'subnet' not in self.agent_gateway_port:
            LOG.error(_('Missing subnet/agent_gateway_port'))
            return
        self._set_subnet_info(self.agent_gateway_port)

        # add fip-namespace and agent_gateway_port
        fip_ns_name = (
            self.get_fip_ns_name(str(network_id)))
        self._create_namespace(fip_ns_name)
        ri.fip_iptables_manager = iptables_manager.IptablesManager(
            root_helper=self.root_helper, namespace=fip_ns_name,
            use_ipv6=self.use_ipv6)
        # no connection tracking needed in fip namespace
        ri.fip_iptables_manager.ipv4['raw'].add_rule('PREROUTING',
                                                     '-j CT --notrack')
        ri.fip_iptables_manager.apply()
        interface_name = (
            self.get_fip_ext_device_name(self.agent_gateway_port['id']))
        self.agent_gateway_added(fip_ns_name, self.agent_gateway_port,
                                 interface_name)

    def create_rtr_2_fip_link(self, ri, network_id):
        """Create interface between router and Floating IP namespace."""
        rtr_2_fip_name = self.get_rtr_int_device_name(ri.router_id)
        fip_2_rtr_name = self.get_fip_int_device_name(ri.router_id)
        fip_ns_name = self.get_fip_ns_name(str(network_id))

        # add link local IP to interface
        if ri.rtr_fip_subnet is None:
            ri.rtr_fip_subnet = self.local_subnets.allocate(ri.router_id)
        rtr_2_fip, fip_2_rtr = ri.rtr_fip_subnet.get_pair()
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=ri.ns_name)
        int_dev = ip_wrapper.add_veth(rtr_2_fip_name,
                                      fip_2_rtr_name, fip_ns_name)
        self.internal_ns_interface_added(str(rtr_2_fip),
                                         rtr_2_fip_name, ri.ns_name)
        self.internal_ns_interface_added(str(fip_2_rtr),
                                         fip_2_rtr_name, fip_ns_name)
        int_dev[0].link.set_up()
        int_dev[1].link.set_up()
        # add default route for the link local interface
        device = ip_lib.IPDevice(rtr_2_fip_name, self.root_helper,
                                 namespace=ri.ns_name)
        device.route.add_gateway(str(fip_2_rtr.ip), table=FIP_RT_TBL)
        #setup the NAT rules and chains
        self._handle_router_fip_nat_rules(ri, rtr_2_fip_name, 'add_rules')
        # kicks the FW Agent to add rules for the IR namespace if configured
        self.process_router_add(ri)

    def floating_ip_added_dist(self, ri, fip):
        """Add floating IP to FIP namespace."""
        floating_ip = fip['floating_ip_address']
        fixed_ip = fip['fixed_ip_address']
        rule_pr = self.fip_priorities.pop()
        ri.floating_ips_dict[floating_ip] = rule_pr
        fip_2_rtr_name = self.get_fip_int_device_name(ri.router_id)
        ip_rule = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
        ip_rule.add_rule_from(fixed_ip, FIP_RT_TBL, rule_pr)

        #Add routing rule in fip namespace
        fip_cidr = str(floating_ip) + FLOATING_IP_CIDR_SUFFIX
        fip_ns_name = self.get_fip_ns_name(str(fip['floating_network_id']))
        rtr_2_fip, _ = ri.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, self.root_helper,
                                 namespace=fip_ns_name)
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
        interface_name = (
            self.get_fip_ext_device_name(self.agent_gateway_port['id']))
        self._send_gratuitous_arp_packet(fip_ns_name,
                                         interface_name, floating_ip,
                                         distributed=True)
        # update internal structures
        self.agent_fip_count = self.agent_fip_count + 1
        ri.dist_fip_count = ri.dist_fip_count + 1

    def floating_ip_removed_dist(self, ri, fip_cidr):
        """Remove floating IP from FIP namespace."""
        floating_ip = fip_cidr.split('/')[0]
        rtr_2_fip_name = self.get_rtr_int_device_name(ri.router_id)
        fip_2_rtr_name = self.get_fip_int_device_name(ri.router_id)
        rtr_2_fip, fip_2_rtr = ri.rtr_fip_subnet.get_pair()
        fip_ns_name = self.get_fip_ns_name(str(self._fetch_external_net_id()))
        ip_rule_rtr = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
        if floating_ip in ri.floating_ips_dict:
            rule_pr = ri.floating_ips_dict[floating_ip]
            #TODO(rajeev): Handle else case - exception/log?
        else:
            rule_pr = None

        ip_rule_rtr.delete_rule_priority(rule_pr)
        self.fip_priorities.add(rule_pr)
        device = ip_lib.IPDevice(fip_2_rtr_name, self.root_helper,
                                 namespace=fip_ns_name)

        device.route.delete_route(fip_cidr, str(rtr_2_fip.ip))
        # check if this is the last FIP for this router
        ri.dist_fip_count = ri.dist_fip_count - 1
        if ri.dist_fip_count == 0:
            #remove default route entry
            device = ip_lib.IPDevice(rtr_2_fip_name, self.root_helper,
                                     namespace=ri.ns_name)
            ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=fip_ns_name)
            device.route.delete_gateway(str(fip_2_rtr.ip), table=FIP_RT_TBL)
            self.local_subnets.release(ri.router_id)
            ri.rtr_fip_subnet = None
            ns_ip.del_veth(fip_2_rtr_name)
        # clean up fip-namespace if this is the last FIP
        self.agent_fip_count = self.agent_fip_count - 1
        if self.agent_fip_count == 0:
            self._destroy_fip_namespace(fip_ns_name)

    def floating_forward_rules(self, floating_ip, fixed_ip):
        return [('PREROUTING', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', '-s %s -j SNAT --to %s' %
                 (fixed_ip, floating_ip))]

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.debug(_('Got router deleted notification for %s'), router_id)
        update = RouterUpdate(router_id, PRIORITY_RPC, action=DELETE_ROUTER)
        self._queue.add(update)

    def _update_arp_entry(self, ri, ip, mac, subnet_id, operation):
        """Add or delete arp entry into router namespace for the subnet."""
        port = self.get_internal_port(ri, subnet_id)
        # update arp entry only if the subnet is attached to the router
        if port:
            ip_cidr = str(ip) + '/32'
            try:
                # TODO(mrsmith): optimize the calls below for bulk calls
                net = netaddr.IPNetwork(ip_cidr)
                interface_name = self.get_internal_device_name(port['id'])
                device = ip_lib.IPDevice(interface_name, self.root_helper,
                                         namespace=ri.ns_name)
                if operation == 'add':
                    device.neigh.add(net.version, ip, mac)
                elif operation == 'delete':
                    device.neigh.delete(net.version, ip, mac)
            except Exception:
                LOG.exception(_("DVR: Failed updating arp entry"))
                self.fullsync = True

    def add_arp_entry(self, context, payload):
        """Add arp entry into router namespace.  Called from RPC."""
        arp_table = payload['arp_table']
        router_id = payload['router_id']
        ip = arp_table['ip_address']
        mac = arp_table['mac_address']
        subnet_id = arp_table['subnet_id']
        ri = self.router_info.get(router_id)
        if ri:
            self._update_arp_entry(ri, ip, mac, subnet_id, 'add')

    def del_arp_entry(self, context, payload):
        """Delete arp entry from router namespace.  Called from RPC."""
        arp_table = payload['arp_table']
        router_id = payload['router_id']
        ip = arp_table['ip_address']
        mac = arp_table['mac_address']
        subnet_id = arp_table['subnet_id']
        ri = self.router_info.get(router_id)
        if ri:
            self._update_arp_entry(ri, ip, mac, subnet_id, 'delete')

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug(_('Got routers updated notification :%s'), routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            for id in routers:
                update = RouterUpdate(id, PRIORITY_RPC)
                self._queue.add(update)

    def router_removed_from_agent(self, context, payload):
        LOG.debug(_('Got router removed from agent :%r'), payload)
        router_id = payload['router_id']
        update = RouterUpdate(router_id, PRIORITY_RPC, action=DELETE_ROUTER)
        self._queue.add(update)

    def router_added_to_agent(self, context, payload):
        LOG.debug(_('Got router added to agent :%r'), payload)
        self.routers_updated(context, payload)

    def _process_routers(self, routers, all_routers=False):
        pool = eventlet.GreenPool()
        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        target_ex_net_id = self._fetch_external_net_id()
        # if routers are all the routers we have (They are from router sync on
        # starting or when error occurs during running), we seek the
        # routers which should be removed.
        # If routers are from server side notification, we seek them
        # from subset of incoming routers and ones we have now.
        if all_routers:
            prev_router_ids = set(self.router_info)
        else:
            prev_router_ids = set(self.router_info) & set(
                [router['id'] for router in routers])
        cur_router_ids = set()
        for r in routers:
            # If namespaces are disabled, only process the router associated
            # with the configured agent id.
            if (not self.conf.use_namespaces and
                r['id'] != self.conf.router_id):
                continue
            ex_net_id = (r['external_gateway_info'] or {}).get('network_id')
            if not ex_net_id and not self.conf.handle_internal_only_routers:
                continue
            if (target_ex_net_id and ex_net_id and
                ex_net_id != target_ex_net_id):
                # Double check that our single external_net_id has not changed
                # by forcing a check by RPC.
                if (ex_net_id != self._fetch_external_net_id(force=True)):
                    continue
            cur_router_ids.add(r['id'])
            if r['id'] not in self.router_info:
                self._router_added(r['id'], r)
            ri = self.router_info[r['id']]
            ri.router = r
            pool.spawn_n(self.process_router, ri)
        # identify and remove routers that no longer exist
        for router_id in prev_router_ids - cur_router_ids:
            pool.spawn_n(self._router_removed, router_id)
        pool.waitall()

    def _process_router_update(self):
        for rp, update in self._queue.each_update_to_next_router():
            LOG.debug("Starting router update for %s", update.id)
            router = update.router
            if update.action != DELETE_ROUTER and not router:
                try:
                    update.timestamp = timeutils.utcnow()
                    routers = self.plugin_rpc.get_routers(self.context,
                                                          [update.id])
                except Exception:
                    msg = _("Failed to fetch router information for '%s'")
                    LOG.exception(msg, update.id)
                    self.fullsync = True
                    continue

                if routers:
                    router = routers[0]

            if not router:
                self._router_removed(update.id)
                continue

            self._process_routers([router])
            LOG.debug("Finished a router update for %s", update.id)
            rp.fetched_and_processed(update.timestamp)

    def _process_routers_loop(self):
        LOG.debug("Starting _process_routers_loop")
        pool = eventlet.GreenPool(size=8)
        while True:
            pool.spawn_n(self._process_router_update)

    def _router_ids(self):
        if not self.conf.use_namespaces:
            return [self.conf.router_id]

    @periodic_task.periodic_task
    def periodic_sync_routers_task(self, context):
        self._sync_routers_task(context)

    def _sync_routers_task(self, context):
        if self.services_sync:
            super(L3NATAgent, self).process_services_sync(context)
        LOG.debug(_("Starting _sync_routers_task - fullsync:%s"),
                  self.fullsync)
        if not self.fullsync:
            return

        # Capture a picture of namespaces *before* fetching the full list from
        # the database.  This is important to correctly identify stale ones.
        namespaces = set()
        if self._clean_stale_namespaces:
            namespaces = self._list_namespaces()
        prev_router_ids = set(self.router_info)

        try:
            router_ids = self._router_ids()
            timestamp = timeutils.utcnow()
            routers = self.plugin_rpc.get_routers(
                context, router_ids)

            LOG.debug(_('Processing :%r'), routers)
            for r in routers:
                update = RouterUpdate(r['id'],
                                      PRIORITY_SYNC_ROUTERS_TASK,
                                      router=r,
                                      timestamp=timestamp)
                self._queue.add(update)
            self.fullsync = False
            LOG.debug(_("_sync_routers_task successfully completed"))
        except n_rpc.RPCException:
            LOG.exception(_("Failed synchronizing routers due to RPC error"))
            self.fullsync = True
        except Exception:
            LOG.exception(_("Failed synchronizing routers"))
            self.fullsync = True
        else:
            # Resync is not necessary for the cleanup of stale namespaces
            curr_router_ids = set([r['id'] for r in routers])

            # Two kinds of stale routers:  Routers for which info is cached in
            # self.router_info and the others.  First, handle the former.
            for router_id in prev_router_ids - curr_router_ids:
                update = RouterUpdate(router_id,
                                      PRIORITY_SYNC_ROUTERS_TASK,
                                      timestamp=timestamp,
                                      action=DELETE_ROUTER)
                self._queue.add(update)

            # Next, one effort to clean out namespaces for which we don't have
            # a record.  (i.e. _clean_stale_namespaces=False after one pass)
            if self._clean_stale_namespaces:
                ids_to_keep = curr_router_ids | prev_router_ids
                self._cleanup_namespaces(namespaces, ids_to_keep)

    def after_start(self):
        eventlet.spawn_n(self._process_routers_loop)
        LOG.info(_("L3 agent started"))

    def _update_routing_table(self, ri, operation, route):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop']]
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=ri.ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def routes_updated(self, ri):
        new_routes = ri.router['routes']
        if ri.is_ha:
            self._process_virtual_routes(ri, new_routes)
            return

        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug(_("Added route entry is '%s'"), route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            #replace success even if there is no existing route
            self._update_routing_table(ri, 'replace', route)
        for route in removes:
            LOG.debug(_("Removed route entry is '%s'"), route)
            self._update_routing_table(ri, 'delete', route)
        ri.routes = new_routes


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-l3-agent',
            'host': host,
            'topic': topics.L3_AGENT,
            'configurations': {
                'agent_mode': self.conf.agent_mode,
                'use_namespaces': self.conf.use_namespaces,
                'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'external_network_bridge': self.conf.external_network_bridge,
                'gateway_external_network_id':
                self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver},
            'start_flag': True,
            'agent_type': l3_constants.AGENT_TYPE_L3}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug(_("Report state task started"))
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(l3_constants.INTERFACE_KEY,
                                                []))
            num_floating_ips += len(ri.router.get(l3_constants.FLOATINGIP_KEY,
                                                  []))
        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['interfaces'] = num_interfaces
        configurations['floating_ips'] = num_floating_ips
        try:
            self.state_rpc.report_state(self.context, self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
            LOG.debug(_("Report state task successfully completed"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Neutron server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def _register_opts(conf):
    conf.register_opts(L3NATAgent.OPTS)
    conf.register_opts(l3_ha_agent.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)


def main(manager='neutron.agent.l3_agent.L3NATAgentWithStateReport'):
    _register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()
