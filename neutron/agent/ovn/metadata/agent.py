# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import re

from neutron_lib import constants as n_const
from oslo_concurrency import lockutils
from oslo_log import log
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import vlog
import six
import tenacity

from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.ovn.metadata import driver as metadata_driver
from neutron.agent.ovn.metadata import ovsdb
from neutron.agent.ovn.metadata import server as metadata_server
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config


LOG = log.getLogger(__name__)
_SYNC_STATE_LOCK = lockutils.ReaderWriterLock()
CHASSIS_METADATA_LOCK = 'chassis_metadata_lock'

NS_PREFIX = 'ovnmeta-'
MAC_PATTERN = re.compile(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', re.I)
OVN_VIF_PORT_TYPES = ("", "external", )

MetadataPortInfo = collections.namedtuple('MetadataPortInfo', ['mac',
                                                               'ip_addresses'])


def _sync_lock(f):
    """Decorator to block all operations for a global sync call."""
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        with _SYNC_STATE_LOCK.write_lock():
            return f(*args, **kwargs)
    return wrapped


class ConfigException(Exception):
    """Misconfiguration of the agent

    This exception is raised when agent detects its wrong configuration.
    Typically agent should resync when this is raised.
    """


class PortBindingChassisEvent(row_event.RowEvent):
    def __init__(self, metadata_agent):
        self.agent = metadata_agent
        table = 'Port_Binding'
        events = (self.ROW_UPDATE,)
        super(PortBindingChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        # Check if the port has been bound/unbound to our chassis and update
        # the metadata namespace accordingly.
        resync = False
        if row.type not in OVN_VIF_PORT_TYPES:
            return
        with _SYNC_STATE_LOCK.read_lock():
            try:
                net_name = ovn_utils.get_network_name_from_datapath(
                        row.datapath)
                LOG.info(self.LOG_MSG, row.logical_port, net_name)
                self.agent.update_datapath(str(row.datapath.uuid), net_name)
            except ConfigException:
                # We're now in the reader lock mode, we need to exit the
                # context and then use writer lock
                resync = True
        if resync:
            self.agent.resync()


class PortBindingChassisCreatedEvent(PortBindingChassisEvent):
    LOG_MSG = "Port %s in datapath %s bound to our chassis"

    def match_fn(self, event, row, old):
        try:
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False


class PortBindingChassisDeletedEvent(PortBindingChassisEvent):
    LOG_MSG = "Port %s in datapath %s unbound from our chassis"

    def match_fn(self, event, row, old):
        try:
            return (old.chassis[0].name == self.agent.chassis and
                    not row.chassis)
        except (IndexError, AttributeError):
            return False


class ChassisCreateEventBase(row_event.RowEvent):
    """Row create event - Chassis name == our_chassis.

    On connection, we get a dump of all chassis so if we catch a creation
    of our own chassis it has to be a reconnection. In this case, we need
    to do a full sync to make sure that we capture all changes while the
    connection to OVSDB was down.
    """
    table = None

    def __init__(self, metadata_agent):
        self.agent = metadata_agent
        self.first_time = True
        events = (self.ROW_CREATE,)
        super(ChassisCreateEventBase, self).__init__(
            events, self.table, (('name', '=', self.agent.chassis),))
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        if self.first_time:
            self.first_time = False
        else:
            # NOTE(lucasagomes): Re-register the ovn metadata agent
            # with the local chassis in case its entry was re-created
            # (happens when restarting the ovn-controller)
            self.agent.register_metadata_agent()
            LOG.info("Connection to OVSDB established, doing a full sync")
            self.agent.sync()


class ChassisCreateEvent(ChassisCreateEventBase):
    table = 'Chassis'


class ChassisPrivateCreateEvent(ChassisCreateEventBase):
    table = 'Chassis_Private'


class SbGlobalUpdateEvent(row_event.RowEvent):
    """Row update event on SB_Global table."""

    def __init__(self, metadata_agent):
        self.agent = metadata_agent
        table = 'SB_Global'
        events = (self.ROW_UPDATE,)
        super(SbGlobalUpdateEvent, self).__init__(events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        table = ('Chassis_Private' if self.agent.has_chassis_private
                 else 'Chassis')
        self.agent.sb_idl.db_set(
            table, self.agent.chassis, ('external_ids', {
                ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY:
                    str(row.nb_cfg)})).execute()


class MetadataAgent(object):

    def __init__(self, conf):
        self.conf = conf
        vlog.use_python_logger(max_level=config.get_ovn_ovsdb_log_level())
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='metadata')

    def _load_config(self):
        self.chassis = self._get_own_chassis_name()
        self.ovn_bridge = self._get_ovn_bridge()
        LOG.debug("Loaded chassis %s and ovn bridge %s.",
                  self.chassis, self.ovn_bridge)

    @_sync_lock
    def resync(self):
        """Resync the agent.

        Reload the configuration and sync the agent again.
        """
        self._load_config()
        self.sync()

    def start(self):
        # Open the connection to OVS database
        self.ovs_idl = ovsdb.MetadataAgentOvsIdl().start()
        self._load_config()

        # Launch the server that will act as a proxy between the VM's and Nova.
        proxy = metadata_server.UnixDomainMetadataProxy(self.conf,
                self.chassis)
        proxy.run()

        tables = ('Encap', 'Port_Binding', 'Datapath_Binding', 'SB_Global',
                  'Chassis')
        events = (PortBindingChassisCreatedEvent(self),
                  PortBindingChassisDeletedEvent(self),
                  SbGlobalUpdateEvent(self))

        # TODO(lucasagomes): Remove this in the future. Try to register
        # the Chassis_Private table, if not present, fallback to the normal
        # Chassis table.
        # Open the connection to OVN SB database.
        self.has_chassis_private = False
        try:
            self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
                chassis=self.chassis, tables=tables + ('Chassis_Private', ),
                events=events + (ChassisPrivateCreateEvent(self), )).start()
            self.has_chassis_private = True
        except AssertionError:
            self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
                chassis=self.chassis, tables=tables,
                events=events + (ChassisCreateEvent(self), )).start()

        # Do the initial sync.
        self.sync()

        # Register the agent with its corresponding Chassis
        self.register_metadata_agent()

        proxy.wait()

    @tenacity.retry(
        wait=tenacity.wait_exponential(
            max=config.get_ovn_ovsdb_retry_max_interval()),
        reraise=True)
    def register_metadata_agent(self):
        # NOTE(lucasagomes): db_add() will not overwrite the UUID if
        # it's already set.
        table = ('Chassis_Private' if self.has_chassis_private else 'Chassis')
        ext_ids = {
            ovn_const.OVN_AGENT_METADATA_ID_KEY: uuidutils.generate_uuid()}
        self.sb_idl.db_add(table, self.chassis, 'external_ids',
                           ext_ids).execute(check_error=True)

    def _get_own_chassis_name(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        As long as ovn-controller is running on this node, the key is
        guaranteed to exist and will include the chassis name.
        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['system-id']

    def _get_ovn_bridge(self):
        """Return the external_ids:ovn-bridge value of the Open_vSwitch table.

        This is the OVS bridge used to plug the metadata ports to.
        If the key doesn't exist, this method will return 'br-int' as default.
        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        try:
            return ext_ids['ovn-bridge']
        except KeyError:
            LOG.warning("Can't read ovn-bridge external-id from OVSDB. Using "
                        "br-int instead.")
            return 'br-int'

    @_sync_lock
    def sync(self):
        """Agent sync.

        This function will make sure that all networks with ports in our
        chassis are serving metadata. Also, it will tear down those namespaces
        which were serving metadata but are no longer needed.
        """
        metadata_namespaces = self.ensure_all_networks_provisioned()
        system_namespaces = tuple(
            ns.decode('utf-8') if isinstance(ns, bytes) else ns
            for ns in ip_lib.list_network_namespaces())
        unused_namespaces = [ns for ns in system_namespaces if
                             ns.startswith(NS_PREFIX) and
                             ns not in metadata_namespaces]
        for ns in unused_namespaces:
            self.teardown_datapath(self._get_datapath_name(ns))

    @staticmethod
    def _get_veth_name(datapath):
        return ['{}{}{}'.format(n_const.TAP_DEVICE_PREFIX,
                                datapath[:10], i) for i in [0, 1]]

    @staticmethod
    def _get_datapath_name(namespace):
        return namespace[len(NS_PREFIX):]

    @staticmethod
    def _get_namespace_name(datapath):
        return NS_PREFIX + datapath

    def _vif_ports(self, ports):
        return (p for p in ports if p.type in OVN_VIF_PORT_TYPES)

    def teardown_datapath(self, datapath, net_name=None):
        """Unprovision this datapath to stop serving metadata.

        This function will shutdown metadata proxy if it's running and delete
        the VETH pair, the OVS port and the namespace.
        """
        self.update_chassis_metadata_networks(datapath, remove=True)

        # TODO(dalvarez): Remove this in Y cycle when we are sure that all
        # namespaces will be created with the Neutron network UUID and not
        # anymore with the OVN datapath UUID.
        dp = net_name or datapath

        namespace = self._get_namespace_name(dp)
        ip = ip_lib.IPWrapper(namespace)
        # If the namespace doesn't exist, return
        if not ip.netns.exists(namespace):
            return

        LOG.info("Cleaning up %s namespace which is not needed anymore",
                 namespace)

        metadata_driver.MetadataDriver.destroy_monitored_metadata_proxy(
            self._process_monitor, dp, self.conf, namespace)

        veth_name = self._get_veth_name(dp)
        self.ovs_idl.del_port(veth_name[0]).execute()
        if ip_lib.device_exists(veth_name[0]):
            ip_lib.IPWrapper().del_veth(veth_name[0])

        ip.garbage_collect_namespace()

    def update_datapath(self, datapath, net_name):
        """Update the metadata service for this datapath.

        This function will:
        * Provision the namespace if it wasn't already in place.
        * Update the namespace if it was already serving metadata (for example,
          after binding/unbinding the first/last port of a subnet in our
          chassis).
        * Tear down the namespace if there are no more ports in our chassis
          for this datapath.
        """
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        datapath_ports = [p for p in self._vif_ports(ports) if
                          str(p.datapath.uuid) == datapath]
        if datapath_ports:
            self.provision_datapath(datapath, net_name)
        else:
            self.teardown_datapath(datapath, net_name)

    def _ensure_datapath_checksum(self, namespace):
        """Ensure the correct checksum in the metadata packets in DPDK bridges

        (LP#1904871) In DPDK deployments (integration bridge datapath_type ==
        "netdev"), the checksum between the metadata namespace and OVS is not
        correctly populated.
        """
        if (self.ovs_idl.db_get(
                'Bridge', self.ovn_bridge, 'datapath_type').execute() !=
                ovn_const.CHASSIS_DATAPATH_NETDEV):
            return

        iptables_mgr = iptables_manager.IptablesManager(
            use_ipv6=True, nat=False, namespace=namespace, external_lock=False)
        rule = '-p tcp -m tcp -j CHECKSUM --checksum-fill'
        iptables_mgr.ipv4['mangle'].add_rule('POSTROUTING', rule, wrap=False)
        iptables_mgr.apply()

    def provision_datapath(self, datapath, net_name):
        """Provision the datapath so that it can serve metadata.

        This function will create the namespace and VETH pair if needed
        and assign the IP addresses to the interface corresponding to the
        metadata port of the network. It will also remove existing IP
        addresses that are no longer needed.

        :return: The metadata namespace name of this datapath
        """
        LOG.debug("Provisioning metadata for network %s", net_name)
        port = self.sb_idl.get_metadata_port_network(datapath)
        # If there's no metadata port or it doesn't have a MAC or IP
        # addresses, then tear the namespace down if needed. This might happen
        # when there are no subnets yet created so metadata port doesn't have
        # an IP address.
        if not (port and port.mac and
                port.external_ids.get(ovn_const.OVN_CIDRS_EXT_ID_KEY, None)):
            LOG.debug("There is no metadata port for network %s or it has no "
                      "MAC or IP addresses configured, tearing the namespace "
                      "down if needed", net_name)
            self.teardown_datapath(datapath, net_name)
            return

        # First entry of the mac field must be the MAC address.
        match = MAC_PATTERN.match(port.mac[0].split(' ')[0])
        # If it is not, we can't provision the namespace. Tear it down if
        # needed and log the error.
        if not match:
            LOG.error("Metadata port for network %s doesn't have a MAC "
                      "address, tearing the namespace down if needed",
                      net_name)
            self.teardown_datapath(datapath)
            return

        mac = match.group()
        ip_addresses = set(
            port.external_ids[ovn_const.OVN_CIDRS_EXT_ID_KEY].split(' '))
        ip_addresses.add(ovn_const.METADATA_DEFAULT_CIDR)
        metadata_port = MetadataPortInfo(mac, ip_addresses)

        # Create the VETH pair if it's not created. Also the add_veth function
        # will create the namespace for us.
        namespace = self._get_namespace_name(net_name)
        veth_name = self._get_veth_name(net_name)

        ip1 = ip_lib.IPDevice(veth_name[0])
        if ip_lib.device_exists(veth_name[1], namespace):
            ip2 = ip_lib.IPDevice(veth_name[1], namespace)
        else:
            LOG.debug("Creating VETH %s in %s namespace", veth_name[1],
                      namespace)
            # Might happen that the end in the root namespace exists even
            # though the other end doesn't. Make sure we delete it first if
            # that's the case.
            if ip1.exists():
                ip1.link.delete()
            ip1, ip2 = ip_lib.IPWrapper().add_veth(
                veth_name[0], veth_name[1], namespace)

        # Make sure both ends of the VETH are up
        ip1.link.set_up()
        ip2.link.set_up()

        # Configure the MAC address.
        ip2.link.set_address(metadata_port.mac)
        dev_info = ip2.addr.list()

        # Configure the IP addresses on the VETH pair and remove those
        # that we no longer need.
        current_cidrs = {dev['cidr'] for dev in dev_info}
        for ipaddr in current_cidrs - metadata_port.ip_addresses:
            ip2.addr.delete(ipaddr)
        for ipaddr in metadata_port.ip_addresses - current_cidrs:
            # NOTE(dalvarez): metadata only works on IPv4. We're doing this
            # extra check here because it could be that the metadata port has
            # an IPv6 address if there's an IPv6 subnet with SLAAC in its
            # network. Neutron IPAM will autoallocate an IPv6 address for every
            # port in the network.
            if utils.get_ip_version(ipaddr) == 4:
                ip2.addr.add(ipaddr)

        # Check that this port is not attached to any other OVS bridge. This
        # can happen when the OVN bridge changes (for example, during a
        # migration from ML2/OVS).
        ovs_bridges = set(self.ovs_idl.list_br().execute())
        try:
            ovs_bridges.remove(self.ovn_bridge)
        except KeyError:
            LOG.warning("Configured OVN bridge %s cannot be found in "
                        "the system. Resyncing the agent.", self.ovn_bridge)
            raise ConfigException()

        if ovs_bridges:
            with self.ovs_idl.transaction() as txn:
                for br in ovs_bridges:
                    txn.add(self.ovs_idl.del_port(veth_name[0], bridge=br,
                                                  if_exists=True))

        # Configure the OVS port and add external_ids:iface-id so that it
        # can be tracked by OVN.
        self.ovs_idl.add_port(self.ovn_bridge,
                              veth_name[0]).execute()
        self.ovs_idl.db_set(
            'Interface', veth_name[0],
            ('external_ids', {'iface-id': port.logical_port})).execute()

        # Ensure the correct checksum in the metadata traffic.
        self._ensure_datapath_checksum(namespace)

        # Spawn metadata proxy if it's not already running.
        metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
            self._process_monitor, namespace, ovn_const.METADATA_PORT,
            self.conf, bind_address=ovn_const.METADATA_DEFAULT_IP,
            network_id=net_name)

        self.update_chassis_metadata_networks(net_name)
        return namespace

    def ensure_all_networks_provisioned(self):
        """Ensure that all datapaths are provisioned.

        This function will make sure that all datapaths with ports bound to
        our chassis have its namespace, VETH pair and OVS port created and
        metadata proxy is up and running.

        :return: A list with the namespaces that are currently serving
        metadata
        """
        # Retrieve all VIF ports in our Chassis
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        nets = {(str(p.datapath.uuid),
            ovn_utils.get_network_name_from_datapath(p.datapath))
            for p in self._vif_ports(ports)}
        namespaces = []
        # Make sure that all those datapaths are serving metadata
        for datapath, net_name in nets:
            netns = self.provision_datapath(datapath, net_name)
            if netns:
                namespaces.append(netns)

        return namespaces

    # NOTE(lucasagomes): Even tho the metadata agent is a multi-process
    # application, there's only one Southbound database IDL instance in
    # the agent which handles the OVSDB events therefore we do not need
    # the external=True parameter in the @synchronized decorator.
    @lockutils.synchronized(CHASSIS_METADATA_LOCK)
    def update_chassis_metadata_networks(self, datapath, remove=False):
        """Update metadata networks hosted in this chassis.

        Add or remove a datapath from the list of current datapaths that
        we're currently serving metadata.
        """
        current_dps = self.sb_idl.get_chassis_metadata_networks(self.chassis)
        updated = False
        if remove:
            if datapath in current_dps:
                current_dps.remove(datapath)
                updated = True
        else:
            if datapath not in current_dps:
                current_dps.append(datapath)
                updated = True

        if updated:
            with self.sb_idl.create_transaction(check_error=True) as txn:
                txn.add(self.sb_idl.set_chassis_metadata_networks(
                    self.chassis, current_dps))
