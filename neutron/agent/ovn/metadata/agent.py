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
import functools
from random import randint
import re
import threading
import uuid

import netaddr
from neutron_lib import constants as n_const
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import netutils
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import vlog

from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.ovn.metadata import driver as metadata_driver
from neutron.agent.ovn.metadata import ovsdb
from neutron.agent.ovn.metadata import server as metadata_server
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils
from neutron.conf.agent.database import agents_db
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config


LOG = log.getLogger(__name__)
agents_db.register_db_agents_opts()
_SYNC_STATE_LOCK = lockutils.ReaderWriterLock()
CHASSIS_METADATA_LOCK = 'chassis_metadata_lock'

NS_PREFIX = 'ovnmeta-'
MAC_PATTERN = re.compile(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', re.I)
OVN_VIF_PORT_TYPES = ("", "external", ovn_const.LSP_TYPE_LOCALPORT, )

MetadataPortInfo = collections.namedtuple('MetadataPortInfo', ['mac',
                                                               'ip_addresses',
                                                               'logical_port'])

OVN_METADATA_UUID_NAMESPACE = uuid.UUID('d34bf9f6-da32-4871-9af8-15a4626b41ab')


def _sync_lock(f):
    """Decorator to block all operations for a global sync call."""
    @functools.wraps(f)
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
    def __init__(self, metadata_agent, events):
        self.agent = metadata_agent
        table = 'Port_Binding'
        super(PortBindingChassisEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        # Check if the port has been bound/unbound to our chassis and update
        # the metadata namespace accordingly.
        resync = False
        if row.type not in OVN_VIF_PORT_TYPES:
            return
        if row.type == ovn_const.LSP_TYPE_LOCALPORT:
            new_ext_ids = row.external_ids
            old_ext_ids = old.external_ids
            device_id = row.external_ids.get(
                ovn_const.OVN_DEVID_EXT_ID_KEY, "")
            if not device_id.startswith(NS_PREFIX):
                return
            new_cidrs = new_ext_ids.get(ovn_const.OVN_CIDRS_EXT_ID_KEY, "")
            old_cidrs = old_ext_ids.get(ovn_const.OVN_CIDRS_EXT_ID_KEY, "")
            # If old_cidrs is "", it is create event,
            # nothing needs to be done.
            # If old_cidrs equals new_cidrs, the ip does not change.
            if old_cidrs in ("", new_cidrs, ):
                return
        with _SYNC_STATE_LOCK.read_lock():
            try:
                net_name = ovn_utils.get_network_name_from_datapath(
                    row.datapath)
                LOG.info(self.LOG_MSG, row.logical_port, net_name)
                self.agent.provision_datapath(row.datapath)
            except ConfigException:
                # We're now in the reader lock mode, we need to exit the
                # context and then use writer lock
                resync = True
        if resync:
            self.agent.resync()


class PortBindingMetaPortUpdatedEvent(PortBindingChassisEvent):
    LOG_MSG = "Metadata Port %s in datapath %s updated."

    def __init__(self, metadata_agent):
        events = (self.ROW_UPDATE,)
        super(PortBindingMetaPortUpdatedEvent, self).__init__(
            metadata_agent, events)

    def match_fn(self, event, row, old):
        if row.type == ovn_const.LSP_TYPE_LOCALPORT:
            if hasattr(row, 'external_ids') and hasattr(old, 'external_ids'):
                device_id = row.external_ids.get(
                    ovn_const.OVN_DEVID_EXT_ID_KEY, "")
                if device_id.startswith(NS_PREFIX):
                    return True
        return False


class PortBindingChassisCreatedEvent(PortBindingChassisEvent):
    LOG_MSG = "Port %s in datapath %s bound to our chassis"

    def __init__(self, metadata_agent):
        events = (self.ROW_UPDATE,)
        super(PortBindingChassisCreatedEvent, self).__init__(
            metadata_agent, events)

    def match_fn(self, event, row, old):
        try:
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False


class PortBindingChassisDeletedEvent(PortBindingChassisEvent):
    LOG_MSG = "Port %s in datapath %s unbound from our chassis"

    def __init__(self, metadata_agent):
        events = (self.ROW_UPDATE, self.ROW_DELETE)
        super(PortBindingChassisDeletedEvent, self).__init__(
            metadata_agent, events)

    def match_fn(self, event, row, old):
        try:
            if event == self.ROW_UPDATE:
                return (old.chassis[0].name == self.agent.chassis and
                        not row.chassis)
            else:
                if row.chassis[0].name == self.agent.chassis:
                    if row.type != "external":
                        LOG.warning(
                            'Removing non-external type port %(port_id)s with '
                            'type "%(type)s"',
                            {"port_id": row.uuid, "type": row.type})
                    return True
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
        self.first_run = True

    def run(self, event, row, old):

        def _update_chassis(self, row):
            table = ('Chassis_Private' if self.agent.has_chassis_private
                     else 'Chassis')
            self.agent.sb_idl.db_set(
                table, self.agent.chassis, ('external_ids', {
                    ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY:
                        str(row.nb_cfg)})).execute()

        delay = 0
        if self.first_run:
            self.first_run = False
        else:
            # We occasionally see port binding failed errors due to
            # the ml2 driver refusing to bind the port to a dead agent.
            # if all agents heartbeat at the same time, they will all
            # cause a load spike on the server. To mitigate that we
            # need to spread out the load by introducing a random delay.
            # clamp the max delay between 3 and 10 seconds.
            max_delay = max(min(cfg.CONF.agent_down_time // 3, 10), 3)
            delay = randint(0, max_delay)

        LOG.debug("Delaying updating chassis table for %s seconds", delay)
        timer = threading.Timer(delay, _update_chassis, [self, row])
        timer.start()


class MetadataAgent(object):

    def __init__(self, conf):
        self.conf = conf
        vlog.use_python_logger(max_level=config.get_ovn_ovsdb_log_level())
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='metadata')
        self._sb_idl = None
        self._post_fork_event = threading.Event()

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self._post_fork_event.wait()
        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self._sb_idl = val

    def _load_config(self):
        self.chassis = self._get_own_chassis_name()
        try:
            self.chassis_id = uuid.UUID(self.chassis)
        except ValueError:
            # OVS system-id could be a non UUID formatted string.
            self.chassis_id = uuid.uuid5(OVN_METADATA_UUID_NAMESPACE,
                                         self.chassis)
        self.ovn_bridge = self._get_ovn_bridge()
        LOG.debug("Loaded chassis name %s (UUID: %s) and ovn bridge %s.",
                  self.chassis, self.chassis_id, self.ovn_bridge)

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

        tables = ('Encap', 'Port_Binding', 'Datapath_Binding', 'SB_Global',
                  'Chassis')
        events = (PortBindingChassisCreatedEvent(self),
                  PortBindingChassisDeletedEvent(self),
                  SbGlobalUpdateEvent(self),
                  PortBindingMetaPortUpdatedEvent(self))

        # TODO(lucasagomes): Remove this in the future. Try to register
        # the Chassis_Private table, if not present, fallback to the normal
        # Chassis table.
        # Open the connection to OVN SB database.
        self.has_chassis_private = False
        self._post_fork_event.clear()
        try:
            self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
                chassis=self.chassis, tables=tables + ('Chassis_Private', ),
                events=events + (ChassisPrivateCreateEvent(self), )).start()
            self.has_chassis_private = True
        except AssertionError:
            self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
                chassis=self.chassis, tables=tables,
                events=events + (ChassisCreateEvent(self), )).start()

        # Now IDL connections can be safely used.
        self._post_fork_event.set()

        # Launch the server that will act as a proxy between the VM's and Nova.
        self._proxy = metadata_server.UnixDomainMetadataProxy(
            self.conf, self.chassis, sb_idl=self.sb_idl)
        self._proxy.run()

        # Do the initial sync.
        self.sync()

        # Register the agent with its corresponding Chassis
        self.register_metadata_agent()

        self._proxy.wait()

    @ovn_utils.retry()
    def register_metadata_agent(self):
        # NOTE(lucasagomes): db_add() will not overwrite the UUID if
        # it's already set.
        table = ('Chassis_Private' if self.has_chassis_private else 'Chassis')
        # Generate unique, but consistent metadata id for chassis name
        agent_id = uuid.uuid5(self.chassis_id, 'metadata_agent')
        ext_ids = {ovn_const.OVN_AGENT_METADATA_ID_KEY: str(agent_id)}
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

    def get_networks_datapaths(self):
        """Return a set of datapath objects of the VIF ports on the current
        chassis.
        """
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        return set(p.datapath for p in self._vif_ports(ports))

    @_sync_lock
    def sync(self):
        """Agent sync.

        This function will make sure that all networks with ports in our
        chassis are serving metadata. Also, it will tear down those namespaces
        which were serving metadata but are no longer needed.
        """

        # first, clean up namespaces that should no longer deploy
        system_namespaces = tuple(
            ns.decode('utf-8') if isinstance(ns, bytes) else ns
            for ns in ip_lib.list_network_namespaces())
        net_datapaths = self.get_networks_datapaths()
        metadata_namespaces = [
            self._get_namespace_name(
                ovn_utils.get_network_name_from_datapath(datapath))
            for datapath in net_datapaths
        ]
        unused_namespaces = [ns for ns in system_namespaces if
                             ns.startswith(NS_PREFIX) and
                             ns not in metadata_namespaces]
        for ns in unused_namespaces:
            self.teardown_datapath(self._get_datapath_name(ns))

        # resync all network namespaces based on the associated datapaths,
        # even those that are already running. This is to make sure
        # everything within each namespace is up to date.
        for datapath in net_datapaths:
            self.provision_datapath(datapath)

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

    def teardown_datapath(self, net_name):
        """Unprovision this datapath to stop serving metadata.

        This function will shutdown metadata proxy if it's running and delete
        the VETH pair, the OVS port and the namespace.
        """
        namespace = self._get_namespace_name(net_name)
        ip = ip_lib.IPWrapper(namespace)
        # If the namespace doesn't exist, return
        if not ip.netns.exists(namespace):
            return

        LOG.info("Cleaning up %s namespace which is not needed anymore",
                 namespace)

        metadata_driver.MetadataDriver.destroy_monitored_metadata_proxy(
            self._process_monitor, net_name, self.conf, namespace)

        veth_name = self._get_veth_name(net_name)
        self.ovs_idl.del_port(veth_name[0]).execute()
        if ip_lib.device_exists(veth_name[0]):
            ip_lib.IPWrapper().del_veth(veth_name[0])

        ip.garbage_collect_namespace()

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
            use_ipv6=netutils.is_ipv6_enabled(), nat=False,
            namespace=namespace, external_lock=False)
        rule = '-p tcp -m tcp -j CHECKSUM --checksum-fill'
        iptables_mgr.ipv4['mangle'].add_rule('POSTROUTING', rule, wrap=False)
        iptables_mgr.apply()

    def _get_port_ips(self, port):
        # Retrieve IPs from the port mac column which is in form
        # ["<port_mac> <ip1> <ip2> ... <ipN>"]
        if not port.mac:
            LOG.warning("Port %s MAC column is empty, cannot retrieve IP "
                        "addresses", port.uuid)
            return []
        mac_field_attrs = port.mac[0].split()
        ips = mac_field_attrs[1:]
        if not ips:
            LOG.debug("Port %s IP addresses were not retrieved from the "
                      "Port_Binding MAC column %s", port.uuid, mac_field_attrs)
        return ips

    def _active_subnets_cidrs(self, datapath_ports_ips, metadata_port_cidrs):
        active_subnets_cidrs = set()
        # Prepopulate a dictionary where each metadata_port_cidr(string) maps
        # to its netaddr.IPNetwork object. This is so we dont have to
        # reconstruct IPNetwork objects repeatedly in the for loop
        metadata_cidrs_to_network_objects = {
            metadata_port_cidr: netaddr.IPNetwork(metadata_port_cidr)
            for metadata_port_cidr in metadata_port_cidrs
        }

        for datapath_port_ip in datapath_ports_ips:
            ip_obj = netaddr.IPAddress(datapath_port_ip)
            for metadata_cidr, metadata_cidr_obj in \
                    metadata_cidrs_to_network_objects.items():
                if ip_obj in metadata_cidr_obj:
                    active_subnets_cidrs.add(metadata_cidr)
                    break
        return active_subnets_cidrs

    def _process_cidrs(self, current_namespace_cidrs,
                       datapath_ports_ips, metadata_port_subnet_cidrs):
        active_subnets_cidrs = self._active_subnets_cidrs(
            datapath_ports_ips, metadata_port_subnet_cidrs)

        cidrs_to_add = active_subnets_cidrs - current_namespace_cidrs

        if n_const.METADATA_CIDR not in current_namespace_cidrs:
            cidrs_to_add.add(n_const.METADATA_CIDR)
        else:
            active_subnets_cidrs.add(n_const.METADATA_CIDR)

        cidrs_to_delete = current_namespace_cidrs - active_subnets_cidrs

        return cidrs_to_add, cidrs_to_delete

    def _get_provision_params(self, datapath):
        """Performs datapath preprovision checks and returns paremeters
        needed to provision namespace.

        Function will confirm that:
        1. Datapath metadata port has valid MAC and subnet CIDRs
        2. There are datapath port IPs

        If any of those rules are not valid the nemaspace for the
        provided datapath will be tore down.
        If successful, returns datapath's network name, ports IPs
        and meta port info
        """
        net_name = ovn_utils.get_network_name_from_datapath(datapath)
        datapath_uuid = str(datapath.uuid)

        metadata_port = self.sb_idl.get_metadata_port_network(datapath_uuid)
        # If there's no metadata port or it doesn't have a MAC or IP
        # addresses, then tear the namespace down if needed. This might happen
        # when there are no subnets yet created so metadata port doesn't have
        # an IP address.
        if not (metadata_port and metadata_port.mac and
                metadata_port.external_ids.get(
                    ovn_const.OVN_CIDRS_EXT_ID_KEY, None)):
            LOG.debug("There is no metadata port for network %s or it has no "
                      "MAC or IP addresses configured, tearing the namespace "
                      "down if needed", net_name)
            self.teardown_datapath(net_name)
            return

        # First entry of the mac field must be the MAC address.
        match = MAC_PATTERN.match(metadata_port.mac[0].split(' ')[0])
        if not match:
            LOG.error("Metadata port for network %s doesn't have a MAC "
                      "address, tearing the namespace down if needed",
                      net_name)
            self.teardown_datapath(net_name)
            return

        mac = match.group()
        ip_addresses = set(
            metadata_port.external_ids[
                ovn_const.OVN_CIDRS_EXT_ID_KEY].split(' '))
        metadata_port_info = MetadataPortInfo(mac, ip_addresses,
                                              metadata_port.logical_port)

        chassis_ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        datapath_ports_ips = []
        for chassis_port in self._vif_ports(chassis_ports):
            if str(chassis_port.datapath.uuid) == datapath_uuid:
                datapath_ports_ips.extend(self._get_port_ips(chassis_port))

        if not datapath_ports_ips:
            LOG.debug("No valid VIF ports were found for network %s, "
                      "tearing the namespace down if needed", net_name)
            self.teardown_datapath(net_name)
            return

        return net_name, datapath_ports_ips, metadata_port_info

    def provision_datapath(self, datapath):
        """Provision the datapath so that it can serve metadata.

        This function will create the namespace and VETH pair if needed
        and assign the IP addresses to the interface corresponding to the
        metadata port of the network. It will also remove existing IP from
        the namespace if they are no longer needed.

        :param datapath: datapath object.
        :return: The metadata namespace name for the datapath or None
                 if namespace was not provisioned
        """

        provision_params = self._get_provision_params(datapath)
        if not provision_params:
            return
        net_name, datapath_ports_ips, metadata_port_info = provision_params

        LOG.info("Provisioning metadata for network %s", net_name)
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
        ip2.link.set_address(metadata_port_info.mac)

        cidrs_to_add, cidrs_to_delete = self._process_cidrs(
            {dev['cidr'] for dev in ip2.addr.list()},
            datapath_ports_ips,
            metadata_port_info.ip_addresses
        )
        # Delete any non active addresses from the network namespace
        if cidrs_to_delete:
            ip2.addr.delete_multiple(list(cidrs_to_delete))

        # NOTE(dalvarez): metadata only works on IPv4. We're doing this
        # extra check here because it could be that the metadata port has
        # an IPv6 address if there's an IPv6 subnet with SLAAC in its
        # network. Neutron IPAM will autoallocate an IPv6 address for every
        # port in the network.
        ipv4_cidrs_to_add = [
            cidr
            for cidr in cidrs_to_add
            if utils.get_ip_version(cidr) == n_const.IP_VERSION_4]

        if ipv4_cidrs_to_add:
            ip2.addr.add_multiple(ipv4_cidrs_to_add)

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
            ('external_ids', {'iface-id':
                              metadata_port_info.logical_port})).execute()

        # Ensure the correct checksum in the metadata traffic.
        self._ensure_datapath_checksum(namespace)

        # Spawn metadata proxy if it's not already running.
        metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
            self._process_monitor, namespace, n_const.METADATA_PORT,
            self.conf, bind_address=n_const.METADATA_V4_IP,
            network_id=net_name)
