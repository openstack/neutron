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

import abc
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
from neutron.agent.ovn.agent import ovn_neutron_agent
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

NS_PREFIX = ovn_const.OVN_METADATA_PREFIX
MAC_PATTERN = re.compile(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', re.I)
OVN_VIF_PORT_TYPES = (
    "", ovn_const.LSP_TYPE_EXTERNAL, ovn_const.LSP_TYPE_LOCALPORT)

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


# TODO(jlibosva): Remove the decorator after we depend on OVN version that has
# the schema containing the additional_chassis column
def _match_only_if_additional_chassis_is_supported(f):
    @functools.wraps(f)
    def wrapped(self, row, old):
        if not hasattr(row, 'additional_chassis'):
            return False
        return f(self, row, old)
    return wrapped


class ConfigException(Exception):
    """Misconfiguration of the agent

    This exception is raised when agent detects its wrong configuration.
    Typically agent should resync when this is raised.
    """


class _OVNExtensionEvent(metaclass=abc.ABCMeta):
    """Implements a method to retrieve the correct caller agent

    The events inheriting from this class could be called from the OVN metadata
    agent or as part of an extension of the OVN agent ("metadata" extension,
    for example). In future releases, the OVN metadata agent will be superseded
    by the OVN agent (with the "metadata" extension) and this class removed,
    keeping only the compatibility with the OVN agent (to be removed in C+2).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._agent_or_extension = None
        self._agent = None

    @property
    def agent(self):
        """This method provide support for the OVN agent

        This event can be used in the OVN metadata agent and in the OVN
        agent metadata extension.
        """
        if not self._agent_or_extension:
            if isinstance(self._agent, ovn_neutron_agent.OVNNeutronAgent):
                self._agent_or_extension = self._agent['metadata']
            else:
                self._agent_or_extension = self._agent
        return self._agent_or_extension


class PortBindingEvent(_OVNExtensionEvent, row_event.RowEvent):
    def __init__(self, agent):
        table = 'Port_Binding'
        super().__init__((self.__class__.EVENT,), table, None)
        self._agent = agent
        self.event_name = self.__class__.__name__
        self._log_msg = (
            "PortBindingEvent matched for logical port %s and network %s")

    def log_row(self, row):
        net_name = ovn_utils.get_network_name_from_datapath(
            row.datapath)
        LOG.info(self._log_msg, row.logical_port, net_name)

    def match_fn(self, event, row, old):
        return row.type in OVN_VIF_PORT_TYPES

    def run(self, event, row, old):
        # Check if the port has been bound/unbound to our chassis and update
        # the metadata namespace accordingly.
        resync = False

        with _SYNC_STATE_LOCK.read_lock():
            self.log_row(row)
            try:
                self.agent.provision_datapath(row)
            except ConfigException:
                # We're now in the reader lock mode, we need to exit the
                # context and then use writer lock
                resync = True
        if resync:
            self.agent.resync()


class PortBindingCreateWithChassis(PortBindingEvent):
    EVENT = PortBindingEvent.ROW_CREATE

    def match_fn(self, event, row, old):
        self._log_msg = "Port %s in datapath %s bound to our chassis on insert"
        if not (super().match_fn(event, row, old) and row.chassis):
            return False
        return row.chassis[0].name == self.agent.chassis


class PortBindingUpdatedEvent(PortBindingEvent):
    EVENT = PortBindingEvent.ROW_UPDATE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._match_checks = [
            self._is_localport_ext_ids_update,
            self._is_new_chassis_set,
            self._is_chassis_removed,
            self._additional_chassis_added,
            self._additional_chassis_removed,
        ]

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False
        # if any of the check functions is true, the event should be triggered
        return any(check(row, old) for check in self._match_checks)

    def _is_localport_ext_ids_update(self, row, old):
        if row.type != ovn_const.LSP_TYPE_LOCALPORT:
            return False

        if not hasattr(old, 'external_ids'):
            return False

        device_id = row.external_ids.get(
            ovn_const.OVN_DEVID_EXT_ID_KEY, "")
        if not device_id.startswith(NS_PREFIX):
            return False

        new_cidrs = row.external_ids.get(
            ovn_const.OVN_CIDRS_EXT_ID_KEY, "")
        old_cidrs = old.external_ids.get(
            ovn_const.OVN_CIDRS_EXT_ID_KEY, "")
        # If old_cidrs is "", it is create event,
        # nothing needs to be done.
        # If old_cidrs equals new_cidrs, the ip does not change.
        if old_cidrs not in ("", new_cidrs):
            self._log_msg = (
                "Metadata Port %s in datapath %s updated")
            return True
        return False

    def _is_new_chassis_set(self, row, old):
        self._log_msg = "Port %s in datapath %s bound to our chassis"
        try:
            # TODO(jlibosva): Remove the check after we depend on OVN version
            # that has the schema containing the additional_chassis column
            if hasattr(row, 'additional_chassis'):
                try:
                    # If the additional chassis used to be in the old version
                    # the resources are already provisioned
                    if self.agent.chassis in {c.name for c in
                                              old.additional_chassis}:
                        return False
                except AttributeError:
                    pass
            return (row.chassis[0].name == self.agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False

    def _is_chassis_removed(self, row, old):
        self._log_msg = "Port %s in datapath %s unbound from our chassis"
        try:
            return (old.chassis[0].name == self.agent.chassis and
                    not row.chassis)
        except (IndexError, AttributeError):
            return False

    @_match_only_if_additional_chassis_is_supported
    def _additional_chassis_added(self, row, old):
        # Additional chassis of the target node is set during an instance
        # live migration. We can provision resources early before the
        # instance lands on this chassis. After the VM finishes live
        # migration, it already has the resources provisioned therefore we
        # do not need to check when the chassis is moved from
        # the Additional_Chassis column to the Chassis column.
        additional_chassis = {ch for ch in row.additional_chassis
                              if ch.name == self.agent.chassis}
        self.log_msg = (
            "Live migrating port %s from network %s was added to this "
            "chassis. Provisioning resources early.")
        try:
            # Return True if the agent chassis was added to additional_chassis
            # column
            return bool(
                additional_chassis.difference(old.additional_chassis))
        except AttributeError:
            # If additional_chassis column was not changed then the old object
            # raises AttributeError when reading the column
            return False

    @_match_only_if_additional_chassis_is_supported
    def _additional_chassis_removed(self, row, old):
        # The method needs to check only for a case when agent chassis was set
        # in additional_chassis column, was removed but at the same time the
        # agent chassis was not set to chassis column. If the agent chassis is
        # set to chassis then it means live migration was successful and we do
        # not need to teardown the resources.
        try:
            old_a_chassis = {ch for ch in old.additional_chassis
                             if ch.name == self.agent.chassis}
        except AttributeError:
            # If additional chassis was not updated, the old object has no
            # additional_chassis attribute and raises an AttributeError
            return False

        # If was changed to the agent chassis then we do not need to teardown
        # the resources
        try:
            if (hasattr(old, 'chassis') and
                    row.chassis[0].name == self.agent.chassis):
                return False
        except IndexError:
            pass
        # We match the event only if the agent chassis was in the old
        # additional_chassis column and was removed
        return bool(old_a_chassis.difference(row.additional_chassis))


class PortBindingDeletedEvent(PortBindingEvent):
    EVENT = PortBindingEvent.ROW_DELETE

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False
        try:
            if row.chassis[0].name != self.agent.chassis:
                return False
        except (IndexError, AttributeError):
            return False
        if row.type != ovn_const.LSP_TYPE_EXTERNAL:
            LOG.warning(
                'Removing non-external type port %(port_id)s with '
                'type "%(type)s"',
                {"port_id": row.uuid, "type": row.type})
        self._log_msg = (
            "Port %s in datapath %s unbound from our chassis")
        return True


class ChassisPrivateCreateEvent(_OVNExtensionEvent, row_event.RowEvent):
    """Row create event - Chassis name == our_chassis.

    On connection, we get a dump of all chassis so if we catch a creation
    of our own chassis it has to be a reconnection. In this case, we need
    to do a full sync to make sure that we capture all changes while the
    connection to OVSDB was down.
    """
    def __init__(self, agent):
        self._extension = None
        self.first_time = True
        events = (self.ROW_CREATE,)
        super().__init__(events, 'Chassis_Private', None)
        # NOTE(ralonsoh): ``self._agent`` needs to be assigned before being
        # used in the property ``self.agent``.
        self._agent = agent
        self.conditions = (('name', '=', self.agent.chassis),)
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


class SbGlobalUpdateEvent(_OVNExtensionEvent, row_event.RowEvent):
    """Row update event on SB_Global table."""

    def __init__(self, agent):
        table = 'SB_Global'
        events = (self.ROW_UPDATE,)
        super(SbGlobalUpdateEvent, self).__init__(events, table, None)
        self._agent = agent
        self.event_name = self.__class__.__name__
        self.first_run = True

    def run(self, event, row, old):

        def _update_chassis(self, row):
            self.agent.sb_idl.db_set(
                'Chassis_Private', self.agent.chassis, ('external_ids', {
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
        self._conf = conf
        vlog.use_python_logger(max_level=config.get_ovn_ovsdb_log_level())
        self._process_monitor = external_process.ProcessMonitor(
            config=self._conf,
            resource_type='metadata')
        self._sb_idl = None
        self._post_fork_event = threading.Event()
        self._chassis = None

    @property
    def conf(self):
        return self._conf

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self._post_fork_event.wait()
        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self._sb_idl = val

    @property
    def chassis(self):
        return self._chassis

    @property
    def chassis_id(self):
        return self._chassis_id

    @property
    def ovn_bridge(self):
        return self._ovn_bridge

    def _load_config(self):
        self._chassis = self._get_own_chassis_name()
        try:
            self._chassis_id = uuid.UUID(self._chassis)
        except ValueError:
            # OVS system-id could be a non UUID formatted string.
            self._chassis_id = uuid.uuid5(OVN_METADATA_UUID_NAMESPACE,
                                          self._chassis)
        self._ovn_bridge = self._get_ovn_bridge()
        LOG.debug("Loaded chassis name %s (UUID: %s) and ovn bridge %s.",
                  self.chassis, self.chassis_id, self.ovn_bridge)

    def _update_chassis_private_config(self):
        """Update the Chassis_Private register information

        This method should be called once the Metadata Agent has been
        registered (method ``register_metadata_agent`` has been called) and
        the corresponding Chassis_Private register has been created/updated.
        """
        external_ids = {ovn_const.OVN_AGENT_OVN_BRIDGE: self.ovn_bridge}
        self.sb_idl.db_set(
            'Chassis_Private', self.chassis,
            ('external_ids', external_ids)).execute(check_error=True)

    @_sync_lock
    def resync(self):
        """Resync the agent.

        Reload the configuration and sync the agent again.
        """
        self._load_config()
        self._update_chassis_private_config()
        self.sync()

    def start(self):
        # Open the connection to OVS database
        self.ovs_idl = ovsdb.MetadataAgentOvsIdl().start()
        self._load_config()

        tables = ('Encap', 'Port_Binding', 'Datapath_Binding', 'SB_Global',
                  'Chassis', 'Chassis_Private')
        events = (PortBindingUpdatedEvent(self),
                  PortBindingCreateWithChassis(self),
                  PortBindingDeletedEvent(self),
                  SbGlobalUpdateEvent(self),
                  ChassisPrivateCreateEvent(self),
                  )

        self._post_fork_event.clear()
        self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
            chassis=self._chassis, tables=tables, events=events).start()

        # Now IDL connections can be safely used.
        self._post_fork_event.set()

        # Launch the server that will act as a proxy between the VM's and Nova.
        self._proxy = metadata_server.UnixDomainMetadataProxy(
            self.conf, self._chassis, sb_idl=self.sb_idl)
        self._proxy.run()

        # Do the initial sync.
        # Provisioning handled by PortBindingCreateWithChassis
        self.sync(provision=False)

        # Register the agent with its corresponding Chassis
        self.register_metadata_agent()
        self._update_chassis_private_config()

        self._proxy.wait()

    @ovn_utils.retry()
    def register_metadata_agent(self):
        # NOTE(lucasagomes): db_add() will not overwrite the UUID if
        # it's already set.
        # Generate unique, but consistent metadata id for chassis name
        agent_id = uuid.uuid5(self.chassis_id, 'metadata_agent')
        ext_ids = {ovn_const.OVN_AGENT_METADATA_ID_KEY: str(agent_id)}
        self.sb_idl.db_add('Chassis_Private', self.chassis, 'external_ids',
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

    def get_networks_port_bindings(self):
        """Return a set of Port_Binding objects of the VIF ports on the current
        chassis.
        """
        ports = self.sb_idl.get_ports_on_chassis(
            self.chassis, include_additional_chassis=True)
        return list(self._vif_ports(ports))

    @_sync_lock
    def sync(self, provision=True):
        """Agent sync.

        This function will make sure that all networks with ports in our
        chassis are serving metadata. Also, it will tear down those namespaces
        which were serving metadata but are no longer needed.
        """

        # first, clean up namespaces that should no longer deploy
        system_namespaces = tuple(
            ns.decode('utf-8') if isinstance(ns, bytes) else ns
            for ns in ip_lib.list_network_namespaces())
        net_port_bindings = self.get_networks_port_bindings()
        metadata_namespaces = set(
            self._get_namespace_name(
                ovn_utils.get_network_name_from_datapath(datapath))
            for datapath in (pb.datapath for pb in net_port_bindings)
        )
        unused_namespaces = [ns for ns in system_namespaces if
                             ns.startswith(NS_PREFIX) and
                             ns not in metadata_namespaces]
        for ns in unused_namespaces:
            try:
                self.teardown_datapath(self._get_datapath_name(ns))
            except Exception:
                LOG.exception('Error unable to destroy namespace: %s', ns)

        # resync all network namespaces based on the associated datapaths,
        # even those that are already running. This is to make sure
        # everything within each namespace is up to date.
        if provision:
            for port_binding in net_port_bindings:
                self.provision_datapath(port_binding)

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

    def _get_port_ip4_ips_and_ip6_flag(self, port):
        # Retrieve IPv4 addresses from the port mac column which is in form
        # ["<port_mac> <ip1> <ip2> ... <ipN>"]. Also return True if the port
        # has at least one IPv6 address
        if not port.mac:
            LOG.warning("Port %s MAC column is empty, cannot retrieve IP "
                        "addresses", port.uuid)
            return []
        mac_field_attrs = port.mac[0].split()
        ips = mac_field_attrs[1:]
        if not ips:
            LOG.debug("Port %s IP addresses were not retrieved from the "
                      "Port_Binding MAC column %s", port.uuid, mac_field_attrs)
        ip4_ips = []
        any_ip6 = False
        for ip in ips:
            if utils.get_ip_version(ip) == n_const.IP_VERSION_4:
                ip4_ips.append(ip)
            else:
                any_ip6 = True
        return ip4_ips, any_ip6

    def _active_subnets_cidrs(self, datapath_ports_ip4_ips,
                              metadata_port_cidrs):
        active_subnets_cidrs = set()
        # Prepopulate a dictionary where each metadata_port_cidr(string) maps
        # to its netaddr.IPNetwork object. This is so we dont have to
        # reconstruct IPNetwork objects repeatedly in the for loop
        metadata_cidrs_to_network_objects = {
            metadata_port_cidr: netaddr.IPNetwork(metadata_port_cidr)
            for metadata_port_cidr in metadata_port_cidrs if metadata_port_cidr
        }

        for datapath_port_ip in datapath_ports_ip4_ips:
            ip_obj = netaddr.IPAddress(datapath_port_ip)
            for metadata_cidr, metadata_cidr_obj in \
                    metadata_cidrs_to_network_objects.items():
                if ip_obj in metadata_cidr_obj:
                    active_subnets_cidrs.add(metadata_cidr)
                    break
        return active_subnets_cidrs

    def _process_cidrs(self, current_namespace_cidrs,
                       datapath_ports_ip4_ips,
                       metadata_port_subnet_cidrs, lla):
        active_subnets_cidrs = self._active_subnets_cidrs(
            datapath_ports_ip4_ips, metadata_port_subnet_cidrs)

        cidrs_to_add = active_subnets_cidrs - current_namespace_cidrs

        # If we were given an IPv6 link-local to configure, add it and the
        # IPv6 metadata address.
        metadata_cidrs = [n_const.METADATA_CIDR]
        if lla and netutils.is_ipv6_enabled():
            metadata_cidrs.extend([n_const.METADATA_V6_CIDR, lla])

        # Make sure that all required addresses are present
        for addr in metadata_cidrs:
            if addr not in current_namespace_cidrs:
                cidrs_to_add.add(addr)
            else:
                active_subnets_cidrs.add(addr)

        cidrs_to_delete = current_namespace_cidrs - active_subnets_cidrs

        return cidrs_to_add, cidrs_to_delete

    def _get_provision_params(self, datapath):
        """Performs datapath preprovision checks and returns paremeters
        needed to provision namespace.

        Function will confirm that:
        1. Datapath metadata port has valid MAC
        2. There are datapath port IPs

        If any of those rules are not valid the nemaspace for the
        provided datapath will be tore down.
        If successful, returns datapath's network name, ports IPs
        and meta port info
        """
        net_name = ovn_utils.get_network_name_from_datapath(datapath)
        datapath_uuid = str(datapath.uuid)

        metadata_port = self.sb_idl.get_metadata_port_network(datapath_uuid)
        # If there's no metadata port or it doesn't have a MAC address, then
        # tear the namespace down if needed.
        if not (metadata_port and metadata_port.mac):
            LOG.debug("There is no metadata port for network %s or it has no "
                      "MAC address configured, tearing the namespace "
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

        chassis_ports = self.sb_idl.get_ports_on_chassis(
            self._chassis, include_additional_chassis=True)
        datapath_ports_ip4_ips = []
        any_ip6 = False
        for chassis_port in self._vif_ports(chassis_ports):
            if str(chassis_port.datapath.uuid) == datapath_uuid:
                ip4_ips, ip6_flag = self._get_port_ip4_ips_and_ip6_flag(
                    chassis_port)
                datapath_ports_ip4_ips.extend(ip4_ips)
                any_ip6 = any_ip6 or ip6_flag

        if not (datapath_ports_ip4_ips or any_ip6):
            LOG.debug("No valid VIF ports were found for network %s, "
                      "tearing the namespace down if needed", net_name)
            self.teardown_datapath(net_name)
            return

        return net_name, datapath_ports_ip4_ips, any_ip6, metadata_port_info

    def provision_datapath(self, port_binding):
        """Provision the datapath so that it can serve metadata.

        This function will create the namespace and VETH pair if needed
        and assign the IP addresses to the interface corresponding to the
        metadata port of the network. It will also remove existing IP from
        the namespace if they are no longer needed.

        :param port_binding: Port_Binding object.
        :return: The metadata namespace name for the Port_Binding.datapath or
                 None if namespace was not provisioned
        """
        datapath = port_binding.datapath
        mtu = int(port_binding.external_ids.get(
            ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY) or '0')
        provision_params = self._get_provision_params(datapath)
        if not provision_params:
            return
        net_name, datapath_ports_ip4_ips, any_ip6, metadata_port_info = (
            provision_params)

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

        # Configure the MAC address.
        ip2.link.set_address(metadata_port_info.mac)

        # Set VETH ports MTU.
        if mtu:
            ip1.link.set_mtu(mtu)
            ip2.link.set_mtu(mtu)

        # Make sure both ends of the VETH are up
        ip1.link.set_up()
        ip2.link.set_up()

        # If there is an IPv6 address configured on the port, pass the LLA
        # to be configured to _process_cidrs()
        lla = None
        if any_ip6:
            lla = ip_lib.get_ipv6_lladdr(metadata_port_info.mac)
        cidrs_to_add, cidrs_to_delete = self._process_cidrs(
            {dev['cidr'] for dev in ip2.addr.list()},
            datapath_ports_ip4_ips,
            metadata_port_info.ip_addresses,
            lla
        )

        # Delete any non active addresses from the network namespace
        if cidrs_to_delete:
            ip2.addr.delete_multiple(list(cidrs_to_delete))

        if cidrs_to_add:
            ip2.addr.add_multiple(list(cidrs_to_add))

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

        # Only if IPv6 is enabled should we listen on the IPv6 metadata
        # address, same as the dhcp-agent does
        bind_address_v6 = None
        if lla and netutils.is_ipv6_enabled():
            bind_address_v6 = n_const.METADATA_V6_IP

        # Spawn metadata proxy if it's not already running.
        metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
            self._process_monitor, namespace, n_const.METADATA_PORT,
            self.conf, bind_address=n_const.METADATA_V4_IP,
            network_id=net_name, bind_address_v6=bind_address_v6,
            bind_interface=veth_name[1])
