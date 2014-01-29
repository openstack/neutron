# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading
import time

import jsonrpclib
from oslo.config import cfg

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers.mech_arista import config  # noqa
from neutron.plugins.ml2.drivers.mech_arista import db
from neutron.plugins.ml2.drivers.mech_arista import exceptions as arista_exc

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')

class AristaNetwork(object):
   def __init__(self, network_id='', segmentation_id='', network_name=''):
      self.network_id = network_id
      self.segmentation_id = segmentation_id
      self.network_name = network_name

class AristaRPCWrapper(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self):
        self._server = jsonrpclib.Server(self._eapi_host_url())
        self.keystone_conf = cfg.CONF.keystone_authtoken
        self.region = cfg.CONF.ml2_arista.region_name
        self._region_updated_time = None

    def _keystone_url(self):
        keystone_auth_url = ('%s://%s:%s/v2.0/' %
                             (self.keystone_conf.auth_protocol,
                              self.keystone_conf.auth_host,
                              self.keystone_conf.auth_port))
        return keystone_auth_url

    def get_tenants(self):
        """Returns dict of all tenants known by EOS.

        :returns: dictionary containing the networks per tenant
                  and VMs allocated per tenant
        """
        cmds = ['show openstack config region %s' % self.region]
        command_output = self._run_openstack_cmds(cmds,cmds)
        tenants = command_output[0]['tenants']

        return tenants

    def plug_port_into_network(self, vm_id, host_id, port_id,
                               net_id, tenant_id, port_name, device_owner):
        """Genric routine plug a port of a VM instace into network.

        :param vm_id: globally unique identifier for VM instance
        :param host: ID of the host where the VM is placed
        :param port_id: globally unique port ID that connects VM to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        :param device_owner: Device owner - e.g. compute or network:dhcp
        """
        if device_owner == n_const.DEVICE_OWNER_DHCP:
            self.plug_dhcp_port_into_network(vm_id,
                                             host_id,
                                             port_id,
                                             net_id,
                                             tenant_id,
                                             port_name)
        elif device_owner.startswith('compute'):
            self.plug_host_into_network(vm_id,
                                        host_id,
                                        port_id,
                                        net_id,
                                        tenant_id,
                                        port_name)

    def plug_host_into_network(self, vm_id, host, port_id,
                               network_id, tenant_id, port_name):
        """Creates VLAN between TOR and compute host.

        :param vm_id: globally unique identifier for VM instance
        :param host: ID of the host where the VM is placed
        :param port_id: globally unique port ID that connects VM to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        """
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host)]
        if port_name:
            cmds.append('port id %s name "%s" network-id %s' %
                        (port_id, port_name, network_id))
        else:
            cmds.append('port id %s network-id %s' %
                        (port_id, network_id))
        cmds.append('exit')
        cmds.append('exit')
        self._run_openstack_config_cmds(cmds)

    def plug_dhcp_port_into_network(self, dhcp_id, host, port_id,
                                    network_id, tenant_id, port_name):
        """Creates VLAN between TOR and dhcp host.

        :param dhcp_id: globally unique identifier for dhcp
        :param host: ID of the host where the dhcp is hosted
        :param port_id: globally unique port ID that connects dhcp to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        :param port_name: Name of the port - for display purposes
        """
        cmds = ['tenant %s' % tenant_id,
                'network id %s' % network_id]
        if port_name:
            cmds.append('dhcp id %s hostid %s port-id %s name "%s"' %
                        (dhcp_id, host, port_id, port_name))
        else:
            cmds.append('dhcp id %s hostid %s port-id %s' %
                        (dhcp_id, host, port_id))
        cmds.append('exit')
        self._run_openstack_config_cmds(cmds)

    def unplug_host_from_network(self, vm_id, host, port_id,
                                 network_id, tenant_id):
        """Removes previously configured VLAN between TOR and a host.

        :param vm_id: globally unique identifier for VM instance
        :param host: ID of the host where the VM is placed
        :param port_id: globally unique port ID that connects VM to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        """
        cmds = ['tenant %s' % tenant_id,
                'vm id %s hostid %s' % (vm_id, host),
                'no port id %s' % port_id,
                'exit',
                'exit']
        self._run_openstack_config_cmds(cmds)

    def unplug_dhcp_port_from_network(self, dhcp_id, host, port_id,
                                      network_id, tenant_id):
        """Removes previously configured VLAN between TOR and a dhcp host.

        :param dhcp_id: globally unique identifier for dhcp
        :param host: ID of the host where the dhcp is hosted
        :param port_id: globally unique port ID that connects dhcp to network
        :param network_id: globally unique neutron network identifier
        :param tenant_id: globally unique neutron tenant identifier
        """
        cmds = ['tenant %s' % tenant_id,
                'network id %s' % network_id,
                'no dhcp id %s port-id %s' % (dhcp_id, port_id),
                'exit']
        self._run_openstack_config_cmds(cmds)

    def create_networks(self, tenant_id, network_list ):
        """Creates a network on Arista Hardware

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        :param network_name: Network name - for display purposes
        :param seg_id: Segment ID of the network
        """
        cmds = ['tenant %s' % tenant_id]
        # Create a reference to function to avoid name lookups in the loop
        append_cmd = cmds.append
        for network in network_list:
           if network.network_name:
               append_cmd('network id %s name "%s"' %
                           (network.network_id, network.network_name))
           else:
               append_cmd('network id %s' % network.network_id)
           append_cmd('segment 1 type vlan id %d' % network.segmentation_id)
        append_cmd( 'exit' )
        append_cmd( 'exit' )

        self._run_openstack_config_cmds(cmds)

    def create_network_segments(self, tenant_id, network_id,
                                network_name, segments):
        """Creates a network on Arista Hardware

        Note: This method is not used at the moment. create_networks()
        is used instead. This will be used once the support for
        multiple segments is added in Neutron.

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        :param network_name: Network name - for display purposes
        :param segments: List of segments in a given network
        """
        if segments:
            cmds = ['tenant %s' % tenant_id,
                    'network id %s name "%s"' % (network_id, network_name)]
            seg_num = 1
            for seg in segments:
                cmds.append('segment %d type %s id %d' % (seg_num,
                            seg['network_type'], seg['segmentation_id']))
                seg_num += 1
            cmds.append('exit')  # exit for segment mode
            cmds.append('exit')  # exit for network mode
            cmds.append('exit')  # exit for tenant mode

            self._run_openstack_config_cmds(cmds)

    def delete_networks(self, tenant_id, network_id_list):
        """Deletes a specified network for a given tenant

        :param tenant_id: globally unique neutron tenant identifier
        :param network_id: globally unique neutron network identifier
        """
        cmds = ['tenant %s' % tenant_id ]
        for network_id in network_id_list:
            cmds.append( 'no network id %s' % network_id )
        cmds.append( 'exit' )
        cmds.append( 'exit' )
        self._run_openstack_config_cmds(cmds)

    def delete_vms(self, tenant_id, vm_id_list):
        """Deletes a VM from EOS for a given tenant

        :param tenant_id : globally unique neutron tenant identifier
        :param vm_id : id of a VM that needs to be deleted.
        """
        cmds = ['tenant %s' % tenant_id]
        for vm_id in vm_id_list:
            cmds.append( 'no vm id %s' % vm_id )
        cmds.append( 'exit' )
        cmds.append( 'exit' )
        self._run_openstack_config_cmds(cmds)

    def create_vm_ports(self, tenant_id, vm_port_list, vms):
       cmds = ['tenant %s' % tenant_id]
       # Create a reference to function to avoid name lookups in the loop
       append_cmd = cmds.append
       for port in vm_port_list:
          port_name = ''
          try:
             port_name = 'name "%s"' % port['name']
          except KeyError:
             port_name = ''

          vm = vms[port['device_id']]
          if port['device_owner'] == n_const.DEVICE_OWNER_DHCP:
             append_cmd( 'network id %s' % port['network_id'] )
             append_cmd( 'dhcp id %s hostid %s port-id %s %s' %
                          (vm['vmId'], vm['host'], port['id'], port_name) )
          elif port['device_owner'].startswith('compute'):
             append_cmd('vm id %s hostid %s' % (vm['vmId'], vm['host']) )
             append_cmd('port id %s %s network-id %s' %
                         (port['id'], port_name, port['network_id']))
          else:
             continue
       append_cmd('exit')
       self._run_openstack_config_cmds(cmds)

    def delete_tenant(self, tenant_id):
        """Deletes a given tenant and all its networks and VMs from EOS.

        :param tenant_id: globally unique neutron tenant identifier
        """
        self.delete_tenants([tenant_id])

    def delete_tenants(self, tenant_list):
        cmds = []
        for tenant in tenant_list:
           cmds.append('no tenant %s' % tenant)
        cmds.append('exit')
        self._run_openstack_config_cmds(cmds)

    def register_with_eos(self):
        """This is the registration request with EOS.

        This the initial handshake between Neutron and EOS.
        critical end-point information is registered with EOS.
        """
        cmds = ['auth url %s user %s password %s' %
                (self._keystone_url(),
                self.keystone_conf.admin_user,
                self.keystone_conf.admin_password)]

        log_cmds = ['auth url %s user %s password ******' %
                     (self._keystone_url(),
                     self.keystone_conf.admin_user)]

        self._run_openstack_config_cmds(cmds, commands_to_log=log_cmds)

    def clear_region_updated_time(self):
       self._region_updated_time = None

    def region_in_sync(self):
       eos_region_updated_times = self.get_region_updated_time()
       if self._region_updated_time and \
             self._region_updated_time[ 'regionTimestamp' ] == \
                eos_region_updated_times[ 'regionTimestamp' ]:
          return True
       return False

    def get_region_updated_time(self):
       """ This method return the time at which any entities in the region were
           updated.
       """
       cmds = [ 'show openstack timestamp %s' % self.region ]
       region = self._run_openstack_cmds(commands=cmds, commands_to_log=cmds)[0]
       return region

    def _run_openstack_cmds(self, commands, commands_to_log=None):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param commands_to_logs : This should be set to the command that is logged.
                                  If it is None, then the commands param is logged.
        """
        LOG.info(_('Executing command on Arista EOS: %s'), commands_to_log)
        LOG.info(_('Size of the command: %d'), len(commands))

        try:
            # this returns array of return values for every command in
            # full_command list
            startTime = time.time()
            ret = self._server.runCmds(version=1, cmds=commands)
            LOG.info(_('Time taken to run the command: %f' % ( time.time() - startTime )))
        except Exception as error:
            host = cfg.CONF.ml2_arista.eapi_host
            msg = (_('Error %(err)s while trying to execute '
                     'commands %(cmd)s on EOS %(host)s') %
                   {'err': error, 'cmd': commands_to_log, 'host': host})
            LOG.exception(msg)
            raise arista_exc.AristaRpcError(msg=msg)

        return ret

    def _run_openstack_config_cmds(self, commands, commands_to_log=None):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        :param commands_to_logs : This should be set to the command that is logged.
                                  If it is None, then the commands param is logged.
        """
        command_start = ['enable', 'configure', 'management openstack']
        command_start.append('region %s' % self.region)
        command_timestamp = ['show openstack timestamp %s' % self.region]
        command_end = ['exit', 'exit']
        full_command = command_start + commands + command_timestamp + command_end
        full_log_command = full_command
        if commands_to_log:
           full_log_command = command_start + commands_to_log + command_end

        ret = self._run_openstack_cmds(full_command, full_log_command)
        # Remove return values for 'configure terminal',
        # 'management openstack' and 'exit' commands
        ret = ret[len(command_start):-len(command_end)]
        self._region_updated_time = ret[ -1 ]

    def _eapi_host_url(self):
        self._validate_config()

        user = cfg.CONF.ml2_arista.eapi_username
        pwd = cfg.CONF.ml2_arista.eapi_password
        host = cfg.CONF.ml2_arista.eapi_host

        eapi_server_url = ('https://%s:%s@%s/command-api' %
                           (user, pwd, host))
        return eapi_server_url

    def _validate_config(self):
        if cfg.CONF.ml2_arista.get('eapi_host') == '':
            msg = _('Required option eapi_host is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)
        if cfg.CONF.ml2_arista.get('eapi_username') == '':
            msg = _('Required option eapi_username is not set')
            LOG.error(msg)
            raise arista_exc.AristaConfigError(msg=msg)


class SyncService(object):
    """Synchronizatin of information between Neutron and EOS

    Periodically (through configuration option), this service
    ensures that Networks and VMs configured on EOS/Arista HW
    are always in sync with Neutron DB.
    """
    def __init__(self, rpc_wrapper, neutron_db):
        self._rpc = rpc_wrapper
        self._ndb = neutron_db

    def synchronize(self):
        """Sends data to EOS which differs from neutron DB."""

        LOG.info(_('Syncing Neutron <-> EOS'))
        try:
            # Get the time at which entities in the region were updated.
            # If the times match, then ML2 is in sync with EOS. Otherwise
            # perform a complete sync.
            if self._rpc.region_in_sync():
               LOG.info(_('Regions are in sync!'))
               return
        except arista_exc.AristaRpcError:
            msg = _('EOS is not available, will try sync later')
            LOG.warning(msg)
            return

        try:
            #Always register with EOS to ensure that it has correct credentials
            self._rpc.register_with_eos()
            eos_tenants = self._rpc.get_tenants()
        except arista_exc.AristaRpcError:
            msg = _('EOS is not available, will try sync later')
            LOG.warning(msg)
            return

        db_tenants = db.get_tenants()

        # Delete tenants that are in EOS, but not in the database
        tenants_to_delete = \
            frozenset(eos_tenants.keys()).difference(db_tenants.keys())
        if len( tenants_to_delete ):
            self._rpc.delete_tenants(tenants_to_delete)
        
        for tenant in db_tenants:
            db_nets = db.get_networks(tenant)
            db_vms = db.get_vms(tenant)
            eos_nets = self._get_eos_networks(eos_tenants, tenant)
            eos_vms = self._get_eos_vms(eos_tenants, tenant)

            nets_to_delete = frozenset(eos_nets.keys()).difference(db_nets.keys())
            vms_to_delete = frozenset(eos_vms.keys()).difference(db_vms.keys())

            nets_to_update = frozenset(db_nets.keys()).difference(eos_nets.keys())
            vms_to_update = frozenset(db_vms.keys()).difference(eos_vms.keys())

            if len(vms_to_delete):
                try:
                    self._rpc.delete_vms(tenant, vms_to_delete)
                except arista_exc.AristaRpcError:
                    msg = _('EOS is not available,'
                            'failed to delete vms') 
                    LOG.warning(msg)

            if len(nets_to_delete):
                try:
                   self._rpc.delete_networks(tenant, nets_to_delete)
                except arista_exc.AristaRpcError:
                   msg = _('EOS is not available,'
                           'failed to delete networks') 
                   LOG.warning(msg)

            if len(nets_to_update):
                try:
                   neutron_nets = {}
                   for network in self._ndb.get_all_networks_for_tenant(tenant):
                      neutron_nets[network['id']] = network

                   networks = []
                   for net_id in nets_to_update:
                      vlan_id = db_nets[net_id]['segmentationTypeId']
                      net_name = ''
                      if neutron_nets.has_key(net_id):
                          net_name = neutron_nets[net_id]['name']
                      network = AristaNetwork(network_id=net_id,
                                        segmentation_id=vlan_id,
                                        network_name=net_name)
                      networks.append( network )
                   self._rpc.create_networks(tenant, networks)
                except arista_exc.AristaRpcError:
                   msg = _('EOS is not available,'
                           'failed to update networks') 
                   LOG.warning(msg)

            if len(vms_to_update):
                try:
                   all_vm_ports = self._ndb.get_all_ports_for_tenant(tenant)
                   vm_ports = []
                   vm_ids = frozenset(vms_to_update)
                   for port in all_vm_ports:
                       if port[ 'device_id' ] in vm_ids:
                           vm_ports.append(port)
                   self._rpc.create_vm_ports(tenant, vm_ports, db_vms)
                except arista_exc.AristaRpcError:
                   msg = _('EOS is not available,'
                           'failed to update vms') 
                   LOG.warning(msg)

    def _get_eos_networks(self, eos_tenants, tenant):
        networks = {}
        if eos_tenants and tenant in eos_tenants:
            networks = eos_tenants[tenant]['tenantNetworks']
        return networks

    def _get_eos_vms(self, eos_tenants, tenant):
        vms = {}
        if eos_tenants and tenant in eos_tenants:
            vms = eos_tenants[tenant]['tenantVmInstances']
        return vms


class AristaDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for Arista networking hardware.

    Remebers all networks and VMs that are provisioned on Arista Hardware.
    Does not send network provisioning request if the network has already been
    provisioned before for the given port.
    """
    def __init__(self, rpc=None):

        self.rpc = rpc or AristaRPCWrapper()
        self.db_nets = db.AristaProvisionedNets()
        self.db_vms = db.AristaProvisionedVms()
        self.db_tenants = db.AristaProvisionedTenants()
        self.ndb = db.NeutronNets()

        confg = cfg.CONF.ml2_arista
        self.segmentation_type = db.VLAN_SEGMENTATION
        self.timer = None
        self.eos = SyncService(self.rpc, self.ndb)
        self.sync_timeout = confg['sync_interval']
        self.eos_sync_lock = threading.Lock()

    def initialize(self):
        self.rpc.register_with_eos()
        # Registring with EOS updates self.rpc.region_updated_time. Clear it to
        # force an initial sync
        self.rpc.clear_region_updated_time()
        self._cleanup_db()
        self._synchronization_thread()

    def create_network_precommit(self, context):
        """Remember the tenant, and network information."""

        network = context.current
        segments = context.network_segments
        network_id = network['id']
        tenant_id = network['tenant_id']
        segmentation_id = segments[0]['segmentation_id']
        with self.eos_sync_lock:
            db.remember_tenant(tenant_id)
            db.remember_network(tenant_id,
                                network_id,
                                segmentation_id)

    def create_network_postcommit(self, context):
        """Provision the network on the Arista Hardware."""

        network = context.current
        network_id = network['id']
        network_name = network['name']
        tenant_id = network['tenant_id']
        segments = context.network_segments
        vlan_id = segments[0]['segmentation_id']
        with self.eos_sync_lock:
            if db.is_network_provisioned(tenant_id, network_id):
                try:
                    network = AristaNetwork(network_id=network_id,
                                      segmentation_id=vlan_id,
                                      network_name=network_name)
                    self.rpc.create_networks(tenant_id, [network])
                except arista_exc.AristaRpcError:
                    LOG.info(EOS_UNREACHABLE_MSG)
                    raise ml2_exc.MechanismDriverError()
            else:
                msg = _('Network %s is not created as it is not found in'
                        'Arista DB') % network_id
                LOG.info(msg)

    def update_network_precommit(self, context):
        """At the moment we only support network name change

        Any other change in network is not supported at this time.
        We do not store the network names, therefore, no DB store
        action is performed here.
        """
        new_network = context.current
        orig_network = context.original
        if new_network['name'] != orig_network['name']:
            msg = _('Network name changed to %s') % new_network['name']
            LOG.info(msg)

    def update_network_postcommit(self, context):
        """At the moment we only support network name change

        If network name is changed, a new network create request is
        sent to the Arista Hardware.
        """
        new_network = context.current
        orig_network = context.original
        if new_network['name'] != orig_network['name']:
            network_id = new_network['id']
            network_name = new_network['name']
            tenant_id = new_network['tenant_id']
            vlan_id = new_network['provider:segmentation_id']
            with self.eos_sync_lock:
                if db.is_network_provisioned(tenant_id, network_id):
                    try:
                        network = AristaNetwork(network_id=network_id,
                                          segmentation_id=vlan_id,
                                          network_name=network_name)
                        self.rpc.create_network(tenant_id, [network])
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    msg = _('Network %s is not updated as it is not found in'
                            'Arista DB') % network_id
                    LOG.info(msg)

    def delete_network_precommit(self, context):
        """Delete the network infromation from the DB."""
        network = context.current
        network_id = network['id']
        tenant_id = network['tenant_id']
        with self.eos_sync_lock:
            if db.is_network_provisioned(tenant_id, network_id):
                db.forget_network(tenant_id, network_id)
            # if necessary, delete tenant as well.
            self.delete_tenant(tenant_id)

    def delete_network_postcommit(self, context):
        """Send network delete request to Arista HW."""
        network = context.current
        network_id = network['id']
        tenant_id = network['tenant_id']
        with self.eos_sync_lock:

            # Succeed deleting network in case EOS is not accessible.
            # EOS state will be updated by sync thread once EOS gets
            # alive.
            try:
                self.rpc.delete_networks(tenant_id, [network_id])
            except arista_exc.AristaRpcError:
                LOG.info(EOS_UNREACHABLE_MSG)
                raise ml2_exc.MechanismDriverError()

    def create_port_precommit(self, context):
        """Remember the infromation about a VM and its ports

        A VM information, along with the physical host information
        is saved.
        """
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = port[portbindings.HOST_ID]

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            network_id = port['network_id']
            tenant_id = port['tenant_id']
            with self.eos_sync_lock:
                db.remember_vm(device_id, host, port_id,
                               network_id, tenant_id)

    def create_port_postcommit(self, context):
        """Plug a physical host into a network.

        Send provisioning request to Arista Hardware to plug a host
        into appropriate network.
        """
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = port[portbindings.HOST_ID]

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            port_name = port['name']
            network_id = port['network_id']
            tenant_id = port['tenant_id']
            with self.eos_sync_lock:
                hostname = self._host_name(host)
                vm_provisioned = db.is_vm_provisioned(device_id,
                                                      host,
                                                      port_id,
                                                      network_id,
                                                      tenant_id)
                net_provisioned = db.is_network_provisioned(tenant_id,
                                                            network_id)
                if vm_provisioned and net_provisioned:
                    try:
                        self.rpc.plug_port_into_network(device_id,
                                                        hostname,
                                                        port_id,
                                                        network_id,
                                                        tenant_id,
                                                        port_name,
                                                        device_owner)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    msg = _('VM %s is not created as it is not found in '
                            'Arista DB') % device_id
                    LOG.info(msg)

    def update_port_precommit(self, context):
        """Update the name of a given port.

        At the moment we only support port name change.
        Any other change to port is not supported at this time.
        We do not store the port names, therefore, no DB store
        action is performed here.
        """
        new_port = context.current
        orig_port = context.original
        if new_port['name'] != orig_port['name']:
            msg = _('Port name changed to %s') % new_port['name']
            LOG.info(msg)

    def update_port_postcommit(self, context):
        """Update the name of a given port in EOS.

        At the moment we only support port name change
        Any other change to port is not supported at this time.
        """
        port = context.current
        orig_port = context.original
        if port['name'] == orig_port['name']:
            # nothing to do
            return

        device_id = port['device_id']
        device_owner = port['device_owner']
        host = port[portbindings.HOST_ID]
        is_vm_boot = device_id and device_owner

        if host and is_vm_boot:
            port_id = port['id']
            port_name = port['name']
            network_id = port['network_id']
            tenant_id = port['tenant_id']
            with self.eos_sync_lock:
                hostname = self._host_name(host)
                segmentation_id = db.get_segmentation_id(tenant_id,
                                                         network_id)
                vm_provisioned = db.is_vm_provisioned(device_id,
                                                      host,
                                                      port_id,
                                                      network_id,
                                                      tenant_id)
                net_provisioned = db.is_network_provisioned(tenant_id,
                                                            network_id,
                                                            segmentation_id)
                if vm_provisioned and net_provisioned:
                    try:
                        self.rpc.plug_port_into_network(device_id,
                                                        hostname,
                                                        port_id,
                                                        network_id,
                                                        tenant_id,
                                                        port_name,
                                                        device_owner)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    msg = _('VM %s is not updated as it is not found in '
                            'Arista DB') % device_id
                    LOG.info(msg)

    def delete_port_precommit(self, context):
        """Delete information about a VM and host from the DB."""
        port = context.current

        host_id = port[portbindings.HOST_ID]
        device_id = port['device_id']
        tenant_id = port['tenant_id']
        network_id = port['network_id']
        port_id = port['id']
        with self.eos_sync_lock:
            if db.is_vm_provisioned(device_id, host_id, port_id,
                                    network_id, tenant_id):
                db.forget_vm(device_id, host_id, port_id,
                             network_id, tenant_id)
            # if necessary, delete tenant as well.
            self.delete_tenant(tenant_id)

    def delete_port_postcommit(self, context):
        """unPlug a physical host from a network.

        Send provisioning request to Arista Hardware to unplug a host
        from appropriate network.
        """
        port = context.current
        device_id = port['device_id']
        host = port[portbindings.HOST_ID]
        port_id = port['id']
        network_id = port['network_id']
        tenant_id = port['tenant_id']
        device_owner = port['device_owner']

        try:
            with self.eos_sync_lock:
                hostname = self._host_name(host)
                if device_owner == n_const.DEVICE_OWNER_DHCP:
                    self.rpc.unplug_dhcp_port_from_network(device_id,
                                                           hostname,
                                                           port_id,
                                                           network_id,
                                                           tenant_id)
                else:
                    self.rpc.unplug_host_from_network(device_id,
                                                      hostname,
                                                      port_id,
                                                      network_id,
                                                      tenant_id)
        except arista_exc.AristaRpcError:
            LOG.info(EOS_UNREACHABLE_MSG)
            raise ml2_exc.MechanismDriverError()

    def delete_tenant(self, tenant_id):
        """delete a tenant from DB.

        A tenant is deleted only if there is no network or VM configured
        configured for this tenant.
        """
        objects_for_tenant = (db.num_nets_provisioned(tenant_id) +
                              db.num_vms_provisioned(tenant_id))
        if not objects_for_tenant:
            db.forget_tenant(tenant_id)

    def _host_name(self, hostname):
        fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
        return hostname if fqdns_used else hostname.split('.')[0]

    def _synchronization_thread(self):
        with self.eos_sync_lock:
            t1 = time.clock()
            self.eos.synchronize()
            t2 = time.clock()
            LOG.debug(_("Time taken to synchronize: " + str( t2 - t1 )))

        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()

    def stop_synchronization_thread(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _cleanup_db(self):
        """Clean up any uncessary entries in our DB."""
        db_tenants = db.get_tenants()
        for tenant in db_tenants:
            neutron_nets = self.ndb.get_all_networks_for_tenant(tenant)
            neutron_nets_id = []
            for net in neutron_nets:
                neutron_nets_id.append(net['id'])
            db_nets = db.get_networks(tenant)
            for net_id in db_nets.keys():
                if net_id not in neutron_nets_id:
                    db.forget_network(tenant, net_id)
