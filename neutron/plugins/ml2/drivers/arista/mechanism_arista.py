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

from networking_arista.common import db_lib
from networking_arista.ml2 import arista_ml2
from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import constants as n_const
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers.arista import config  # noqa
from neutron.plugins.ml2.drivers.arista import db
from neutron.plugins.ml2.drivers.arista import exceptions as arista_exc

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')


class AristaDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for Arista networking hardware.

    Remembers all networks and VMs that are provisioned on Arista Hardware.
    Does not send network provisioning request if the network has already been
    provisioned before for the given port.
    """
    def __init__(self, rpc=None):

        self.rpc = rpc or arista_ml2.AristaRPCWrapper()
        self.db_nets = db.AristaProvisionedNets()
        self.db_vms = db.AristaProvisionedVms()
        self.db_tenants = db.AristaProvisionedTenants()
        self.ndb = db_lib.NeutronNets()

        confg = cfg.CONF.ml2_arista
        self.segmentation_type = db_lib.VLAN_SEGMENTATION
        self.timer = None
        self.eos = arista_ml2.SyncService(self.rpc, self.ndb)
        self.sync_timeout = confg['sync_interval']
        self.eos_sync_lock = threading.Lock()

    def initialize(self):
        self.rpc.register_with_eos()
        self._cleanup_db()
        self.rpc.check_cli_commands()
        # Registering with EOS updates self.rpc.region_updated_time. Clear it
        # to force an initial sync
        self.rpc.clear_region_updated_time()
        self._synchronization_thread()

    def create_network_precommit(self, context):
        """Remember the tenant, and network information."""

        network = context.current
        segments = context.network_segments
        if segments[0][driver_api.NETWORK_TYPE] != p_const.TYPE_VLAN:
            # If network type is not VLAN, do nothing
            return
        network_id = network['id']
        tenant_id = network['tenant_id']
        if not tenant_id:
            tenant_id = context._plugin_context.tenant_id
        segmentation_id = segments[0]['segmentation_id']
        with self.eos_sync_lock:
            db_lib.remember_tenant(tenant_id)
            db_lib.remember_network(tenant_id,
                                network_id,
                                segmentation_id)

    def create_network_postcommit(self, context):
        """Provision the network on the Arista Hardware."""

        network = context.current
        network_id = network['id']
        network_name = network['name']
        tenant_id = network['tenant_id']
        if not tenant_id:
            tenant_id = context._plugin_context.tenant_id
        segments = context.network_segments
        vlan_id = segments[0]['segmentation_id']
        shared_net = network['shared']
        with self.eos_sync_lock:
            if db_lib.is_network_provisioned(tenant_id, network_id):
                try:
                    network_dict = {
                        'network_id': network_id,
                        'segmentation_id': vlan_id,
                        'network_name': network_name,
                        'shared': shared_net}
                    self.rpc.create_network(tenant_id, network_dict)
                except arista_exc.AristaRpcError:
                    LOG.info(EOS_UNREACHABLE_MSG)
                    raise ml2_exc.MechanismDriverError()
            else:
                LOG.info(_LI('Network %s is not created as it is not found in '
                             'Arista DB'), network_id)

    def update_network_precommit(self, context):
        """At the moment we only support network name change

        Any other change in network is not supported at this time.
        We do not store the network names, therefore, no DB store
        action is performed here.
        """
        new_network = context.current
        orig_network = context.original
        if new_network['name'] != orig_network['name']:
            LOG.info(_LI('Network name changed to %s'), new_network['name'])

    def update_network_postcommit(self, context):
        """At the moment we only support network name change

        If network name is changed, a new network create request is
        sent to the Arista Hardware.
        """
        new_network = context.current
        orig_network = context.original
        if ((new_network['name'] != orig_network['name']) or
           (new_network['shared'] != orig_network['shared'])):
            network_id = new_network['id']
            network_name = new_network['name']
            tenant_id = new_network['tenant_id']
            if not tenant_id:
                tenant_id = context._plugin_context.tenant_id
            vlan_id = new_network['provider:segmentation_id']
            shared_net = new_network['shared']
            with self.eos_sync_lock:
                if db_lib.is_network_provisioned(tenant_id, network_id):
                    try:
                        network_dict = {
                            'network_id': network_id,
                            'segmentation_id': vlan_id,
                            'network_name': network_name,
                            'shared': shared_net}
                        self.rpc.create_network(tenant_id, network_dict)
                    except arista_exc.AristaRpcError:
                        LOG.info(EOS_UNREACHABLE_MSG)
                        raise ml2_exc.MechanismDriverError()
                else:
                    LOG.info(_LI('Network %s is not updated as it is not found'
                                 ' in Arista DB'), network_id)

    def delete_network_precommit(self, context):
        """Delete the network infromation from the DB."""
        network = context.current
        network_id = network['id']
        tenant_id = network['tenant_id']
        with self.eos_sync_lock:
            if db_lib.is_network_provisioned(tenant_id, network_id):
                db_lib.forget_network(tenant_id, network_id)

    def delete_network_postcommit(self, context):
        """Send network delete request to Arista HW."""
        network = context.current
        segments = context.network_segments
        if segments[0][driver_api.NETWORK_TYPE] != p_const.TYPE_VLAN:
            # If networtk type is not VLAN, do nothing
            return
        network_id = network['id']
        tenant_id = network['tenant_id']
        if not tenant_id:
            tenant_id = context._plugin_context.tenant_id
        with self.eos_sync_lock:

            # Succeed deleting network in case EOS is not accessible.
            # EOS state will be updated by sync thread once EOS gets
            # alive.
            try:
                self.rpc.delete_network(tenant_id, network_id)
                # if necessary, delete tenant as well.
                self.delete_tenant(tenant_id)
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
        host = context.host

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            network_id = port['network_id']
            tenant_id = port['tenant_id']
            if not tenant_id:
                tenant_id = context._plugin_context.tenant_id
            with self.eos_sync_lock:
                if not db_lib.is_network_provisioned(tenant_id, network_id):
                    # Ignore this request if network is not provisioned
                    return
                db_lib.remember_tenant(tenant_id)
                db_lib.remember_vm(device_id, host, port_id,
                               network_id, tenant_id)

    def create_port_postcommit(self, context):
        """Plug a physical host into a network.

        Send provisioning request to Arista Hardware to plug a host
        into appropriate network.
        """
        port = context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and is_vm_boot:
            port_id = port['id']
            port_name = port['name']
            network_id = port['network_id']
            tenant_id = port['tenant_id']
            if not tenant_id:
                tenant_id = context._plugin_context.tenant_id
            with self.eos_sync_lock:
                hostname = self._host_name(host)
                vm_provisioned = db_lib.is_vm_provisioned(device_id,
                                                      host,
                                                      port_id,
                                                      network_id,
                                                      tenant_id)
                # If network does not exist under this tenant,
                # it may be a shared network. Get shared network owner Id
                net_provisioned = (
                    db_lib.is_network_provisioned(tenant_id, network_id) or
                    self.ndb.get_shared_network_owner_id(network_id)
                )
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
                    LOG.info(_LI('VM %s is not created as it is not found in '
                                 'Arista DB'), device_id)

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
            LOG.info(_LI('Port name changed to %s'), new_port['name'])
        new_port = context.current
        device_id = new_port['device_id']
        device_owner = new_port['device_owner']
        host = context.host

        # device_id and device_owner are set on VM boot
        is_vm_boot = device_id and device_owner
        if host and host != orig_port['binding:host_id'] and is_vm_boot:
            port_id = new_port['id']
            network_id = new_port['network_id']
            tenant_id = new_port['tenant_id']
            if not tenant_id:
                tenant_id = context._plugin_context.tenant_id
            with self.eos_sync_lock:
                db_lib.update_vm_host(device_id, host, port_id,
                                      network_id, tenant_id)

    def update_port_postcommit(self, context):
        """Update the name of a given port in EOS.

        At the moment we only support port name change
        Any other change to port is not supported at this time.
        """
        port = context.current
        orig_port = context.original

        device_id = port['device_id']
        device_owner = port['device_owner']
        host = context.host
        is_vm_boot = device_id and device_owner

        if host and is_vm_boot:
            port_id = port['id']
            port_name = port['name']
            network_id = port['network_id']
            tenant_id = port['tenant_id']
            if not tenant_id:
                tenant_id = context._plugin_context.tenant_id
            with self.eos_sync_lock:
                hostname = self._host_name(host)
                segmentation_id = db_lib.get_segmentation_id(tenant_id,
                                                         network_id)
                vm_provisioned = db_lib.is_vm_provisioned(device_id,
                                                      host,
                                                      port_id,
                                                      network_id,
                                                      tenant_id)
                # If network does not exist under this tenant,
                # it may be a shared network. Get shared network owner Id
                net_provisioned = (
                    db_lib.is_network_provisioned(tenant_id, network_id,
                                                  segmentation_id) or
                    self.ndb.get_shared_network_owner_id(network_id)
                )
                if vm_provisioned and net_provisioned:
                    try:
                        orig_host = orig_port['binding:host_id']
                        if host != orig_host:
                            # The port moved to a different host. So delete the
                            # old port on the old host before creating a new
                            # port on the new host.
                            self._delete_port(port, orig_host, tenant_id)
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
                    LOG.info(_LI('VM %s is not updated as it is not found in '
                                 'Arista DB'), device_id)

    def delete_port_precommit(self, context):
        """Delete information about a VM and host from the DB."""
        port = context.current

        host_id = context.host
        device_id = port['device_id']
        tenant_id = port['tenant_id']
        if not tenant_id:
            tenant_id = context._plugin_context.tenant_id
        network_id = port['network_id']
        port_id = port['id']
        with self.eos_sync_lock:
            if db_lib.is_vm_provisioned(device_id, host_id, port_id,
                                        network_id, tenant_id):
                db_lib.forget_vm(device_id, host_id, port_id,
                             network_id, tenant_id)

    def delete_port_postcommit(self, context):
        """unPlug a physical host from a network.

        Send provisioning request to Arista Hardware to unplug a host
        from appropriate network.
        """
        port = context.current
        host = context.host
        tenant_id = port['tenant_id']
        if not tenant_id:
            tenant_id = context._plugin_context.tenant_id

        with self.eos_sync_lock:
            self._delete_port(port, host, tenant_id)

    def _delete_port(self, port, host, tenant_id):
        """Deletes the port from EOS.

        param port: Port which is to be deleted
        param host: The host on which the port existed
        param tenant_id: The tenant to which the port belongs to. Some times
                         the tenant id in the port dict is not present (as in
                         the case of HA router).
        """
        device_id = port['device_id']
        port_id = port['id']
        network_id = port['network_id']
        device_owner = port['device_owner']

        try:
            if not db_lib.is_network_provisioned(tenant_id, network_id):
                # If we do not have network associated with this, ignore it
                return
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
            # if necessary, delete tenant as well.
            self.delete_tenant(tenant_id)
        except arista_exc.AristaRpcError:
            LOG.info(EOS_UNREACHABLE_MSG)
            raise ml2_exc.MechanismDriverError()

    def delete_tenant(self, tenant_id):
        """delete a tenant from DB.

        A tenant is deleted only if there is no network or VM configured
        configured for this tenant.
        """
        objects_for_tenant = (db_lib.num_nets_provisioned(tenant_id) +
                              db_lib.num_vms_provisioned(tenant_id))
        if not objects_for_tenant:
            db_lib.forget_tenant(tenant_id)
            try:
                self.rpc.delete_tenant(tenant_id)
            except arista_exc.AristaRpcError:
                LOG.info(EOS_UNREACHABLE_MSG)
                raise ml2_exc.MechanismDriverError()

    def _host_name(self, hostname):
        fqdns_used = cfg.CONF.ml2_arista['use_fqdn']
        return hostname if fqdns_used else hostname.split('.')[0]

    def _synchronization_thread(self):
        with self.eos_sync_lock:
            self.eos.do_synchronize()

        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()

    def stop_synchronization_thread(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _cleanup_db(self):
        """Clean up any uncessary entries in our DB."""
        db_tenants = db_lib.get_tenants()
        for tenant in db_tenants:
            neutron_nets = self.ndb.get_all_networks_for_tenant(tenant)
            neutron_nets_id = []
            for net in neutron_nets:
                neutron_nets_id.append(net['id'])
            db_nets = db_lib.get_networks(tenant)
            for net_id in db_nets.keys():
                if net_id not in neutron_nets_id:
                    db_lib.forget_network(tenant, net_id)
