# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
# All Rights Reserved.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.
# @author: Bob Kukura, Red Hat, Inc.

import logging
import os

from quantum.api.api_common import OperationalStatus
from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum.common.utils import find_config_file
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.plugins.openvswitch.common import config
from quantum.plugins.openvswitch import ovs_db
from quantum.plugins.openvswitch import ovs_db_v2
from quantum.quantum_plugin_base import QuantumPluginBase
from quantum import policy


LOG = logging.getLogger("ovs_quantum_plugin")


# Exception thrown if no more VLANs are available
class NoFreeVLANException(Exception):
    # TODO(rkukura) Remove this class when removing V1 API
    pass


class VlanMap(object):
    # TODO(rkukura) Remove this class when removing V1 API
    vlans = {}
    net_ids = {}
    free_vlans = set()

    def __init__(self, vlan_min=1, vlan_max=4094):
        if vlan_min > vlan_max:
            LOG.warn("Using default VLAN values! vlan_min = %s is larger"
                     " than vlan_max = %s!" % (vlan_min, vlan_max))
            vlan_min = 1
            vlan_max = 4094

        self.vlan_min = vlan_min
        self.vlan_max = vlan_max
        self.vlans.clear()
        self.net_ids.clear()
        self.free_vlans = set(xrange(self.vlan_min, self.vlan_max + 1))

    def already_used(self, vlan_id, network_id):
        self.free_vlans.remove(vlan_id)
        self.set_vlan(vlan_id, network_id)

    def set_vlan(self, vlan_id, network_id):
        self.vlans[vlan_id] = network_id
        self.net_ids[network_id] = vlan_id

    def acquire(self, network_id):
        if len(self.free_vlans):
            vlan = self.free_vlans.pop()
            self.set_vlan(vlan, network_id)
            LOG.debug("Allocated VLAN %s for network %s" % (vlan, network_id))
            return vlan
        else:
            raise NoFreeVLANException("No VLAN free for network %s" %
                                      network_id)

    def acquire_specific(self, vlan_id, network_id):
        LOG.debug("Allocating specific VLAN %s for network %s"
                  % (vlan_id, network_id))
        if vlan_id < 1 or vlan_id > 4094:
            msg = _("Specified VLAN %s outside legal range (1-4094)") % vlan_id
            raise q_exc.InvalidInput(error_message=msg)
        if self.vlans.get(vlan_id):
            raise q_exc.VlanIdInUse(vlan_id=vlan_id)
        self.free_vlans.discard(vlan_id)
        self.set_vlan(vlan_id, network_id)

    def release(self, network_id):
        vlan = self.net_ids.get(network_id, None)
        if vlan is not None:
            if vlan >= self.vlan_min and vlan <= self.vlan_max:
                self.free_vlans.add(vlan)
            del self.vlans[vlan]
            del self.net_ids[network_id]
            LOG.debug("Deallocated VLAN %s (used by network %s)" %
                      (vlan, network_id))
        else:
            LOG.error("No vlan found with network \"%s\"", network_id)

    def populate_already_used(self, vlans):
        for vlan_id, network_id in vlans:
            LOG.debug("Adding already populated vlan %s -> %s" %
                      (vlan_id, network_id))
            self.already_used(vlan_id, network_id)


class OVSQuantumPlugin(QuantumPluginBase):
    # TODO(rkukura) Remove this class when removing V1 API

    def __init__(self, configfile=None):
        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
        options.update({"sql_max_retries": sql_max_retries})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        self.vmap = VlanMap(cfg.CONF.OVS.vlan_min, cfg.CONF.OVS.vlan_max)
        # Populate the map with anything that is already present in the
        # database
        self.vmap.populate_already_used(ovs_db.get_vlans())

    def get_all_networks(self, tenant_id, **kwargs):
        nets = []
        for x in db.network_list(tenant_id):
            LOG.debug("Adding network: %s" % x.uuid)
            nets.append(self._make_net_dict(str(x.uuid), x.name,
                                            None, x.op_status))
        return nets

    def _make_net_dict(self, net_id, net_name, ports, op_status):
        res = {
            'net-id': net_id,
            'net-name': net_name,
            'net-op-status': op_status,
        }
        if ports:
            res['net-ports'] = ports
        return res

    def create_network(self, tenant_id, net_name, **kwargs):
        net = db.network_create(tenant_id, net_name,
                                op_status=OperationalStatus.UP)
        try:
            vlan_id = self.vmap.acquire(str(net.uuid))
        except NoFreeVLANException:
            db.network_destroy(net.uuid)
            raise

        LOG.debug("Created network: %s" % net)
        ovs_db.add_vlan_binding(vlan_id, str(net.uuid))
        return self._make_net_dict(str(net.uuid), net.name, [], net.op_status)

    def delete_network(self, tenant_id, net_id):
        db.validate_network_ownership(tenant_id, net_id)
        net = db.network_get(net_id)

        # Verify that no attachments are plugged into the network
        for port in db.port_list(net_id):
            if port.interface_id:
                raise q_exc.NetworkInUse(net_id=net_id)
        net = db.network_destroy(net_id)
        ovs_db.remove_vlan_binding(net_id)
        self.vmap.release(net_id)
        return self._make_net_dict(str(net.uuid), net.name, [], net.op_status)

    def get_network_details(self, tenant_id, net_id):
        db.validate_network_ownership(tenant_id, net_id)
        net = db.network_get(net_id)
        ports = self.get_all_ports(tenant_id, net_id)
        return self._make_net_dict(str(net.uuid), net.name,
                                   ports, net.op_status)

    def update_network(self, tenant_id, net_id, **kwargs):
        db.validate_network_ownership(tenant_id, net_id)
        net = db.network_update(net_id, tenant_id, **kwargs)
        return self._make_net_dict(str(net.uuid), net.name,
                                   None, net.op_status)

    def _make_port_dict(self, port):
        if port.state == "ACTIVE":
            op_status = port.op_status
        else:
            op_status = OperationalStatus.DOWN

        return {
            'port-id': str(port.uuid),
            'port-state': port.state,
            'port-op-status': op_status,
            'net-id': port.network_id,
            'attachment': port.interface_id,
        }

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        ids = []
        db.validate_network_ownership(tenant_id, net_id)
        ports = db.port_list(net_id)
        # This plugin does not perform filtering at the moment
        return [{'port-id': str(p.uuid)} for p in ports]

    def create_port(self, tenant_id, net_id, port_state=None, **kwargs):
        LOG.debug("Creating port with network_id: %s" % net_id)
        db.validate_network_ownership(tenant_id, net_id)
        port = db.port_create(net_id, port_state,
                              op_status=OperationalStatus.DOWN)
        return self._make_port_dict(port)

    def delete_port(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        port = db.port_destroy(port_id, net_id)
        return self._make_port_dict(port)

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        db.validate_port_ownership(tenant_id, net_id, port_id)
        port = db.port_get(port_id, net_id)
        db.port_update(port_id, net_id, **kwargs)
        return self._make_port_dict(port)

    def get_port_details(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        port = db.port_get(port_id, net_id)
        return self._make_port_dict(port)

    def plug_interface(self, tenant_id, net_id, port_id, remote_iface_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        db.port_set_attachment(port_id, net_id, remote_iface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        db.port_set_attachment(port_id, net_id, "")
        db.port_update(port_id, net_id, op_status=OperationalStatus.DOWN)

    def get_interface_details(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        res = db.port_get(port_id, net_id)
        return res.interface_id


class OVSQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """Implement the Quantum abstractions using Open vSwitch.

    Depending on whether tunneling is enabled, either a GRE tunnel or
    a new VLAN is created for each network. An agent is relied upon to
    perform the actual OVS configuration on each host.

    The provider extension is also supported. As discussed in
    https://bugs.launchpad.net/quantum/+bug/1023156, this class could
    be simplified, and filtering on extended attributes could be
    handled, by adding support for extended attributes to the
    QuantumDbPluginV2 base class. When that occurs, this class should
    be updated to take advantage of it.
    """

    supported_extension_aliases = ["provider"]

    def __init__(self, configfile=None):
        self.enable_tunneling = cfg.CONF.OVS.enable_tunneling
        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        options.update({'base': models_v2.model_base.BASEV2})
        sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
        options.update({"sql_max_retries": sql_max_retries})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        # update the vlan_id table based on current configuration
        ovs_db_v2.update_vlan_id_pool()

    # TODO(rkukura) Use core mechanism for attribute authorization
    # when available.

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
                            "extension:provider_network:view",
                            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:provider_network:set",
                              network)

    def _extend_network_dict(self, context, network):
        if self._check_provider_view_auth(context, network):
            if not self.enable_tunneling:
                network['provider:vlan_id'] = ovs_db_v2.get_vlan(network['id'])

    def create_network(self, context, network):
        net = super(OVSQuantumPluginV2, self).create_network(context, network)
        try:
            vlan_id = network['network'].get('provider:vlan_id')
            if vlan_id not in (None, attributes.ATTR_NOT_SPECIFIED):
                self._enforce_provider_set_auth(context, net)
                ovs_db_v2.reserve_specific_vlan_id(vlan_id)
            else:
                vlan_id = ovs_db_v2.reserve_vlan_id()
        except Exception:
            super(OVSQuantumPluginV2, self).delete_network(context, net['id'])
            raise

        LOG.debug("Created network: %s" % net['id'])
        ovs_db_v2.add_vlan_binding(vlan_id, str(net['id']))
        self._extend_network_dict(context, net)
        return net

    def update_network(self, context, id, network):
        net = super(OVSQuantumPluginV2, self).update_network(context, id,
                                                             network)
        self._extend_network_dict(context, net)
        return net

    def delete_network(self, context, id):
        vlan_id = ovs_db_v2.get_vlan(id)
        result = super(OVSQuantumPluginV2, self).delete_network(context, id)
        ovs_db_v2.release_vlan_id(vlan_id)
        return result

    def get_network(self, context, id, fields=None, verbose=None):
        net = super(OVSQuantumPluginV2, self).get_network(context, id,
                                                          None, verbose)
        self._extend_network_dict(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None, verbose=None):
        nets = super(OVSQuantumPluginV2, self).get_networks(context, filters,
                                                            None, verbose)
        for net in nets:
            self._extend_network_dict(context, net)
        # TODO(rkukura): Filter on extended attributes.
        return [self._fields(net, fields) for net in nets]
