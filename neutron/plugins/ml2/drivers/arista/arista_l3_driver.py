# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Arista Networks, Inc.  All rights reserved.
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
# @author: Sukhdev Kapur, Arista Networks, Inc.
#

import hashlib

import jsonrpclib
from oslo.config import cfg

from neutron import context as nctx
from neutron.db import db_base_plugin_v2
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers.arista import exceptions as arista_exc

LOG = logging.getLogger(__name__)

EOS_UNREACHABLE_MSG = _('Unable to reach EOS')

router_in_vrf =  {
   'router'    : {'create'  : ['vrf definition {0}',
                               'rd {1}',
                               'exit'],
                  'delete'  : ['no vrf definition {0}'],
                 },
   'interface' : {'add'     : ['ip routing vrf {1}',
                               'vlan {0}',
                               'exit',
                               'interface vlan {0}',
                               'vrf forwarding {1}',
                               'ip address {2}'],
                  'remove'  : ['no interface vlan {0}'],
                 }
            }

router_in_default_vrf =  {
   'router'    : {'create'  : [],
                  'delete'  : ['no ip routing',
                               'no ipv6 unicast-routing'],
                 },
   'interface' : {'add'     : ['ip routing',
                               'vlan {0}',
                               'exit',
                               'interface vlan {0}',
                               'ip address {2}'],
                  'remove'  : ['no interface vlan {0}'],
                 }
            }

router_in_default_vrf_v6 =  {
   'router'    : {'create'  : [],
                  'delete'  : ['no ip routing',
                               'no ipv6 unicast-routing'],
                 },
   'interface' : {'add'     : ['ipv6 unicast-routing',
                               'vlan {0}',
                               'exit',
                               'interface vlan {0}',
                               'ipv6 enable',
                               'ipv6 address {2}'],
                  'remove'  : ['no interface vlan {0}'],
                 }
            }

additional_cmds_for_mlag =  {
   'router'    : {'create'  : ['ip virtual-router mac-address {0}'],
                  'delete'  : ['no ip virtual-router mac-address'],
                 },
   'interface' : {'add'     : ['ip virtual-router address {0}'],
                  'remove'  : [],
                 }
            }

additional_cmds_for_mlag_v6 =  {
   'router'    : {'create'  : [],
                  'delete'  : [],
                 },
   'interface' : {'add'     : ['ipv6 virtual-router address {0}'],
                  'remove'  : [],
                 }
            }


class AristaL3Driver(object):
    """Wraps Arista JSON RPC.

    All communications between Neutron and EOS are over JSON RPC.
    EOS - operating system used on Arista hardware
    Command API - JSON RPC API provided by Arista EOS
    """
    def __init__(self):
        self._servers = []
        self._hosts = []
        self.interfaceDict = None
        self._servers.append(jsonrpclib.Server(self._eapi_host_url()))
        self.mlag_configured = cfg.CONF.l3_arista.mlag_config
        self.use_vrf = cfg.CONF.l3_arista.use_vrf
        if self.mlag_configured:
            self._servers.append(jsonrpclib.Server(self._eapi_mlag_host_url()))
            self._additionalRouterCmdsDict = additional_cmds_for_mlag['router']
            self._additionalInterfaceCmdsDict = (
                additional_cmds_for_mlag['interface'])
        if self.use_vrf:
            self.routerDict = router_in_vrf['router']
            self.interfaceDict = router_in_vrf['interface']
        else:
            self.routerDict = router_in_default_vrf['router']
            self.interfaceDict = router_in_default_vrf['interface']

    def _eapi_host_url(self):
        self._validate_config()

        user = cfg.CONF.l3_arista.primary_l3_host_username
        pwd = cfg.CONF.l3_arista.primary_l3_host_password
        host = cfg.CONF.l3_arista.primary_l3_host
        self._hosts.append(host)

        eapi_server_url = ('https://%s:%s@%s/command-api' %
                           (user, pwd, host))
        return eapi_server_url

    def _eapi_mlag_host_url(self):
        if not self.mlag_configured:
            return None
        user = cfg.CONF.l3_arista.primary_l3_host_username
        pwd = cfg.CONF.l3_arista.primary_l3_host_password
        host = cfg.CONF.l3_arista.seconadry_l3_host
        self._hosts.append(host)

        eapi_mlag_server_url = ('https://%s:%s@%s/command-api' %
                                (user, pwd, host))
        return eapi_mlag_server_url

    def _validate_config(self):
        if cfg.CONF.l3_arista.get('primary_l3_host') == '':
            msg = _('Required option primary_l3_host is not set')
            LOG.error(msg)
            raise arista_exc.AristaSevicePluginConfigError(msg=msg)
        if cfg.CONF.l3_arista.get('mlag_config'):
            #if cfg.CONF.arista.get('use_vrf'):
            #    #This is invalid/unsupported configuration
            #    msg = _('VRF does not support MLAG mode')
            #    LOG.error(msg)
            #    raise arista_exc.AristaSevicePluginConfigError(msg=msg)
            if cfg.CONF.l3_arista.get('seconadry_l3_host') == '':
                msg = _('Required option seconadry_l3_host is not set')
                LOG.error(msg)
                raise arista_exc.AristaSevicePluginConfigError(msg=msg)
        if cfg.CONF.l3_arista.get('primary_l3_host_username') == '':
            msg = _('Required option primary_l3_host_username is not set')
            LOG.error(msg)
            raise arista_exc.AristaSevicePluginConfigError(msg=msg)

    def create_router_on_eos(self, router_name, rdm, server):
        """Creates a router on Arista HW Device.

        :param router_name: globally unique identifier for router/VRF 
        :param RD: A random value between 1 and 10 to create rd for VRF
        """
        cmds=[]
        rd = "%s:%s" % (rdm, rdm)

        for c in self.routerDict['create']:
            cmds.append(c.format(router_name, rd))

        if self.mlag_configured:
            mac = '02:1c:73:00:42:e9'
            for c in self._additionalRouterCmdsDict['create']:
                cmds.append(c.format(mac))
          
        self._run_openstack_l3_cmds(cmds, server)

    def delete_router_from_eos(self, router_name, server):
        """Deletes a router from Arista HW Device.

        :param router_name: globally unique identifier for router/VRF 
        """
        cmds=[]
        for c in self.routerDict['delete']:
            cmds.append(c.format(router_name))
        if self.mlag_configured:
            for c in self._additionalRouterCmdsDict['delete']:
                cmds.append(c)

        self._run_openstack_l3_cmds(cmds, server)

    def _select_dicts(self, ipv):
        if self.use_vrf:
            self.interfaceDict = router_in_vrf['interface']
        else:
            if ipv == 6:
                #for ipV6 use IpV6 commmands
                self.interfaceDict = router_in_default_vrf_v6['interface']
                self._additionalInterfaceCmdsDict = (
                    additional_cmds_for_mlag_v6['interface'])
            else:
                self.interfaceDict = router_in_default_vrf['interface']
                self._additionalInterfaceCmdsDict = (
                    additional_cmds_for_mlag['interface'])

    def add_interface_to_router(self, segment_id,
                                router_name, gip, router_ip, mask, server):
        """Adds an interface to existing HW router on Arista HW device.

        :param segment_id: VLAN Id associated with interface that is added
        :param router_name: globally unique identifier for router/VRF 
        :param cidr: CIDR associated the sub-interface being added 
        """

        if not segment_id:
            segment_id = 1
        cmds=[]
        for c in self.interfaceDict['add']:
            if self.mlag_configured:
                ip = router_ip
            else:
                ip = gip + '/' + mask
            cmds.append(c.format(segment_id, router_name, ip))
        if self.mlag_configured:
            for c in self._additionalInterfaceCmdsDict['add']:
                #vip = ".".join(cidr.split( '/' ) [0 ].split('.')[ 0:3]) + '.1'
                cmds.append(c.format(gip))

        #pdb.set_trace()
        self._run_openstack_l3_cmds(cmds, server)

    def delete_interface_from_router(self, segment_id, router_name, server):
        """Deltes an interface from existing HW router on Arista HW device.

        :param segment_id: VLAN Id associated with interface that is added
        :param router_name: globally unique identifier for router/VRF 
        """

        if not segment_id:
            segment_id = 1
        cmds=[]
        for c in self.interfaceDict['remove']:
            cmds.append(c.format(segment_id))

        self._run_openstack_l3_cmds(cmds, server)

    def create_router(self, context, tenant_id, router):
        """Creates A router on Arista Switch.

        """
        if router:
            rdm =str(int(hashlib.sha256(router['name']).hexdigest(),16) % 6553)
            for s in self._servers:
                self.create_router_on_eos(router['name'], rdm, s)

    def delete_router(self, context, tenant_id, router_id, router):
        """Deleted A router from Arista Switch.

        """
        if router:
            for s in self._servers:
                self.delete_router_from_eos(router['name'], s)


    def update_router(self, context, router_id, original_router, new_router):
        """Update A router which is already created on Arista Switch.

        """
        pass

    def add_router_interface(self, context, router_info):
        """Adds an interface to a router created on Arista HW router.

        """
        if router_info:
            self._select_dicts(router_info['ip_version'])
            cidr = router_info['cidr']
            subnet_mask = cidr.split('/')[1]
            #virtualIp = ".".join(cidr.split( '/' ) [0 ].split('.')[ 0:3]) 
            if self.mlag_configured: 
                # For MLAG, we send a specific IP address as opposed to cidr
                # For now, we are using x.x.x.253 and x.x.x.254 as virtual IP
                for i in range(len(self._servers)):
                    #vip = virtualIp + '.' +  str (254 - i) + '/' + cidr.split('/')[1]
                    router_ip = self._get_router_ip(cidr, i,
                                                    router_info['ip_version'])
                    self.add_interface_to_router(router_info['seg_id'],
                                                 router_info['name'],
                                                 router_info['gip'],
                                                 router_ip, subnet_mask,
                                                 self._servers[i])
                  
            else:
                for s in self._servers:
                   self.add_interface_to_router(router_info['seg_id'],
                                                router_info['name'],
                                                router_info['gip'],
                                                None, subnet_mask, s)

    def remove_router_interface(self, context, router_info):
        """Removes previously configured interface from router on Arista HW.

        """
        if router_info:
            for s in self._servers:
                self.delete_interface_from_router(router_info['seg_id'],
                                                  router_info['name'], s)

    def _run_openstack_l3_cmds(self, commands, server):
        """Execute/sends a CAPI (Command API) command to EOS.

        In this method, list of commands is appended with prefix and
        postfix commands - to make is understandble by EOS.

        :param commands : List of command to be executed on EOS.
        """
        command_start = ['enable', 'configure']
        command_end = ['exit']
        full_command = command_start + commands + command_end

        LOG.info(_('Executing command on Arista EOS: %s'), full_command)

        try:
            # this returns array of return values for every command in
            # full_command list
            ret = server.runCmds(version=1, cmds=full_command)
            print ret

        except Exception as error:
            msg = (_('Error %(err)s while trying to execute '
                     'commands %(cmd)s on EOS %(host)s') %
                   {'err': error, 'cmd': full_command, 'host': server})
            LOG.exception(msg)
            raise arista_exc.AristaServicePluginRpcError(msg=msg)

#    def _get_binary_from_ip(self, ip_addr, ip_ver):
#       seperator = '.'
#       size = 8
#       num_octets = 4
#       if ip_ver == 6:
#           seperator = ':'
#           size = 16
#           num_octets = 8
#       octets = ip_addr.split(seperator)
#       num = 0
#       given_octets = len(octets)
#       convert_octets = num_octets - given_octets
#       for i in range( len(octets)):
#          if octets[i] == '':
#              for c in range(len(convert_octets+1):
#                  num = num | 0
#                  num = num << size
#              break
#          num = num | int( octets[ i ] )
#          num = num << size
#       return num
    
    def _get_binary_from_ipv4(self, ip_addr):
        octets = ip_addr.split( '.' )
        num = 0
        for i in range( len( octets ) - 1 ):
           num = num | int( octets[ i ] )
           num = num << 8
        return num
    
    def _get_binary_from_ipv6(self, ip_addr):
        octets = ip_addr.split( ':' )
        num = 0
        for i in range( len( octets ) - 1 ):
           if octets[ i ] != '':
              num = num | int(octets[ i ], 16)
              num = num << 16
           else:
              num = num << (7 - i) * 16
              break
        return num

    def _get_ipv4_from_binary(self, bin_addr):
       octets = []
       for i in range( 4 ):
          octets.append( str( bin_addr % 256 ) )
          bin_addr = bin_addr / 256
       return '.'.join( reversed( octets ) )
    
    def _get_ipv6_from_binary(self, bin_addr):
        octets = []
        for i in range( 8 ):
           octets.append( '%x' % ( bin_addr % 65536 ) )
           bin_addr = bin_addr / 65536
        return ':'.join( reversed( octets ) )
    
    def _get_router_ip(self, cidr, ip_count, ip_ver):
        start_ip = 2 + ip_count
        network_addr, prefix = cidr.split( '/' )
        if ip_ver == 4:
            ip = self._get_binary_from_ipv4(network_addr)
            mask = (pow(2,32) - 1) << ( 32 - int(prefix))
        elif ip_ver == 6:
            ip = self._get_binary_from_ipv6(network_addr)
            mask = (pow(2,128) - 1) << ( 128 - int(prefix))
    
        network_addr = ip & mask
    
        if ip_ver == 4:
           router_ip = pow(2, 32 - int(prefix)) - start_ip
        elif ip_ver == 6:
           router_ip = pow(2, 128 - int(prefix)) - start_ip
    
        router_ip = network_addr | router_ip
        if ip_ver == 4:
           return self._get_ipv4_from_binary(router_ip) + '/' + prefix
        else:
           return self._get_ipv6_from_binary(router_ip) + '/' + prefix


class NeutronNets(db_base_plugin_v2.NeutronDbPluginV2):
    """Access to Neutron DB.

    Provides access to the Neutron Data bases for all provisioned
    networks as well ports. This data is used during the synchronization
    of DB between ML2 Mechanism Driver and Arista EOS
    Names of the networks and ports are not stroed in Arista repository
    They are pulled from Neutron DB.
    """

    def __init__(self):
        self.admin_ctx = nctx.get_admin_context()

    def get_network_name(self, tenant_id, network_id):
        network = self._get_network(tenant_id, network_id)
        network_name = None
        if network:
            network_name = network[0]['name']
        return network_name

    def get_all_networks_for_tenant(self, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        return super(NeutronNets,
                     self).get_networks(self.admin_ctx, filters=filters) or []

    def get_all_ports_for_tenant(self, tenant_id):
        filters = {'tenant_id': [tenant_id]}
        return super(NeutronNets,
                     self).get_ports(self.admin_ctx, filters=filters) or []

    def _get_network(self, tenant_id, network_id):
        filters = {'tenant_id': [tenant_id],
                   'id': [network_id]}
        return super(NeutronNets,
                     self).get_networks(self.admin_ctx, filters=filters) or []

    def get_subnet_info(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet

    def get_subnet_ip_version(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['ip_version']

    def get_subnet_gateway_ip(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['gateway_ip']

    def get_subnet_cidr(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['cidr']

    def get_network_id(self, subnet_id):
        subnet = self.get_subnet(subnet_id)
        return subnet['network_id']

    def get_network_id_from_port_id(self, port_id):
        port = self.get_port(port_id)
        return port['network_id']

    def get_subnet(self, subnet_id):
        return super(NeutronNets,
                     self).get_subnet(self.admin_ctx, subnet_id) or []

    def get_port(self, port_id):
        return super(NeutronNets,
                     self).get_port(self.admin_ctx, port_id) or []

