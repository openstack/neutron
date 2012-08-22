"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
# @author: Dan Wendlandt, Nicira, Inc
#
"""

import logging
import sys
import time

import netaddr

from quantum.agent.common import config
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.agent.linux import iptables_manager
from quantum.agent.linux import utils as linux_utils
from quantum.db import l3_db
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantumclient.v2_0 import client

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qgw-'


class RouterInfo(object):

    def __init__(self, router_id, root_helper):
        self.router_id = router_id
        self.ex_gw_port = None
        self.internal_ports = []
        self.floating_ips = []
        self.root_helper = root_helper

        self.iptables_manager = iptables_manager.IptablesManager(
            root_helper=root_helper,
            #FIXME(danwent): use_ipv6=True,
            namespace=self.ns_name())

    def ns_name(self):
        return NS_PREFIX + self.router_id


class L3NATAgent(object):

    OPTS = [
        cfg.StrOpt('admin_user'),
        cfg.StrOpt('admin_password'),
        cfg.StrOpt('admin_tenant_name'),
        cfg.StrOpt('auth_url'),
        cfg.StrOpt('auth_strategy', default='keystone'),
        cfg.StrOpt('auth_region'),
        cfg.StrOpt('root_helper', default='sudo'),
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help="Name of bridge used for external network traffic."),
        cfg.StrOpt('interface_driver',
                   help="The driver used to manage the virtual interface."),
        cfg.IntOpt('polling_interval',
                   default=3,
                   help="The time in seconds between state poll requests."),
        cfg.StrOpt('metadata_ip', default='127.0.0.1',
                   help="IP address used by Nova metadata server."),
        cfg.IntOpt('metadata_port',
                   default=8775,
                   help="TCP Port used by Nova metadata server."),
        #FIXME(danwent): not currently used
        cfg.BoolOpt('send_arp_for_ha',
                    default=True,
                    help="Send gratuitious ARP when router IP is configured")
    ]

    def __init__(self, conf):
        self.conf = conf
        self.router_info = {}

        if not conf.interface_driver:
            LOG.error(_('You must specify an interface driver'))
            sys.exit(1)
        try:
            self.driver = importutils.import_object(conf.interface_driver,
                                                    conf)
        except:
            LOG.exception(_("Error importing interface driver '%s'"
                            % conf.interface_driver))
            sys.exit(1)

        self.polling_interval = conf.polling_interval

        if not ip_lib.device_exists(self.conf.external_network_bridge):
            raise Exception("external network bridge '%s' does not exist"
                            % self.conf.external_network_bridge)

        self.qclient = client.Client(
            username=self.conf.admin_user,
            password=self.conf.admin_password,
            tenant_name=self.conf.admin_tenant_name,
            auth_url=self.conf.auth_url,
            auth_strategy=self.conf.auth_strategy,
            auth_region=self.conf.auth_region
        )

        # disable forwarding
        linux_utils.execute(['sysctl', '-w', 'net.ipv4.ip_forward=0'],
                            self.conf.root_helper, check_exit_code=False)

        self._destroy_all_router_namespaces()

        # enable forwarding
        linux_utils.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                            self.conf.root_helper, check_exit_code=False)

    def _destroy_all_router_namespaces(self):
        """Destroy all router namespaces on the host to eliminate
        all stale linux devices, iptables rules, and namespaces.
        """
        root_ip = ip_lib.IPWrapper(self.conf.root_helper)
        for ns in root_ip.get_namespaces(self.conf.root_helper):
            if ns.startswith(NS_PREFIX):
                try:
                    self._destroy_router_namespace(ns)
                except:
                    LOG.exception("couldn't delete namespace '%s'" % ns)

    def _destroy_router_namespace(self, namespace):
        ns_ip = ip_lib.IPWrapper(self.conf.root_helper,
                                 namespace=namespace)
        for d in ns_ip.get_devices():
            if d.name.startswith(INTERNAL_DEV_PREFIX):
                # device is on default bridge
                self.driver.unplug(d.name)
            elif d.name.startswith(EXTERNAL_DEV_PREFIX):
                self.driver.unplug(d.name,
                                   bridge=self.conf.external_network_bridge)
        ns_ip.netns.delete(namespace)

    def daemon_loop(self):

        #TODO(danwent): this simple diff logic does not handle if a
        # resource is modified (i.e., ip change on port, or floating ip
        # mapped from one IP to another).  Will fix this properly with
        # update notifications.
        # Likewise, it does not handle removing routers

        while True:
            try:
                self.do_single_loop()
            except:
                LOG.exception("Error running l3_nat daemon_loop")

            time.sleep(self.polling_interval)

    def do_single_loop(self):
        prev_router_ids = set(self.router_info)
        cur_router_ids = set()

        # identify and update new or modified routers
        for r in self.qclient.list_routers()['routers']:
            cur_router_ids.add(r['id'])
            if r['id'] not in self.router_info:
                self.router_info[r['id']] = RouterInfo(r['id'],
                                                       self.conf.root_helper)
            ri = self.router_info[r['id']]
            self.process_router(ri)

        # identify and remove routers that no longer exist
        for router_id in prev_router_ids - cur_router_ids:
            ri = self.router_info[router_id]
            del self.router_info[router_id]
            self._destroy_router_namespace(ri.ns_name())
        prev_router_ids = cur_router_ids

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception("Router port %s has no IP address" % port['id'])
        if len(ips) > 1:
            LOG.error("Ignoring multiple IPs on router port %s" % port['id'])
        port['subnet'] = self.qclient.show_subnet(
            ips[0]['subnet_id'])['subnet']
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def process_router(self, ri):

        ex_gw_port = self._get_ex_gw_port(ri)

        internal_ports = self.qclient.list_ports(
            device_id=ri.router_id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF)['ports']

        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]

        for p in new_ports:
            self._set_subnet_info(p)
            ri.internal_ports.append(p)
            self.internal_network_added(ri, ex_gw_port, p['id'],
                                        p['ip_cidr'], p['mac_address'])

        for p in old_ports:
            ri.internal_ports.remove(p)
            self.internal_network_removed(ri, ex_gw_port, p['id'],
                                          p['ip_cidr'])

        internal_cidrs = [p['ip_cidr'] for p in ri.internal_ports]

        if ex_gw_port and not ri.ex_gw_port:
            self._set_subnet_info(ex_gw_port)
            self.external_gateway_added(ri, ex_gw_port, internal_cidrs)
        elif not ex_gw_port and ri.ex_gw_port:
            self.external_gateway_removed(ri, ri.ex_gw_port,
                                          internal_cidrs)

        if ri.ex_gw_port or ex_gw_port:
            self.process_router_floating_ips(ri, ex_gw_port)

        ri.ex_gw_port = ex_gw_port

    def process_router_floating_ips(self, ri, ex_gw_port):
        floating_ips = self.qclient.list_floatingips(
            router_id=ri.router_id)['floatingips']
        existing_floating_ip_ids = set([fip['id'] for fip in ri.floating_ips])
        cur_floating_ip_ids = set([fip['id'] for fip in floating_ips])

        for fip in floating_ips:
            if fip['port_id']:
                if fip['id'] not in existing_floating_ip_ids:
                    ri.floating_ips.append(fip)
                    self.floating_ip_added(ri, ex_gw_port,
                                           fip['floating_ip_address'],
                                           fip['fixed_ip_address'])

        floating_ip_ids_to_remove = (existing_floating_ip_ids -
                                     cur_floating_ip_ids)
        for fip in ri.floating_ips:
            if fip['id'] in floating_ip_ids_to_remove:
                ri.floating_ips.remove(fip)
                self.floating_ip_removed(ri, ri.ex_gw_port,
                                         fip['floating_ip_address'],
                                         fip['fixed_ip_address'])

    def _get_ex_gw_port(self, ri):
        ports = self.qclient.list_ports(
            device_id=ri.router_id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_GW)['ports']
        if not ports:
            return None
        elif len(ports) == 1:
            return ports[0]
        else:
            LOG.error("Ignoring multiple gateway ports for router %s"
                      % ri.router_id)

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def external_gateway_added(self, ri, ex_gw_port, internal_cidrs):

        interface_name = self.get_external_device_name(ex_gw_port['id'])
        ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.conf.root_helper,
                                    namespace=ri.ns_name()):
            self.driver.plug(None, ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ri.ns_name())
        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ri.ns_name())

        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_port['subnet']['gateway_ip']:
            cmd = ['route', 'add', 'default', 'gw', gw_ip]
            ip_wrapper = ip_lib.IPWrapper(self.conf.root_helper,
                                          namespace=ri.ns_name())
            ip_wrapper.netns.execute(cmd)

        for (c, r) in self.external_gateway_filter_rules():
            ri.iptables_manager.ipv4['filter'].add_rule(c, r)
        for (c, r) in self.external_gateway_nat_rules(ex_gw_ip,
                                                      internal_cidrs):
            ri.iptables_manager.ipv4['nat'].add_rule(c, r)
        ri.iptables_manager.apply()

    def external_gateway_removed(self, ri, ex_gw_port, internal_cidrs):

        interface_name = self.get_external_device_name(ex_gw_port['id'])
        if ip_lib.device_exists(interface_name,
                                root_helper=self.conf.root_helper,
                                namespace=ri.ns_name()):
            self.driver.unplug(interface_name)

        ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
        for c, r in self.external_gateway_filter_rules():
            ri.iptables_manager.ipv4['filter'].remove_rule(c, r)
        for c, r in self.external_gateway_nat_rules(ex_gw_ip, internal_cidrs):
            ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
        ri.iptables_manager.apply()

    def external_gateway_filter_rules(self):
        return [('INPUT', '-s 0.0.0.0/0 -d %s '
                          '-p tcp -m tcp --dport %s '
                          '-j ACCEPT' %
                          (self.conf.metadata_ip, self.conf.metadata_port))]

    def external_gateway_nat_rules(self, ex_gw_ip, internal_cidrs):
        rules = [('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                  '-p tcp -m tcp --dport 80 -j DNAT '
                  '--to-destination %s:%s' %
                  (self.conf.metadata_ip, self.conf.metadata_port))]
        for cidr in internal_cidrs:
            rules.extend(self.internal_network_nat_rules(ex_gw_ip, cidr))
        return rules

    def internal_network_added(self, ri, ex_gw_port, port_id,
                               internal_cidr, mac_address):
        interface_name = self.get_internal_device_name(port_id)
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.conf.root_helper,
                                    namespace=ri.ns_name()):
            self.driver.plug(None, port_id, interface_name, mac_address,
                             namespace=ri.ns_name())

        self.driver.init_l3(interface_name, [internal_cidr],
                            namespace=ri.ns_name())

        if ex_gw_port:
            ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
            for c, r in self.internal_network_nat_rules(ex_gw_ip,
                                                        internal_cidr):
                ri.iptables_manager.ipv4['nat'].add_rule(c, r)
            ri.iptables_manager.apply()

    def internal_network_removed(self, ri, ex_gw_port, port_id, internal_cidr):
        interface_name = self.get_internal_device_name(port_id)
        if ip_lib.device_exists(interface_name,
                                root_helper=self.conf.root_helper,
                                namespace=ri.ns_name()):
            self.driver.unplug(interface_name)

        if ex_gw_port:
            ex_gw_ip = ex_gw_port['fixed_ips'][0]['ip_address']
            for c, r in self.internal_network_nat_rules(ex_gw_ip,
                                                        internal_cidr):
                ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
            ri.iptables_manager.apply()

    def internal_network_nat_rules(self, ex_gw_ip, internal_cidr):
        return [('snat', '-s %s -j SNAT --to-source %s' %
                 (internal_cidr, ex_gw_ip)),
                ('POSTROUTING', '-s %s -d %s/32 -j ACCEPT' %
                 (internal_cidr, self.conf.metadata_ip))]

    def floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        ip_cidr = str(floating_ip) + '/32'
        interface_name = self.get_external_device_name(ex_gw_port['id'])
        device = ip_lib.IPDevice(interface_name, self.conf.root_helper,
                                 namespace=ri.ns_name())

        if not ip_cidr in [addr['cidr'] for addr in device.addr.list()]:
            net = netaddr.IPNetwork(ip_cidr)
            device.addr.add(net.version, ip_cidr, str(net.broadcast))

        for chain, rule in self.floating_forward_rules(floating_ip, fixed_ip):
            ri.iptables_manager.ipv4['nat'].add_rule(chain, rule)
        ri.iptables_manager.apply()

    def floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        ip_cidr = str(floating_ip) + '/32'
        net = netaddr.IPNetwork(ip_cidr)
        interface_name = self.get_external_device_name(ex_gw_port['id'])

        device = ip_lib.IPDevice(interface_name, self.conf.root_helper,
                                 namespace=ri.ns_name())
        device.addr.delete(net.version, ip_cidr)

        for chain, rule in self.floating_forward_rules(floating_ip, fixed_ip):
            ri.iptables_manager.ipv4['nat'].remove_rule(chain, rule)
        ri.iptables_manager.apply()

    def floating_forward_rules(self, floating_ip, fixed_ip):
        return [('PREROUTING', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', '-s %s -j SNAT --to %s' %
                 (fixed_ip, floating_ip))]


def main():
    conf = config.setup_conf()
    conf.register_opts(L3NATAgent.OPTS)
    conf.register_opts(interface.OPTS)
    conf(sys.argv)
    config.setup_logging(conf)

    mgr = L3NATAgent(conf)
    mgr.daemon_loop()


if __name__ == '__main__':
    main()
