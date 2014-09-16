# Copyright 2013 vArmour Networks Inc.
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

import sys

import eventlet
eventlet.monkey_patch()

import netaddr
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent import l3_agent
from neutron.agent import l3_ha_agent
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.common import constants as l3_constants
from neutron.common import topics
from neutron.openstack.common import log as logging
from neutron.openstack.common import service
from neutron import service as neutron_service
from neutron.services.firewall.agents.l3reference import firewall_l3_agent
from neutron.services.firewall.agents.varmour import varmour_api
from neutron.services.firewall.agents.varmour import varmour_utils as va_utils


LOG = logging.getLogger(__name__)


class vArmourL3NATAgent(l3_agent.L3NATAgent,
                        firewall_l3_agent.FWaaSL3AgentRpcCallback):
    def __init__(self, host, conf=None):
        LOG.debug(_('vArmourL3NATAgent: __init__'))
        self.rest = varmour_api.vArmourRestAPI()
        super(vArmourL3NATAgent, self).__init__(host, conf)

    def _destroy_router_namespaces(self, only_router_id=None):
        return

    def _destroy_router_namespace(self, namespace):
        return

    def _create_router_namespace(self, ri):
        return

    def _router_added(self, router_id, router):
        LOG.debug(_("_router_added: %s"), router_id)
        ri = l3_agent.RouterInfo(router_id, self.root_helper,
                                 self.conf.use_namespaces, router)
        self.router_info[router_id] = ri
        super(vArmourL3NATAgent, self).process_router_add(ri)

    def _router_removed(self, router_id):
        LOG.debug(_("_router_removed: %s"), router_id)

        ri = self.router_info[router_id]
        if ri:
            ri.router['gw_port'] = None
            ri.router[l3_constants.INTERFACE_KEY] = []
            ri.router[l3_constants.FLOATINGIP_KEY] = []
            self.process_router(ri)

            name = va_utils.get_snat_rule_name(ri)
            self.rest.del_cfg_objs(va_utils.REST_URL_CONF_NAT_RULE, name)

            name = va_utils.get_dnat_rule_name(ri)
            self.rest.del_cfg_objs(va_utils.REST_URL_CONF_NAT_RULE, name)

            name = va_utils.get_trusted_zone_name(ri)
            self._va_unset_zone_interfaces(name, True)

            name = va_utils.get_untrusted_zone_name(ri)
            self._va_unset_zone_interfaces(name, True)

            del self.router_info[router_id]

    def _spawn_metadata_proxy(self, router_id, ns_name):
        return

    def _destroy_metadata_proxy(self, router_id, ns_name):
        return

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
            return
        if len(ips) > 1:
            LOG.warn(_("Ignoring multiple IPs on router port %s"), port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def _va_unset_zone_interfaces(self, zone_name, remove_zone=False):
        # return True if zone exists; otherwise, return False
        LOG.debug(_("_va_unset_zone_interfaces: %s"), zone_name)
        resp = self.rest.rest_api('GET', va_utils.REST_URL_CONF_ZONE)
        if resp and resp['status'] == 200:
            zlist = resp['body']['response']
            for zn in zlist:
                if zn == zone_name:
                    commit = False

                    if 'interface' in zlist[zn]:
                        for intf in zlist[zn]['interface']:
                            self.rest.rest_api('DELETE',
                                               va_utils.REST_URL_CONF +
                                               va_utils.REST_ZONE_NAME % zn +
                                               va_utils.REST_INTF_NAME % intf)
                            commit = True
                    if remove_zone:
                        self.rest.rest_api('DELETE',
                                           va_utils.REST_URL_CONF +
                                           va_utils.REST_ZONE_NAME % zn)
                        commit = True

                    if commit:
                        self.rest.commit()

                    return True

        return False

    def _va_pif_2_lif(self, pif):
        return pif + '.0'

    def _va_set_interface_ip(self, pif, cidr):
        LOG.debug(_("_va_set_interface_ip: %(pif)s %(cidr)s"),
                  {'pif': pif, 'cidr': cidr})

        lif = self._va_pif_2_lif(pif)
        obj = va_utils.REST_INTF_NAME % pif + va_utils.REST_LOGIC_NAME % lif
        body = {
            'name': lif,
            'family': 'ipv4',
            'address': cidr
        }
        self.rest.rest_api('PUT', va_utils.REST_URL_CONF + obj, body)

    def _va_get_port_name(self, port_list, name):
        if name:
            for p in port_list:
                if p['VM name'] == name:
                    return p['name']

    def _va_config_trusted_zone(self, ri, plist):
        zone = va_utils.get_trusted_zone_name(ri)
        LOG.debug(_("_va_config_trusted_zone: %s"), zone)

        body = {
            'name': zone,
            'type': 'L3',
            'interface': []
        }

        if not self._va_unset_zone_interfaces(zone):
            # if zone doesn't exist, create it
            self.rest.rest_api('POST', va_utils.REST_URL_CONF_ZONE, body)
            self.rest.commit()

        # add new internal ports to trusted zone
        for p in ri.internal_ports:
            if p['admin_state_up']:
                dev = self.get_internal_device_name(p['id'])
                pif = self._va_get_port_name(plist, dev)
                if pif:
                    lif = self._va_pif_2_lif(pif)
                    if lif not in body['interface']:
                        body['interface'].append(lif)

                        self._va_set_interface_ip(pif, p['ip_cidr'])

        if body['interface']:
            self.rest.rest_api('PUT', va_utils.REST_URL_CONF_ZONE, body)
            self.rest.commit()

    def _va_config_untrusted_zone(self, ri, plist):
        zone = va_utils.get_untrusted_zone_name(ri)
        LOG.debug(_("_va_config_untrusted_zone: %s"), zone)

        body = {
            'name': zone,
            'type': 'L3',
            'interface': []
        }

        if not self._va_unset_zone_interfaces(zone):
            # if zone doesn't exist, create it
            self.rest.rest_api('POST', va_utils.REST_URL_CONF_ZONE, body)
            self.rest.commit()

        # add new gateway ports to untrusted zone
        if ri.ex_gw_port:
            LOG.debug(_("_va_config_untrusted_zone: gw=%r"), ri.ex_gw_port)
            dev = self.get_external_device_name(ri.ex_gw_port['id'])
            pif = self._va_get_port_name(plist, dev)
            if pif:
                lif = self._va_pif_2_lif(pif)

                self._va_set_interface_ip(pif, ri.ex_gw_port['ip_cidr'])

                body['interface'].append(lif)
                self.rest.rest_api('PUT', va_utils.REST_URL_CONF_ZONE, body)
                self.rest.commit()

    def _va_config_router_snat_rules(self, ri, plist):
        LOG.debug(_('_va_config_router_snat_rules: %s'), ri.router['id'])

        prefix = va_utils.get_snat_rule_name(ri)
        self.rest.del_cfg_objs(va_utils.REST_URL_CONF_NAT_RULE, prefix)

        if not ri.enable_snat:
            return

        for idx, p in enumerate(ri.internal_ports):
            if p['admin_state_up']:
                dev = self.get_internal_device_name(p['id'])
                pif = self._va_get_port_name(plist, dev)
                if pif:
                    net = netaddr.IPNetwork(p['ip_cidr'])
                    body = {
                        'name': '%s_%d' % (prefix, idx),
                        'ingress-context-type': 'interface',
                        'ingress-index': self._va_pif_2_lif(pif),
                        'source-address': [
                            [str(netaddr.IPAddress(net.first + 2)),
                             str(netaddr.IPAddress(net.last - 1))]
                        ],
                        'flag': 'interface translate-source'
                    }
                    self.rest.rest_api('POST',
                                       va_utils.REST_URL_CONF_NAT_RULE,
                                       body)

        if ri.internal_ports:
            self.rest.commit()

    def _va_config_floating_ips(self, ri):
        LOG.debug(_('_va_config_floating_ips: %s'), ri.router['id'])

        prefix = va_utils.get_dnat_rule_name(ri)
        self.rest.del_cfg_objs(va_utils.REST_URL_CONF_NAT_RULE, prefix)

        # add new dnat rules
        for idx, fip in enumerate(ri.floating_ips):
            body = {
                'name': '%s_%d' % (prefix, idx),
                'ingress-context-type': 'zone',
                'ingress-index': va_utils.get_untrusted_zone_name(ri),
                'destination-address': [[fip['floating_ip_address'],
                                         fip['floating_ip_address']]],
                'static': [fip['fixed_ip_address'], fip['fixed_ip_address']],
                'flag': 'translate-destination'
            }
            self.rest.rest_api('POST', va_utils.REST_URL_CONF_NAT_RULE, body)

        if ri.floating_ips:
            self.rest.commit()

    def process_router(self, ri):
        LOG.debug(_("process_router: %s"), ri.router['id'])
        super(vArmourL3NATAgent, self).process_router(ri)

        self.rest.auth()

        # read internal port name and configuration port name map
        resp = self.rest.rest_api('GET', va_utils.REST_URL_INTF_MAP)
        if resp and resp['status'] == 200:
            try:
                plist = resp['body']['response']
            except ValueError:
                LOG.warn(_("Unable to parse interface mapping."))
                return
        else:
            LOG.warn(_("Unable to read interface mapping."))
            return

        if ri.ex_gw_port:
            self._set_subnet_info(ri.ex_gw_port)
        self._va_config_trusted_zone(ri, plist)
        self._va_config_untrusted_zone(ri, plist)
        self._va_config_router_snat_rules(ri, plist)
        self._va_config_floating_ips(ri)

    def _handle_router_snat_rules(self, ri, ex_gw_port, internal_cidrs,
                                  interface_name, action):
        return

    def _send_gratuitous_arp_packet(self, ri, interface_name, ip_address):
        return

    def external_gateway_added(self, ri, ex_gw_port,
                               interface_name, internal_cidrs):
        LOG.debug(_("external_gateway_added: %s"), ri.router['id'])

        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ri.ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ri.ns_name,
                             prefix=l3_agent.EXTERNAL_DEV_PREFIX)
        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ri.ns_name)

    def _update_routing_table(self, ri, operation, route):
        return


class vArmourL3NATAgentWithStateReport(vArmourL3NATAgent,
                                       l3_agent.L3NATAgentWithStateReport):
    pass


def main():
    conf = cfg.CONF
    conf.register_opts(vArmourL3NATAgent.OPTS)
    conf.register_opts(l3_ha_agent.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.services.firewall.agents.varmour.varmour_router.'
                'vArmourL3NATAgentWithStateReport')
    service.launch(server).wait()
