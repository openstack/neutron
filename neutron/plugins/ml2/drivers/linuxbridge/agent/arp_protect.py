# Copyright (c) 2015 Mirantis, Inc.
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

import netaddr
from neutron_lib.utils import net
from oslo_concurrency import lockutils
from oslo_log import log as logging
import tenacity

from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)
SPOOF_CHAIN_PREFIX = 'neutronARP-'
MAC_CHAIN_PREFIX = 'neutronMAC-'


def setup_arp_spoofing_protection(vif, port_details):
    if not port_details.get('port_security_enabled', True):
        # clear any previous entries related to this port
        delete_arp_spoofing_protection([vif])
        LOG.info("Skipping ARP spoofing rules for port '%s' because "
                 "it has port security disabled", vif)
        return
    if net.is_port_trusted(port_details):
        # clear any previous entries related to this port
        delete_arp_spoofing_protection([vif])
        LOG.debug("Skipping ARP spoofing rules for network owned port "
                  "'%s'.", vif)
        return
    _setup_arp_spoofing_protection(vif, port_details)


@lockutils.synchronized('ebtables')
def _setup_arp_spoofing_protection(vif, port_details):
    current_rules = ebtables(['-L']).splitlines()
    _install_mac_spoofing_protection(vif, port_details, current_rules)
    # collect all of the addresses and cidrs that belong to the port
    addresses = {f['ip_address'] for f in port_details['fixed_ips']}
    if port_details.get('allowed_address_pairs'):
        addresses |= {p['ip_address']
                      for p in port_details['allowed_address_pairs']}

    addresses = {ip for ip in addresses
                 if netaddr.IPNetwork(ip).version == 4}
    if any(netaddr.IPNetwork(ip).prefixlen == 0 for ip in addresses):
        # don't try to install protection because a /0 prefix allows any
        # address anyway and the ARP_SPA can only match on /1 or more.
        return

    _install_arp_spoofing_protection(vif, addresses, current_rules)


def chain_name(vif):
    # start each chain with a common identifier for cleanup to find
    return '%s%s' % (SPOOF_CHAIN_PREFIX, vif)


@lockutils.synchronized('ebtables')
def delete_arp_spoofing_protection(vifs):
    current_rules = ebtables(['-L']).splitlines()
    _delete_arp_spoofing_protection(vifs, current_rules, table='nat',
                                    chain='PREROUTING')


def _delete_arp_spoofing_protection(vifs, current_rules, table, chain):
    # delete the jump rule and then delete the whole chain
    jumps = [vif for vif in vifs if vif_jump_present(vif, current_rules)]
    for vif in jumps:
        ebtables(['-D', chain, '-i', vif, '-j',
                  chain_name(vif), '-p', 'ARP'], table=table)
    for vif in vifs:
        chain_delete(chain_name(vif), table, current_rules)
    _delete_mac_spoofing_protection(vifs, current_rules, table=table,
                                    chain=chain)


@lockutils.synchronized('ebtables')
def delete_unreferenced_arp_protection(current_vifs):
    # deletes all jump rules and chains that aren't in current_vifs but match
    # the spoof prefix
    current_rules = ebtables(['-L'], table='nat').splitlines()
    to_delete = []
    for line in current_rules:
        # we're looking to find and turn the following:
        # Bridge chain: SPOOF_CHAIN_PREFIXtap199, entries: 0, policy: DROP
        # into 'tap199'
        if line.startswith('Bridge chain: %s' % SPOOF_CHAIN_PREFIX):
            devname = line.split(SPOOF_CHAIN_PREFIX, 1)[1].split(',')[0]
            if devname not in current_vifs:
                to_delete.append(devname)
    LOG.info("Clearing orphaned ARP spoofing entries for devices %s",
             to_delete)
    _delete_arp_spoofing_protection(to_delete, current_rules, table='nat',
                                    chain='PREROUTING')


@lockutils.synchronized('ebtables')
def install_arp_spoofing_protection(vif, addresses):
    current_rules = ebtables(['-L']).splitlines()
    _install_arp_spoofing_protection(vif, addresses, current_rules)


def _install_arp_spoofing_protection(vif, addresses, current_rules):
    # make a VIF-specific ARP chain so we don't conflict with other rules
    vif_chain = chain_name(vif)
    if not chain_exists(vif_chain, current_rules):
        ebtables(['-N', vif_chain, '-P', 'DROP'])
        # Append a default DROP rule at the end of the chain. This will
        # avoid "ebtables-nft" error when listing the chain.
        ebtables(['-A', vif_chain, '-j', 'DROP'])
    else:
        # Flush the chain to clear previous accepts. This will cause dropped
        # ARP packets until the allows are installed, but that's better than
        # leaked spoofed packets and ARP can handle losses.
        ebtables(['-F', vif_chain])
        ebtables(['-A', vif_chain, '-j', 'DROP'])
    for addr in sorted(addresses):
        ebtables(['-I', vif_chain, '-p', 'ARP', '--arp-ip-src', addr,
                  '-j', 'ACCEPT'])
    # check if jump rule already exists, if not, install it
    if not vif_jump_present(vif, current_rules):
        ebtables(['-A', 'PREROUTING', '-i', vif, '-j',
                  vif_chain, '-p', 'ARP'])


def chain_exists(chain, current_rules):
    for rule in current_rules:
        if rule.startswith('Bridge chain: %s' % chain):
            return True
    return False


def chain_delete(chain, table, current_rules):
    # flush and delete chain if exists
    if chain_exists(chain, current_rules):
        ebtables(['-F', chain], table=table)
        ebtables(['-X', chain], table=table)


def vif_jump_present(vif, current_rules):
    searches = (('-i %s' % vif), ('-j %s' % chain_name(vif)), ('-p ARP'))
    for line in current_rules:
        if all(s in line for s in searches):
            return True
    return False


def _install_mac_spoofing_protection(vif, port_details, current_rules):
    mac_addresses = {port_details['mac_address']}
    if port_details.get('allowed_address_pairs'):
        mac_addresses |= {p['mac_address']
                          for p in port_details['allowed_address_pairs']}
    mac_addresses = list(mac_addresses)
    vif_chain = _mac_chain_name(vif)
    # mac filter chain for each vif which has a default deny
    if not chain_exists(vif_chain, current_rules):
        ebtables(['-N', vif_chain, '-P', 'DROP'])
        # Append a default DROP rule at the end of the chain. This will
        # avoid "ebtables-nft" error when listing the chain.
        ebtables(['-A', vif_chain, '-j', 'DROP'])

    # check if jump rule already exists, if not, install it
    if not _mac_vif_jump_present(vif, current_rules):
        ebtables(['-I', 'PREROUTING', '-i', vif, '-j', vif_chain])

    _delete_vif_mac_rules(vif, current_rules)
    # we can't just feed all allowed macs at once because we can exceed
    # the maximum argument size. limit to 500 per rule.
    for chunk in (mac_addresses[i:i + 500]
                  for i in range(0, len(mac_addresses), 500)):
        new_rule = ['-I', vif_chain, '-i', vif,
                    '--among-src', ','.join(sorted(chunk)), '-j', 'RETURN']
        ebtables(new_rule)


def _mac_vif_jump_present(vif, current_rules):
    searches = (('-i %s' % vif), ('-j %s' % _mac_chain_name(vif)))
    for line in current_rules:
        if all(s in line for s in searches):
            return True
    return False


def _mac_chain_name(vif):
    return '%s%s' % (MAC_CHAIN_PREFIX, vif)


def _delete_vif_mac_rules(vif, current_rules):
    chain = _mac_chain_name(vif)
    for rule in current_rules:
        if '-i %s' % vif in rule and '--among-src' in rule:
            # Flush the table and recreate the default DROP rule.
            ebtables(['-F', chain])
            ebtables(['-A', chain, '-j', 'DROP'])


def _delete_mac_spoofing_protection(vifs, current_rules, table, chain):
    # delete the jump rule and then delete the whole chain
    jumps = [vif for vif in vifs
             if _mac_vif_jump_present(vif, current_rules)]
    for vif in jumps:
        ebtables(['-D', chain, '-i', vif, '-j',
                  _mac_chain_name(vif)], table=table)
    for vif in vifs:
        chain_delete(_mac_chain_name(vif), table, current_rules)


# Used to scope ebtables commands in testing
NAMESPACE = None


@tenacity.retry(
    wait=tenacity.wait_exponential(multiplier=0.02),
    retry=tenacity.retry_if_exception(lambda e: e.returncode in [255, 4]),
    reraise=True
)
def ebtables(comm, table='nat'):
    execute = ip_lib.IPWrapper(NAMESPACE).netns.execute
    return execute(['ebtables', '-t', table, '--concurrent'] + comm,
                   run_as_root=True, privsep_exec=True)
