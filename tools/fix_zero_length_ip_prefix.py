"""
This script is needed to convert addresses that are zero prefix to be two
address of one prefix to avoid a bug that exists in juno where the ipset
manager isn't able to handle zero prefix lenght addresses.
"""

import os
import sys

import netaddr
from neutronclient.v2_0 import client


def main():
    try:
        username = os.environ['OS_USERNAME']
        tenant_name = os.environ['OS_TENANT_NAME']
        password = os.environ['OS_PASSWORD']
        auth_url = os.environ['OS_AUTH_URL']
    except KeyError:
        print("You need to source your openstack creds file first!")
        sys.exit(1)

    neutron = client.Client(username=username,
                            tenant_name=tenant_name,
                            password=password,
                            auth_url=auth_url)

    ports = neutron.list_ports()
    for port in ports['ports']:
        new_address_pairs = []
        needs_update = False
        allowed_address_pairs = port.get('allowed_address_pairs')
        if allowed_address_pairs:
            for address_pair in allowed_address_pairs:
                ip = address_pair['ip_address']
                mac = address_pair['mac_address']
                if(netaddr.IPNetwork(ip).prefixlen == 0):
                    needs_update = True
                    if(netaddr.IPNetwork(ip).version == 4):
                        new_address_pairs.append({'ip_address': '0.0.0.0/1',
                                                  'mac_address': mac})
                        new_address_pairs.append({'ip_address': '128.0.0.0/1',
                                                  'mac_address': mac})
                    elif(netaddr.IPNetwork(ip).version == 6):
                        new_address_pairs.append({'ip_address': '::/1',
                                                  'mac_address': mac})
                        new_address_pairs.append({'ip_address': '8000::/1',
                                                  'mac_address': mac})
                else:
                    new_address_pairs.append(address_pair)
            if needs_update:
                print ("Updating port %s with new address_pairs %s" %
                       (port['id'], new_address_pairs))
                neutron.update_port(
                    port['id'],
                    {'port': {'allowed_address_pairs': new_address_pairs}})

main()
