# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron.openstack.common import uuidutils


class FakeNuageClient(object):
    def __init__(self, server, base_uri, serverssl,
                 serverauth, auth_resource, organization):
        pass

    def rest_call(self, action, resource, data, extra_headers=None):
        pass

    def vms_on_l2domain(self, l2dom_id):
        pass

    def vms_on_subnet(self, subnet_id):
        pass

    def create_subnet(self, neutron_subnet, params):
        nuage_subnet = {
            'nuage_l2template_id': uuidutils.generate_uuid(),
            'nuage_userid': uuidutils.generate_uuid(),
            'nuage_groupid': uuidutils.generate_uuid(),
            'nuage_l2domain_id': uuidutils.generate_uuid()
        }
        return nuage_subnet

    def update_subnet(self, neutron_subnet, params):
        pass

    def delete_subnet(self, id):
        pass

    def create_router(self, neutron_router, router, params):
        nuage_router = {
            'nuage_userid': uuidutils.generate_uuid(),
            'nuage_groupid': uuidutils.generate_uuid(),
            'nuage_domain_id': uuidutils.generate_uuid(),
            'nuage_def_zone_id': uuidutils.generate_uuid(),
        }
        return nuage_router

    def delete_router(self, id):
        pass

    def delete_user(self, id):
        pass

    def delete_group(self, id):
        pass

    def create_domain_subnet(self, neutron_subnet, params):
        pass

    def delete_domain_subnet(self, id):
        pass

    def create_net_partition(self, params):
        fake_net_partition = {
            'nuage_entid': uuidutils.generate_uuid(),
            'l3dom_id': uuidutils.generate_uuid(),
            'l2dom_id': uuidutils.generate_uuid(),
        }
        return fake_net_partition

    def get_def_netpartition_data(self, default_net_part):
        if default_net_part == 'default_test_np':
            fake_defnetpart_data = {
                'np_id': uuidutils.generate_uuid(),
                'l3dom_tid': uuidutils.generate_uuid(),
                'l2dom_tid': uuidutils.generate_uuid(),
            }
            return fake_defnetpart_data

    def get_net_partition_id_by_name(self, name):
        return uuidutils.generate_uuid()

    def delete_net_partition(self, id, l3dom_id=None, l2dom_id=None):
        pass

    def check_del_def_net_partition(self, ent_name):
        pass

    def create_vms(self, params):
        pass

    def delete_vms(self, params):
        pass

    def create_nuage_staticroute(self, params):
        return uuidutils.generate_uuid()

    def delete_nuage_staticroute(self, id):
        pass

    def create_nuage_sharedresource(self, params):
        return uuidutils.generate_uuid()

    def delete_nuage_sharedresource(self, id):
        pass

    def create_nuage_floatingip(self, params):
        return uuidutils.generate_uuid()

    def delete_nuage_floatingip(self, id):
        pass

    def update_nuage_vm_vport(self, params):
        pass

    def get_nuage_fip_pool_by_id(self, net_id):
        result = {
            'nuage_fip_pool_id': uuidutils.generate_uuid()
        }
        return result

    def get_nuage_fip_by_id(self, params):
        if 'neutron_fip' in params:
            neutron_fip = params['neutron_fip']
            if (neutron_fip['floating_ip_address'] == '12.0.0.3' and
                neutron_fip['fixed_ip_address'] == '10.0.1.2') or (
                    neutron_fip['floating_ip_address'] == '12.0.0.5' and
                    neutron_fip['fixed_ip_address'] == '10.0.1.3'):
                result = {
                    'nuage_fip_id': '1',
                    'nuage_parent_id': '1'
                }
                return result

    def get_nuage_port_by_id(self, params):
        if 'nuage_fip_id' in params and params['nuage_fip_id'] == '1':
            domain_id = uuidutils.generate_uuid()
        else:
            if 'nuage_router_id' in params:
                domain_id = params['nuage_router_id']
            else:
                return

        result = {
            'nuage_vif_id': uuidutils.generate_uuid(),
            'nuage_vport_id': uuidutils.generate_uuid(),
            'nuage_domain_id': domain_id
        }

        return result

    def get_zone_by_routerid(self, neutron_router_id):
        result = {
            'nuage_zone_id': uuidutils.generate_uuid()
        }
        return result

    def get_usergroup(self, tenant, net_partition_id):
        return uuidutils.generate_uuid(), uuidutils.generate_uuid()

    def get_sg_vptag_mapping(self, id):
        pass

    def validate_nuage_sg_rule_definition(self, params):
        pass

    def create_nuage_sgrule(self, params):
        pass

    def update_nuage_vport(self, params):
        pass

    def delete_nuage_sgrule(self, params):
        pass

    def delete_nuage_secgroup(self, params):
        pass

    def process_port_create_security_group(self, params):
        pass

    def delete_port_security_group_bindings(self, params):
        pass

    def validate_provider_network(self, net_type, phy_net, vlan_id):
        pass

    def remove_router_interface(self, params):
        pass

    def get_resources_to_sync(self, data):
        netpart_id_list = []
        for netpart in data['netpartition']:
            netpart_id_list.append(netpart['id'])

        netpart_dict = {
            'add': netpart_id_list,
            'sync': []
        }

        subn_id_list = []
        if data['subnet']:
            subn_id_list.append(data['subnet'][0])

        l2domain_dict = {
            'add': subn_id_list
        }

        rtr_id_list = []
        if data['router']:
            rtr_id_list.append(data['router'][0])

        domain_dict = {
            'add': rtr_id_list
        }

        domain_subn_id = uuidutils.generate_uuid()

        result = {
            'netpartition': netpart_dict,
            'l2domain': l2domain_dict,
            'domain': domain_dict,
            'domainsubnet': {'add': [domain_subn_id]},
            'sharednetwork': {'add': [uuidutils.generate_uuid()]},
            'route': {'add': []},
            'security': {
                'secgroup': {
                    'l2domain': {'add': {
                        uuidutils.generate_uuid(): [uuidutils.generate_uuid()]
                    }},
                    'domain': {'add': {
                        uuidutils.generate_uuid(): [uuidutils.generate_uuid()]
                    }}
                },
                'secgrouprule': {
                    'l2domain': {'add': [uuidutils.generate_uuid()]},
                    'domain': {'add': [uuidutils.generate_uuid()]}
                },
            },
            'port': {
                'vm': [uuidutils.generate_uuid()],
                'sub_rtr_intf_port_dict': {
                    domain_subn_id: uuidutils.generate_uuid()
                },
                'secgroup': [uuidutils.generate_uuid()]
            },
            'subl2dommapping': [uuidutils.generate_uuid()],
            'fip': {
                'add': [uuidutils.generate_uuid()],
                'associate': [uuidutils.generate_uuid()],
                'disassociate': [uuidutils.generate_uuid()]
            }
        }
        return result

    def create_netpart(self, netpart, fip_quota):
        if netpart['name'] == 'sync-new-netpartition':
            oldid = netpart['id']
            netpart['id'] = 'a917924f-3139-4bdb-a4c3-ea7c8011582f'
            netpart = {
                oldid: netpart
            }
            return netpart
        return {}

    def create_sharednetwork(self, subnet):
        pass

    def create_l2domain(self, netpart_id, subnet):
        subl2dom = {
            'subnet_id': subnet['id'],
            'nuage_subnet_id': '52daa465-cf33-4efd-91d3-f5bc2aebd',
            'net_partition_id': netpart_id,
            'nuage_l2dom_tmplt_id': uuidutils.generate_uuid(),
            'nuage_user_id': uuidutils.generate_uuid(),
            'nuage_group_id': uuidutils.generate_uuid(),
        }

        return subl2dom

    def create_domain(self, netpart, router):
        entrtr = {
            'router_id': router['id'],
            'nuage_router_id': '2d782c02-b88e-44ad-a79b-4bdf11f7df3d',
            'net_partition_id': netpart['id']
        }

        return entrtr

    def create_domainsubnet(self, subnet, ports):
        pass

    def create_route(self, route):
        pass

    def create_vm(self, port):
        pass

    def create_security_group(self, secgrp, ports):
        pass

    def create_security_group_rule(self, secgrprule):
        pass

    def create_fip(self, fip, ipalloc):
        pass

    def associate_fip(self, fip):
        pass

    def disassociate_fip(self, fip):
        pass
