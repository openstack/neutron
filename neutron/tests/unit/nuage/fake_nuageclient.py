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
#
# @author: Ronak Shah, Aniket Dandekar, Nuage Networks, Alcatel-Lucent USA Inc.

from neutron.openstack.common import uuidutils


class FakeNuageClient(object):
    def __init__(self, server, base_uri, serverssl,
                 serverauth, auth_resource, organization):
        pass

    def rest_call(self, action, resource, data, extra_headers=None):
        pass

    def vms_on_l2domain(self, l2dom_id):
        pass

    def create_subnet(self, neutron_subnet, params):
        nuage_subnet = {
            'nuage_l2template_id': uuidutils.generate_uuid(),
            'nuage_userid': uuidutils.generate_uuid(),
            'nuage_groupid': uuidutils.generate_uuid(),
            'nuage_l2domain_id': uuidutils.generate_uuid()
        }
        return nuage_subnet

    def delete_subnet(self, id, template_id):
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
