# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions SRL
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
# @author: Alessandro Pilotti, Cloudbase Solutions Srl
# @author: Claudiu Belu, Cloudbase Solutions Srl

from neutron.plugins.hyperv.agent import utils


class HyperVUtilsV2(utils.HyperVUtils):

    _EXTERNAL_PORT = 'Msvm_ExternalEthernetPort'
    _ETHERNET_SWITCH_PORT = 'Msvm_EthernetSwitchPort'
    _PORT_ALLOC_SET_DATA = 'Msvm_EthernetPortAllocationSettingData'
    _PORT_VLAN_SET_DATA = 'Msvm_EthernetSwitchPortVlanSettingData'
    _PORT_ALLOC_ACL_SET_DATA = 'Msvm_EthernetSwitchPortAclSettingData'
    _LAN_ENDPOINT = 'Msvm_LANEndpoint'
    _STATE_DISABLED = 3
    _OPERATION_MODE_ACCESS = 1

    _ACL_DIR_IN = 1
    _ACL_DIR_OUT = 2
    _ACL_TYPE_IPV4 = 2
    _ACL_TYPE_IPV6 = 3
    _ACL_ACTION_METER = 3
    _ACL_APPLICABILITY_LOCAL = 1

    _wmi_namespace = '//./root/virtualization/v2'

    def __init__(self):
        super(HyperVUtilsV2, self).__init__()

    def connect_vnic_to_vswitch(self, vswitch_name, switch_port_name):
        vnic = self._get_vnic_settings(switch_port_name)
        vswitch = self._get_vswitch(vswitch_name)

        port, found = self._get_switch_port_allocation(switch_port_name, True)
        port.HostResource = [vswitch.path_()]
        port.Parent = vnic.path_()
        if not found:
            vm = self._get_vm_from_res_setting_data(vnic)
            self._add_virt_resource(vm, port)
        else:
            self._modify_virt_resource(port)

    def _modify_virt_resource(self, res_setting_data):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        (job_path, out_set_data, ret_val) = vs_man_svc.ModifyResourceSettings(
            ResourceSettings=[res_setting_data.GetText_(1)])
        self._check_job_status(ret_val, job_path)

    def _add_virt_resource(self, vm, res_setting_data):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        (job_path, out_set_data, ret_val) = vs_man_svc.AddResourceSettings(
            vm.path_(), [res_setting_data.GetText_(1)])
        self._check_job_status(ret_val, job_path)

    def _remove_virt_resource(self, res_setting_data):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        (job, ret_val) = vs_man_svc.RemoveResourceSettings(
            ResourceSettings=[res_setting_data.path_()])
        self._check_job_status(ret_val, job)

    def _add_virt_feature(self, element, res_setting_data):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        (job_path, out_set_data, ret_val) = vs_man_svc.AddFeatureSettings(
            element.path_(), [res_setting_data.GetText_(1)])
        self._check_job_status(ret_val, job_path)

    def disconnect_switch_port(
            self, vswitch_name, switch_port_name, delete_port):
        """Disconnects the switch port."""
        sw_port, found = self._get_switch_port_allocation(switch_port_name)
        if not sw_port:
            # Port not found. It happens when the VM was already deleted.
            return

        if delete_port:
            self._remove_virt_resource(sw_port)
        else:
            sw_port.EnabledState = self._STATE_DISABLED
            self._modify_virt_resource(sw_port)

    def _get_vswitch(self, vswitch_name):
        vswitch = self._conn.Msvm_VirtualEthernetSwitch(
            ElementName=vswitch_name)
        if not len(vswitch):
            raise utils.HyperVException(msg=_('VSwitch not found: %s') %
                                        vswitch_name)
        return vswitch[0]

    def _get_vswitch_external_port(self, vswitch):
        vswitch_ports = vswitch.associators(
            wmi_result_class=self._ETHERNET_SWITCH_PORT)
        for vswitch_port in vswitch_ports:
            lan_endpoints = vswitch_port.associators(
                wmi_result_class=self._LAN_ENDPOINT)
            if len(lan_endpoints):
                lan_endpoints = lan_endpoints[0].associators(
                    wmi_result_class=self._LAN_ENDPOINT)
                if len(lan_endpoints):
                    ext_port = lan_endpoints[0].associators(
                        wmi_result_class=self._EXTERNAL_PORT)
                    if ext_port:
                        return vswitch_port

    def set_vswitch_port_vlan_id(self, vlan_id, switch_port_name):
        port_alloc, found = self._get_switch_port_allocation(switch_port_name)
        if not found:
            raise utils.HyperVException(
                msg=_('Port Alloc not found: %s') % switch_port_name)

        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        vlan_settings = self._get_vlan_setting_data_from_port_alloc(port_alloc)
        if vlan_settings:
            # Removing the feature because it cannot be modified
            # due to a wmi exception.
            (job_path, ret_val) = vs_man_svc.RemoveFeatureSettings(
                FeatureSettings=[vlan_settings.path_()])
            self._check_job_status(ret_val, job_path)

        (vlan_settings, found) = self._get_vlan_setting_data(switch_port_name)
        vlan_settings.AccessVlanId = vlan_id
        vlan_settings.OperationMode = self._OPERATION_MODE_ACCESS
        (job_path, out, ret_val) = vs_man_svc.AddFeatureSettings(
            port_alloc.path_(), [vlan_settings.GetText_(1)])
        self._check_job_status(ret_val, job_path)

    def _get_vlan_setting_data_from_port_alloc(self, port_alloc):
        return self._get_first_item(port_alloc.associators(
            wmi_result_class=self._PORT_VLAN_SET_DATA))

    def _get_vlan_setting_data(self, switch_port_name, create=True):
        return self._get_setting_data(
            self._PORT_VLAN_SET_DATA,
            switch_port_name, create)

    def _get_switch_port_allocation(self, switch_port_name, create=False):
        return self._get_setting_data(
            self._PORT_ALLOC_SET_DATA,
            switch_port_name, create)

    def _get_setting_data(self, class_name, element_name, create=True):
        element_name = element_name.replace("'", '"')
        q = self._conn.query("SELECT * FROM %(class_name)s WHERE "
                             "ElementName = '%(element_name)s'" %
                             {"class_name": class_name,
                              "element_name": element_name})
        data = self._get_first_item(q)
        found = data is not None
        if not data and create:
            data = self._get_default_setting_data(class_name)
            data.ElementName = element_name
        return data, found

    def _get_default_setting_data(self, class_name):
        return self._conn.query("SELECT * FROM %s WHERE InstanceID "
                                "LIKE '%%\\Default'" % class_name)[0]

    def _get_first_item(self, obj):
        if obj:
            return obj[0]

    def enable_port_metrics_collection(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return

        # Add the ACLs only if they don't already exist
        acls = port.associators(wmi_result_class=self._PORT_ALLOC_ACL_SET_DATA)
        for acl_type in [self._ACL_TYPE_IPV4, self._ACL_TYPE_IPV6]:
            for acl_dir in [self._ACL_DIR_IN, self._ACL_DIR_OUT]:
                acls = [v for v in acls
                        if v.Action == self._ACL_ACTION_METER and
                        v.Applicability == self._ACL_APPLICABILITY_LOCAL and
                        v.Direction == acl_dir and
                        v.AclType == acl_type]
                if not acls:
                    acl = self._get_default_setting_data(
                        self._PORT_ALLOC_ACL_SET_DATA)
                    acl.AclType = acl_type
                    acl.Direction = acl_dir
                    acl.Action = self._ACL_ACTION_METER
                    acl.Applicability = self._ACL_APPLICABILITY_LOCAL
                    self._add_virt_feature(port, acl)
