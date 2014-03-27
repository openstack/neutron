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
    _PORT_SECURITY_SET_DATA = 'Msvm_EthernetSwitchPortSecuritySettingData'
    _PORT_ALLOC_ACL_SET_DATA = 'Msvm_EthernetSwitchPortAclSettingData'
    _PORT_EXT_ACL_SET_DATA = _PORT_ALLOC_ACL_SET_DATA
    _LAN_ENDPOINT = 'Msvm_LANEndpoint'
    _STATE_DISABLED = 3
    _OPERATION_MODE_ACCESS = 1

    _VIRTUAL_SYSTEM_SETTING_DATA = 'Msvm_VirtualSystemSettingData'
    _VM_SUMMARY_ENABLED_STATE = 100
    _HYPERV_VM_STATE_ENABLED = 2

    _ACL_DIR_IN = 1
    _ACL_DIR_OUT = 2

    _ACL_TYPE_IPV4 = 2
    _ACL_TYPE_IPV6 = 3

    _ACL_ACTION_ALLOW = 1
    _ACL_ACTION_DENY = 2
    _ACL_ACTION_METER = 3

    _METRIC_ENABLED = 2
    _NET_IN_METRIC_NAME = 'Filtered Incoming Network Traffic'
    _NET_OUT_METRIC_NAME = 'Filtered Outgoing Network Traffic'

    _ACL_APPLICABILITY_LOCAL = 1
    _ACL_APPLICABILITY_REMOTE = 2

    _ACL_DEFAULT = 'ANY'
    _IPV4_ANY = '0.0.0.0/0'
    _IPV6_ANY = '::/0'
    _TCP_PROTOCOL = 'tcp'
    _UDP_PROTOCOL = 'udp'
    _ICMP_PROTOCOL = '1'
    _MAX_WEIGHT = 65500

    # 2 directions x 2 address types = 4 ACLs
    _REJECT_ACLS_COUNT = 4

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

    def _remove_virt_feature(self, feature_resource):
        self._remove_multiple_virt_features([feature_resource])

    def _remove_multiple_virt_features(self, feature_resources):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        (job_path, ret_val) = vs_man_svc.RemoveFeatureSettings(
            FeatureSettings=[f.path_() for f in feature_resources])
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
                msg=_('Port Allocation not found: %s') % switch_port_name)

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
                _acls = self._filter_acls(
                    acls, self._ACL_ACTION_METER, acl_dir, acl_type)

                if not _acls:
                    acl = self._create_acl(
                        acl_dir, acl_type, self._ACL_ACTION_METER)
                    self._add_virt_feature(port, acl)

    def enable_control_metrics(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return

        metric_svc = self._conn.Msvm_MetricService()[0]
        metric_names = [self._NET_IN_METRIC_NAME, self._NET_OUT_METRIC_NAME]

        for metric_name in metric_names:
            metric_def = self._conn.CIM_BaseMetricDefinition(Name=metric_name)
            if metric_def:
                metric_svc.ControlMetrics(
                    Subject=port.path_(),
                    Definition=metric_def[0].path_(),
                    MetricCollectionEnabled=self._METRIC_ENABLED)

    def can_enable_control_metrics(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return False

        if not self._is_port_vm_started(port):
            return False

        # all 4 meter ACLs must be existent first. (2 x direction)
        acls = port.associators(wmi_result_class=self._PORT_ALLOC_ACL_SET_DATA)
        acls = [a for a in acls if a.Action == self._ACL_ACTION_METER]
        if len(acls) < 2:
            return False
        return True

    def _is_port_vm_started(self, port):
        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        vmsettings = port.associators(
            wmi_result_class=self._VIRTUAL_SYSTEM_SETTING_DATA)
        #See http://msdn.microsoft.com/en-us/library/cc160706%28VS.85%29.aspx
        (ret_val, summary_info) = vs_man_svc.GetSummaryInformation(
            [self._VM_SUMMARY_ENABLED_STATE],
            [v.path_() for v in vmsettings])
        if ret_val or not summary_info:
            raise utils.HyperVException(msg=_('Cannot get VM summary data '
                                              'for: %s') % port.ElementName)

        return summary_info[0].EnabledState is self._HYPERV_VM_STATE_ENABLED

    def create_security_rule(self, switch_port_name, direction, acl_type,
                             local_port, protocol, remote_address):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            return

        # Add the ACLs only if they don't already exist
        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        weight = self._get_new_weight(acls)
        self._bind_security_rule(
            port, direction, acl_type, self._ACL_ACTION_ALLOW, local_port,
            protocol, remote_address, weight)

    def remove_security_rule(self, switch_port_name, direction, acl_type,
                             local_port, protocol, remote_address):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            # Port not found. It happens when the VM was already deleted.
            return

        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        filtered_acls = self._filter_security_acls(
            acls, self._ACL_ACTION_ALLOW, direction, acl_type, local_port,
            protocol, remote_address)

        for acl in filtered_acls:
            self._remove_virt_feature(acl)

    def remove_all_security_rules(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            # Port not found. It happens when the VM was already deleted.
            return

        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        filtered_acls = [a for a in acls if
                         a.Action is not self._ACL_ACTION_METER]

        if filtered_acls:
            self._remove_multiple_virt_features(filtered_acls)

    def create_default_reject_all_rules(self, switch_port_name):
        port, found = self._get_switch_port_allocation(switch_port_name, False)
        if not found:
            raise utils.HyperVException(
                msg=_('Port Allocation not found: %s') % switch_port_name)

        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        filtered_acls = [v for v in acls if v.Action == self._ACL_ACTION_DENY]

        if len(filtered_acls) >= self._REJECT_ACLS_COUNT:
            return

        for acl in filtered_acls:
            self._remove_virt_feature(acl)

        weight = 0
        ipv4_pair = (self._ACL_TYPE_IPV4, self._IPV4_ANY)
        ipv6_pair = (self._ACL_TYPE_IPV6, self._IPV6_ANY)
        for direction in [self._ACL_DIR_IN, self._ACL_DIR_OUT]:
            for acl_type, address in [ipv4_pair, ipv6_pair]:
                for protocol in [self._TCP_PROTOCOL,
                                 self._UDP_PROTOCOL,
                                 self._ICMP_PROTOCOL]:
                    self._bind_security_rule(
                        port, direction, acl_type, self._ACL_ACTION_DENY,
                        self._ACL_DEFAULT, protocol, address, weight)
                    weight += 1

    def _bind_security_rule(self, port, direction, acl_type, action,
                            local_port, protocol, remote_address, weight):
        acls = port.associators(wmi_result_class=self._PORT_EXT_ACL_SET_DATA)
        filtered_acls = self._filter_security_acls(
            acls, action, direction, acl_type, local_port, protocol,
            remote_address)

        for acl in filtered_acls:
            self._remove_virt_feature(acl)

        acl = self._create_security_acl(
            direction, acl_type, action, local_port, protocol, remote_address,
            weight)

        self._add_virt_feature(port, acl)

    def _create_acl(self, direction, acl_type, action):
        acl = self._get_default_setting_data(self._PORT_ALLOC_ACL_SET_DATA)
        acl.set(Direction=direction,
                AclType=acl_type,
                Action=action,
                Applicability=self._ACL_APPLICABILITY_LOCAL)
        return acl

    def _create_security_acl(self, direction, acl_type, action, local_port,
                             protocol, remote_ip_address, weight):
        acl = self._create_acl(direction, acl_type, action)
        (remote_address, remote_prefix_length) = remote_ip_address.split('/')
        acl.set(Applicability=self._ACL_APPLICABILITY_REMOTE,
                RemoteAddress=remote_address,
                RemoteAddressPrefixLength=remote_prefix_length)
        return acl

    def _filter_acls(self, acls, action, direction, acl_type, remote_addr=""):
        return [v for v in acls
                if v.Action == action and
                v.Direction == direction and
                v.AclType == acl_type and
                v.RemoteAddress == remote_addr]

    def _filter_security_acls(self, acls, acl_action, direction, acl_type,
                              local_port, protocol, remote_addr=""):
        (remote_address, remote_prefix_length) = remote_addr.split('/')
        remote_prefix_length = int(remote_prefix_length)

        return [v for v in acls
                if v.Direction == direction and
                v.Action in [self._ACL_ACTION_ALLOW, self._ACL_ACTION_DENY] and
                v.AclType == acl_type and
                v.RemoteAddress == remote_address and
                v.RemoteAddressPrefixLength == remote_prefix_length]

    def _get_new_weight(self, acls):
        return 0


class HyperVUtilsV2R2(HyperVUtilsV2):
    _PORT_EXT_ACL_SET_DATA = 'Msvm_EthernetSwitchPortExtendedAclSettingData'
    _MAX_WEIGHT = 65500

    # 2 directions x 2 address types x 3 protocols = 12 ACLs
    _REJECT_ACLS_COUNT = 12

    def _create_security_acl(self, direction, acl_type, action, local_port,
                             protocol, remote_addr, weight):
        acl = self._get_default_setting_data(self._PORT_EXT_ACL_SET_DATA)
        acl.set(Direction=direction,
                Action=action,
                LocalPort=str(local_port),
                Protocol=protocol,
                RemoteIPAddress=remote_addr,
                IdleSessionTimeout=0,
                Weight=weight)
        return acl

    def _filter_security_acls(self, acls, action, direction, acl_type,
                              local_port, protocol, remote_addr=""):
        return [v for v in acls
                if v.Action == action and
                v.Direction == direction and
                v.LocalPort == str(local_port) and
                v.Protocol == protocol and
                v.RemoteIPAddress == remote_addr]

    def _get_new_weight(self, acls):
        acls = [a for a in acls if a.Action is not self._ACL_ACTION_DENY]
        if not acls:
            return self._MAX_WEIGHT - 1

        weights = [a.Weight for a in acls]
        min_weight = min(weights)
        for weight in range(min_weight, self._MAX_WEIGHT):
            if weight not in weights:
                return weight

        return min_weight - 1
