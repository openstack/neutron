# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
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
# @author: Pedro Navarro Perez
# @author: Alessandro Pilotti, Cloudbase Solutions Srl

import sys
import time

from oslo.config import cfg

from quantum.common import exceptions as q_exc
from quantum.openstack.common import log as logging

# Check needed for unit testing on Unix
if sys.platform == 'win32':
    import wmi

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class HyperVException(q_exc.QuantumException):
    message = _('HyperVException: %(msg)s')

SET_ACCESS_MODE = 0
VLAN_ID_ADD = 1
VLAN_ID_REMOVE = 2
ENDPOINT_MODE_ACCESS = 2
ENDPOINT_MODE_TRUNK = 5

WMI_JOB_STATE_RUNNING = 4
WMI_JOB_STATE_COMPLETED = 7


class HyperVUtils(object):
    def __init__(self):
        self._wmi_conn = None

    @property
    def _conn(self):
        if self._wmi_conn is None:
            self._wmi_conn = wmi.WMI(moniker='//./root/virtualization')
        return self._wmi_conn

    def get_switch_ports(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        vswitch_ports = vswitch.associators(
            wmi_result_class='Msvm_SwitchPort')
        return set(p.Name for p in vswitch_ports)

    def vnic_port_exists(self, port_id):
        try:
            self._get_vnic_settings(port_id)
        except Exception:
            return False
        return True

    def get_vnic_ids(self):
        return set(
            p.ElementName
            for p in self._conn.Msvm_SyntheticEthernetPortSettingData())

    def _get_vnic_settings(self, vnic_name):
        vnic_settings = self._conn.Msvm_SyntheticEthernetPortSettingData(
            ElementName=vnic_name)
        if not len(vnic_settings):
            raise HyperVException(msg=_('Vnic not found: %s') % vnic_name)
        return vnic_settings[0]

    def connect_vnic_to_vswitch(self, vswitch_name, switch_port_name):
        vnic_settings = self._get_vnic_settings(switch_port_name)
        if not vnic_settings.Connection or not vnic_settings.Connection[0]:
            port = self.get_port_by_id(switch_port_name, vswitch_name)
            if port:
                port_path = port.Path_()
            else:
                port_path = self._create_switch_port(
                    vswitch_name, switch_port_name)
            vnic_settings.Connection = [port_path]
            self._modify_virt_resource(vnic_settings)

    def _get_vm_from_res_setting_data(self, res_setting_data):
        sd = res_setting_data.associators(
            wmi_result_class='Msvm_VirtualSystemSettingData')
        vm = sd[0].associators(
            wmi_result_class='Msvm_ComputerSystem')
        return vm[0]

    def _modify_virt_resource(self, res_setting_data):
        vm = self._get_vm_from_res_setting_data(res_setting_data)

        vs_man_svc = self._conn.Msvm_VirtualSystemManagementService()[0]
        (job_path,
         ret_val) = vs_man_svc.ModifyVirtualSystemResources(
             vm.Path_(), [res_setting_data.GetText_(1)])
        self._check_job_status(ret_val, job_path)

    def _check_job_status(self, ret_val, jobpath):
        """Poll WMI job state for completion"""
        if not ret_val:
            return
        elif ret_val != WMI_JOB_STATE_RUNNING:
            raise HyperVException(msg=_('Job failed with error %d' % ret_val))

        job_wmi_path = jobpath.replace('\\', '/')
        job = wmi.WMI(moniker=job_wmi_path)

        while job.JobState == WMI_JOB_STATE_RUNNING:
            time.sleep(0.1)
            job = wmi.WMI(moniker=job_wmi_path)
        if job.JobState != WMI_JOB_STATE_COMPLETED:
            job_state = job.JobState
            if job.path().Class == "Msvm_ConcreteJob":
                err_sum_desc = job.ErrorSummaryDescription
                err_desc = job.ErrorDescription
                err_code = job.ErrorCode
                raise HyperVException(
                    msg=_("WMI job failed with status %(job_state)d. "
                          "Error details: %(err_sum_desc)s - %(err_desc)s - "
                          "Error code: %(err_code)d") % locals())
            else:
                (error, ret_val) = job.GetError()
                if not ret_val and error:
                    raise HyperVException(
                        msg=_("WMI job failed with status %(job_state)d. "
                              "Error details: %(error)s") % locals())
                else:
                    raise HyperVException(
                        msg=_("WMI job failed with status %(job_state)d. "
                              "No error description available") % locals())

        desc = job.Description
        elap = job.ElapsedTime
        LOG.debug(_("WMI job succeeded: %(desc)s, Elapsed=%(elap)s") %
                  locals())

    def _create_switch_port(self, vswitch_name, switch_port_name):
        """ Creates a switch port """
        switch_svc = self._conn.Msvm_VirtualSwitchManagementService()[0]
        vswitch_path = self._get_vswitch(vswitch_name).path_()
        (new_port, ret_val) = switch_svc.CreateSwitchPort(
            Name=switch_port_name,
            FriendlyName=switch_port_name,
            ScopeOfResidence="",
            VirtualSwitch=vswitch_path)
        if ret_val != 0:
            raise HyperVException(
                msg=_('Failed creating port for %s') % vswitch_name)
        return new_port

    def disconnect_switch_port(
            self, vswitch_name, switch_port_name, delete_port):
        """ Disconnects the switch port """
        switch_svc = self._conn.Msvm_VirtualSwitchManagementService()[0]
        switch_port_path = self._get_switch_port_path_by_name(
            switch_port_name)
        if not switch_port_path:
            # Port not found. It happens when the VM was already deleted.
            return

        (ret_val, ) = switch_svc.DisconnectSwitchPort(
            SwitchPort=switch_port_path)
        if ret_val != 0:
            raise HyperVException(
                msg=_('Failed to disconnect port %(switch_port_name)s '
                      'from switch %(vswitch_name)s '
                      'with error %(ret_val)s') % locals())
        if delete_port:
            (ret_val, ) = switch_svc.DeleteSwitchPort(
                SwitchPort=switch_port_path)
            if ret_val != 0:
                raise HyperVException(
                    msg=_('Failed to delete port %(switch_port_name)s '
                          'from switch %(vswitch_name)s '
                          'with error %(ret_val)s') % locals())

    def _get_vswitch(self, vswitch_name):
        vswitch = self._conn.Msvm_VirtualSwitch(ElementName=vswitch_name)
        if not len(vswitch):
            raise HyperVException(msg=_('VSwitch not found: %s') %
                                  vswitch_name)
        return vswitch[0]

    def _get_vswitch_external_port(self, vswitch):
        vswitch_ports = vswitch.associators(
            wmi_result_class='Msvm_SwitchPort')
        for vswitch_port in vswitch_ports:
            lan_endpoints = vswitch_port.associators(
                wmi_result_class='Msvm_SwitchLanEndpoint')
            if len(lan_endpoints):
                ext_port = lan_endpoints[0].associators(
                    wmi_result_class='Msvm_ExternalEthernetPort')
                if ext_port:
                    return vswitch_port

    def _set_vswitch_external_port_vlan_id(self, vswitch_name, action,
                                           vlan_id=None):
        vswitch = self._get_vswitch(vswitch_name)
        ext_port = self._get_vswitch_external_port(vswitch)
        if not ext_port:
            return

        vlan_endpoint = ext_port.associators(
            wmi_association_class='Msvm_BindsTo')[0]
        vlan_endpoint_settings = vlan_endpoint.associators(
            wmi_association_class='Msvm_NetworkElementSettingData')[0]

        mode = ENDPOINT_MODE_TRUNK
        trunked_vlans = vlan_endpoint_settings.TrunkedVLANList
        new_trunked_vlans = trunked_vlans
        if action == VLAN_ID_ADD:
            if vlan_id not in trunked_vlans:
                new_trunked_vlans += (vlan_id,)
        elif action == VLAN_ID_REMOVE:
            if vlan_id in trunked_vlans:
                new_trunked_vlans = [
                    v for v in trunked_vlans if v != vlan_id
                ]
        elif action == SET_ACCESS_MODE:
            mode = ENDPOINT_MODE_ACCESS
            new_trunked_vlans = ()

        if vlan_endpoint.DesiredEndpointMode != mode:
            vlan_endpoint.DesiredEndpointMode = mode
            vlan_endpoint.put()

        if len(trunked_vlans) != len(new_trunked_vlans):
            vlan_endpoint_settings.TrunkedVLANList = new_trunked_vlans
            vlan_endpoint_settings.put()

    def set_vswitch_port_vlan_id(self, vlan_id, switch_port_name):
        vlan_endpoint_settings = self._conn.Msvm_VLANEndpointSettingData(
            ElementName=switch_port_name)[0]
        if vlan_endpoint_settings.AccessVLAN != vlan_id:
            vlan_endpoint_settings.AccessVLAN = vlan_id
            vlan_endpoint_settings.put()

    def set_vswitch_mode_access(self, vswitch_name):
        LOG.info(_('Setting vswitch %s in access mode (flat)'), vswitch_name)
        self._set_vswitch_external_port_vlan_id(vswitch_name, SET_ACCESS_MODE)

    def add_vlan_id_to_vswitch(self, vlan_id, vswitch_name):
        LOG.info(_('Adding VLAN %s to vswitch %s'),
                 vlan_id, vswitch_name)
        self._set_vswitch_external_port_vlan_id(vswitch_name, VLAN_ID_ADD,
                                                vlan_id)

    def remove_vlan_id_from_vswitch(self, vlan_id, vswitch_name):
        LOG.info(_('Removing VLAN %s from vswitch %s'),
                 vlan_id, vswitch_name)
        self._set_vswitch_external_port_vlan_id(vswitch_name, VLAN_ID_REMOVE,
                                                vlan_id)

    def _get_switch_port_path_by_name(self, switch_port_name):
        vswitch = self._conn.Msvm_SwitchPort(ElementName=switch_port_name)
        if vswitch:
            return vswitch[0].path_()

    def get_vswitch_id(self, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        return vswitch.Name

    def get_port_by_id(self, port_id, vswitch_name):
        vswitch = self._get_vswitch(vswitch_name)
        switch_ports = vswitch.associators(wmi_result_class='Msvm_SwitchPort')
        for switch_port in switch_ports:
            if (switch_port.ElementName == port_id):
                return switch_port
