# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 VMware, Inc
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
# @author: Kaiwei Fan, VMware, Inc.
# @author: Bo Link, VMware, Inc.

from neutron.openstack.common import excutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from neutron.plugins.vmware.vshield.common.constants import RouterStatus
from neutron.plugins.vmware.vshield.common import exceptions
from neutron.plugins.vmware.vshield.tasks.constants import TaskState
from neutron.plugins.vmware.vshield.tasks.constants import TaskStatus
from neutron.plugins.vmware.vshield.tasks import tasks

LOG = logging.getLogger(__name__)


class EdgeApplianceDriver(object):
    def __init__(self):
        # store the last task per edge that has the latest config
        self.updated_task = {
            'nat': {},
            'route': {},
        }

    def _assemble_edge(self, name, appliance_size="compact",
                       deployment_container_id=None, datacenter_moid=None,
                       enable_aesni=True, hypervisor_assist=False,
                       enable_fips=False, remote_access=False):
        edge = {
            'name': name,
            'fqdn': name,
            'hypervisorAssist': hypervisor_assist,
            'type': 'gatewayServices',
            'enableAesni': enable_aesni,
            'enableFips': enable_fips,
            'cliSettings': {
                'remoteAccess': remote_access
            },
            'appliances': {
                'applianceSize': appliance_size
            },
            'vnics': {
                'vnics': []
            }
        }
        if deployment_container_id:
            edge['appliances']['deploymentContainerId'] = (
                deployment_container_id)
        if datacenter_moid:
            edge['datacenterMoid'] = datacenter_moid

        return edge

    def _assemble_edge_appliance(self, resource_pool_id, datastore_id):
        appliance = {}
        if resource_pool_id:
            appliance['resourcePoolId'] = resource_pool_id
        if datastore_id:
            appliance['datastoreId'] = datastore_id
        return appliance

    def _assemble_edge_vnic(self, name, index, portgroup_id,
                            primary_address=None, subnet_mask=None,
                            secondary=None,
                            type="internal",
                            enable_proxy_arp=False,
                            enable_send_redirects=True,
                            is_connected=True,
                            mtu=1500):
        vnic = {
            'index': index,
            'name': name,
            'type': type,
            'portgroupId': portgroup_id,
            'mtu': mtu,
            'enableProxyArp': enable_proxy_arp,
            'enableSendRedirects': enable_send_redirects,
            'isConnected': is_connected
        }
        if primary_address and subnet_mask:
            address_group = {
                'primaryAddress': primary_address,
                'subnetMask': subnet_mask
            }
            if secondary:
                address_group['secondaryAddresses'] = {
                    'ipAddress': secondary,
                    'type': 'IpAddressesDto'
                }

            vnic['addressGroups'] = {
                'addressGroups': [address_group]
            }

        return vnic

    def _edge_status_to_level(self, status):
        if status == 'GREEN':
            status_level = RouterStatus.ROUTER_STATUS_ACTIVE
        elif status in ('GREY', 'YELLOW'):
            status_level = RouterStatus.ROUTER_STATUS_DOWN
        else:
            status_level = RouterStatus.ROUTER_STATUS_ERROR
        return status_level

    def _enable_loadbalancer(self, edge):
        if not edge.get('featureConfigs') or (
            not edge['featureConfigs'].get('features')):
            edge['featureConfigs'] = {'features': []}
        edge['featureConfigs']['features'].append(
            {'featureType': 'loadbalancer_4.0',
             'enabled': True})

    def get_edge_status(self, edge_id):
        try:
            response = self.vcns.get_edge_status(edge_id)[1]
            status_level = self._edge_status_to_level(
                response['edgeStatus'])
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to get edge status:\n%s"),
                          e.response)
            status_level = RouterStatus.ROUTER_STATUS_ERROR
            try:
                desc = jsonutils.loads(e.response)
                if desc.get('errorCode') == (
                    vcns_const.VCNS_ERROR_CODE_EDGE_NOT_RUNNING):
                    status_level = RouterStatus.ROUTER_STATUS_DOWN
            except ValueError:
                LOG.exception(e.response)

        return status_level

    def get_edges_statuses(self):
        edges_status_level = {}
        edges = self._get_edges()
        for edge in edges['edgePage'].get('data', []):
            edge_id = edge['id']
            status = edge['edgeStatus']
            edges_status_level[edge_id] = self._edge_status_to_level(status)

        return edges_status_level

    def _update_interface(self, task):
        edge_id = task.userdata['edge_id']
        config = task.userdata['config']
        LOG.debug(_("VCNS: start updating vnic %s"), config)
        try:
            self.vcns.update_interface(edge_id, config)
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to update vnic %(config)s:\n"
                            "%(response)s"), {
                                'config': config,
                                'response': e.response})
            raise e
        except Exception as e:
            LOG.exception(_("VCNS: Failed to update vnic %d"),
                          config['index'])
            raise e

        return TaskStatus.COMPLETED

    def update_interface(self, router_id, edge_id, index, network,
                         address=None, netmask=None, secondary=None,
                         jobdata=None):
        LOG.debug(_("VCNS: update vnic %(index)d: %(addr)s %(netmask)s"), {
            'index': index, 'addr': address, 'netmask': netmask})
        if index == vcns_const.EXTERNAL_VNIC_INDEX:
            name = vcns_const.EXTERNAL_VNIC_NAME
            intf_type = 'uplink'
        elif index == vcns_const.INTERNAL_VNIC_INDEX:
            name = vcns_const.INTERNAL_VNIC_NAME
            intf_type = 'internal'
        else:
            msg = _("Vnic %d currently not supported") % index
            raise exceptions.VcnsGeneralException(msg)

        config = self._assemble_edge_vnic(
            name, index, network, address, netmask, secondary, type=intf_type)

        userdata = {
            'edge_id': edge_id,
            'config': config,
            'jobdata': jobdata
        }
        task_name = "update-interface-%s-%d" % (edge_id, index)
        task = tasks.Task(task_name, router_id,
                          self._update_interface, userdata=userdata)
        task.add_result_monitor(self.callbacks.interface_update_result)
        self.task_manager.add(task)
        return task

    def _deploy_edge(self, task):
        userdata = task.userdata
        name = userdata['router_name']
        LOG.debug(_("VCNS: start deploying edge %s"), name)
        request = userdata['request']
        try:
            header = self.vcns.deploy_edge(request)[0]
            objuri = header['location']
            job_id = objuri[objuri.rfind("/") + 1:]
            response = self.vcns.get_edge_id(job_id)[1]
            edge_id = response['edgeId']
            LOG.debug(_("VCNS: deploying edge %s"), edge_id)
            userdata['edge_id'] = edge_id
            status = TaskStatus.PENDING
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: deploy edge failed for router %s."),
                          name)
            raise e

        return status

    def _status_edge(self, task):
        edge_id = task.userdata['edge_id']
        try:
            response = self.vcns.get_edge_deploy_status(edge_id)[1]
            task.userdata['retries'] = 0
            system_status = response.get('systemStatus', None)
            if system_status is None:
                status = TaskStatus.PENDING
            elif system_status == 'good':
                status = TaskStatus.COMPLETED
            else:
                status = TaskStatus.ERROR
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Edge %s status query failed."), edge_id)
            raise e
        except Exception as e:
            retries = task.userdata.get('retries', 0) + 1
            if retries < 3:
                task.userdata['retries'] = retries
                msg = _("VCNS: Unable to retrieve edge %(edge_id)s status. "
                        "Retry %(retries)d.") % {
                            'edge_id': edge_id,
                            'retries': retries}
                LOG.exception(msg)
                status = TaskStatus.PENDING
            else:
                msg = _("VCNS: Unable to retrieve edge %s status. "
                        "Abort.") % edge_id
                LOG.exception(msg)
                status = TaskStatus.ERROR
        LOG.debug(_("VCNS: Edge %s status"), edge_id)
        return status

    def _result_edge(self, task):
        router_name = task.userdata['router_name']
        edge_id = task.userdata.get('edge_id')
        if task.status != TaskStatus.COMPLETED:
            LOG.error(_("VCNS: Failed to deploy edge %(edge_id)s "
                        "for %(name)s, status %(status)d"), {
                            'edge_id': edge_id,
                            'name': router_name,
                            'status': task.status
                        })
        else:
            LOG.debug(_("VCNS: Edge %(edge_id)s deployed for "
                        "router %(name)s"), {
                            'edge_id': edge_id, 'name': router_name
                        })

    def _delete_edge(self, task):
        edge_id = task.userdata['edge_id']
        LOG.debug(_("VCNS: start destroying edge %s"), edge_id)
        status = TaskStatus.COMPLETED
        if edge_id:
            try:
                self.vcns.delete_edge(edge_id)
            except exceptions.ResourceNotFound:
                pass
            except exceptions.VcnsApiException as e:
                msg = _("VCNS: Failed to delete %(edge_id)s:\n"
                        "%(response)s") % {
                            'edge_id': edge_id, 'response': e.response}
                LOG.exception(msg)
                status = TaskStatus.ERROR
            except Exception:
                LOG.exception(_("VCNS: Failed to delete %s"), edge_id)
                status = TaskStatus.ERROR

        return status

    def _get_edges(self):
        try:
            return self.vcns.get_edges()[1]
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to get edges:\n%s"), e.response)
            raise e

    def deploy_edge(self, router_id, name, internal_network, jobdata=None,
                    wait_for_exec=False, loadbalancer_enable=True):
        task_name = 'deploying-%s' % name
        edge_name = name
        edge = self._assemble_edge(
            edge_name, datacenter_moid=self.datacenter_moid,
            deployment_container_id=self.deployment_container_id,
            appliance_size='large', remote_access=True)
        appliance = self._assemble_edge_appliance(self.resource_pool_id,
                                                  self.datastore_id)
        if appliance:
            edge['appliances']['appliances'] = [appliance]

        vnic_external = self._assemble_edge_vnic(
            vcns_const.EXTERNAL_VNIC_NAME, vcns_const.EXTERNAL_VNIC_INDEX,
            self.external_network, type="uplink")
        edge['vnics']['vnics'].append(vnic_external)
        vnic_inside = self._assemble_edge_vnic(
            vcns_const.INTERNAL_VNIC_NAME, vcns_const.INTERNAL_VNIC_INDEX,
            internal_network,
            vcns_const.INTEGRATION_EDGE_IPADDRESS,
            vcns_const.INTEGRATION_SUBNET_NETMASK,
            type="internal")
        edge['vnics']['vnics'].append(vnic_inside)
        if loadbalancer_enable:
            self._enable_loadbalancer(edge)
        userdata = {
            'request': edge,
            'router_name': name,
            'jobdata': jobdata
        }
        task = tasks.Task(task_name, router_id,
                          self._deploy_edge,
                          status_callback=self._status_edge,
                          result_callback=self._result_edge,
                          userdata=userdata)
        task.add_executed_monitor(self.callbacks.edge_deploy_started)
        task.add_result_monitor(self.callbacks.edge_deploy_result)
        self.task_manager.add(task)

        if wait_for_exec:
            # waitl until the deploy task is executed so edge_id is available
            task.wait(TaskState.EXECUTED)

        return task

    def delete_edge(self, router_id, edge_id, jobdata=None):
        task_name = 'delete-%s' % edge_id
        userdata = {
            'router_id': router_id,
            'edge_id': edge_id,
            'jobdata': jobdata
        }
        task = tasks.Task(task_name, router_id, self._delete_edge,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.edge_delete_result)
        self.task_manager.add(task)
        return task

    def _assemble_nat_rule(self, action, original_address,
                           translated_address,
                           vnic_index=vcns_const.EXTERNAL_VNIC_INDEX,
                           enabled=True):
        nat_rule = {}
        nat_rule['action'] = action
        nat_rule['vnic'] = vnic_index
        nat_rule['originalAddress'] = original_address
        nat_rule['translatedAddress'] = translated_address
        nat_rule['enabled'] = enabled
        return nat_rule

    def get_nat_config(self, edge_id):
        try:
            return self.vcns.get_nat_config(edge_id)[1]
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to get nat config:\n%s"),
                          e.response)
            raise e

    def _create_nat_rule(self, task):
        # TODO(fank): use POST for optimization
        #             return rule_id for future reference
        rule = task.userdata['rule']
        LOG.debug(_("VCNS: start creating nat rules: %s"), rule)
        edge_id = task.userdata['edge_id']
        nat = self.get_nat_config(edge_id)
        location = task.userdata['location']

        del nat['version']

        if location is None or location == vcns_const.APPEND:
            nat['rules']['natRulesDtos'].append(rule)
        else:
            nat['rules']['natRulesDtos'].insert(location, rule)

        try:
            self.vcns.update_nat_config(edge_id, nat)
            status = TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to create snat rule:\n%s"),
                          e.response)
            status = TaskStatus.ERROR

        return status

    def create_snat_rule(self, router_id, edge_id, src, translated,
                         jobdata=None, location=None):
        LOG.debug(_("VCNS: create snat rule %(src)s/%(translated)s"), {
            'src': src, 'translated': translated})
        snat_rule = self._assemble_nat_rule("snat", src, translated)
        userdata = {
            'router_id': router_id,
            'edge_id': edge_id,
            'rule': snat_rule,
            'location': location,
            'jobdata': jobdata
        }
        task_name = "create-snat-%s-%s-%s" % (edge_id, src, translated)
        task = tasks.Task(task_name, router_id, self._create_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.snat_create_result)
        self.task_manager.add(task)
        return task

    def _delete_nat_rule(self, task):
        # TODO(fank): pass in rule_id for optimization
        #             handle routes update for optimization
        edge_id = task.userdata['edge_id']
        address = task.userdata['address']
        addrtype = task.userdata['addrtype']
        LOG.debug(_("VCNS: start deleting %(type)s rules: %(addr)s"), {
            'type': addrtype, 'addr': address})
        nat = self.get_nat_config(edge_id)
        del nat['version']
        status = TaskStatus.COMPLETED
        for nat_rule in nat['rules']['natRulesDtos']:
            if nat_rule[addrtype] == address:
                rule_id = nat_rule['ruleId']
                try:
                    self.vcns.delete_nat_rule(edge_id, rule_id)
                except exceptions.VcnsApiException as e:
                    LOG.exception(_("VCNS: Failed to delete snat rule:\n"
                                    "%s"), e.response)
                    status = TaskStatus.ERROR

        return status

    def delete_snat_rule(self, router_id, edge_id, src, jobdata=None):
        LOG.debug(_("VCNS: delete snat rule %s"), src)
        userdata = {
            'edge_id': edge_id,
            'address': src,
            'addrtype': 'originalAddress',
            'jobdata': jobdata
        }
        task_name = "delete-snat-%s-%s" % (edge_id, src)
        task = tasks.Task(task_name, router_id, self._delete_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.snat_delete_result)
        self.task_manager.add(task)
        return task

    def create_dnat_rule(self, router_id, edge_id, dst, translated,
                         jobdata=None, location=None):
        # TODO(fank): use POST for optimization
        #             return rule_id for future reference
        LOG.debug(_("VCNS: create dnat rule %(dst)s/%(translated)s"), {
            'dst': dst, 'translated': translated})
        dnat_rule = self._assemble_nat_rule(
            "dnat", dst, translated)
        userdata = {
            'router_id': router_id,
            'edge_id': edge_id,
            'rule': dnat_rule,
            'location': location,
            'jobdata': jobdata
        }
        task_name = "create-dnat-%s-%s-%s" % (edge_id, dst, translated)
        task = tasks.Task(task_name, router_id, self._create_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.dnat_create_result)
        self.task_manager.add(task)
        return task

    def delete_dnat_rule(self, router_id, edge_id, translated,
                         jobdata=None):
        # TODO(fank): pass in rule_id for optimization
        LOG.debug(_("VCNS: delete dnat rule %s"), translated)
        userdata = {
            'edge_id': edge_id,
            'address': translated,
            'addrtype': 'translatedAddress',
            'jobdata': jobdata
        }
        task_name = "delete-dnat-%s-%s" % (edge_id, translated)
        task = tasks.Task(task_name, router_id, self._delete_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.dnat_delete_result)
        self.task_manager.add(task)
        return task

    def _update_nat_rule(self, task):
        # TODO(fank): use POST for optimization
        #             return rule_id for future reference
        edge_id = task.userdata['edge_id']
        if task != self.updated_task['nat'][edge_id]:
            # this task does not have the latest config, abort now
            # for speedup
            return TaskStatus.ABORT

        rules = task.userdata['rules']
        LOG.debug(_("VCNS: start updating nat rules: %s"), rules)

        nat = {
            'featureType': 'nat',
            'rules': {
                'natRulesDtos': rules
            }
        }

        try:
            self.vcns.update_nat_config(edge_id, nat)
            status = TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to create snat rule:\n%s"),
                          e.response)
            status = TaskStatus.ERROR

        return status

    def update_nat_rules(self, router_id, edge_id, snats, dnats,
                         jobdata=None):
        LOG.debug(_("VCNS: update nat rule\n"
                    "SNAT:%(snat)s\n"
                    "DNAT:%(dnat)s\n"), {
                        'snat': snats, 'dnat': dnats})
        nat_rules = []

        for dnat in dnats:
            nat_rules.append(self._assemble_nat_rule(
                'dnat', dnat['dst'], dnat['translated']))
            nat_rules.append(self._assemble_nat_rule(
                'snat', dnat['translated'], dnat['dst']))

        for snat in snats:
            nat_rules.append(self._assemble_nat_rule(
                'snat', snat['src'], snat['translated']))

        userdata = {
            'edge_id': edge_id,
            'rules': nat_rules,
            'jobdata': jobdata,
        }
        task_name = "update-nat-%s" % edge_id
        task = tasks.Task(task_name, router_id, self._update_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.nat_update_result)
        self.updated_task['nat'][edge_id] = task
        self.task_manager.add(task)
        return task

    def _update_routes(self, task):
        edge_id = task.userdata['edge_id']
        if (task != self.updated_task['route'][edge_id] and
            task.userdata.get('skippable', True)):
            # this task does not have the latest config, abort now
            # for speedup
            return TaskStatus.ABORT
        gateway = task.userdata['gateway']
        routes = task.userdata['routes']
        LOG.debug(_("VCNS: start updating routes for %s"), edge_id)
        static_routes = []
        for route in routes:
            static_routes.append({
                "description": "",
                "vnic": vcns_const.INTERNAL_VNIC_INDEX,
                "network": route['cidr'],
                "nextHop": route['nexthop']
            })
        request = {
            "staticRoutes": {
                "staticRoutes": static_routes
            }
        }
        if gateway:
            request["defaultRoute"] = {
                "description": "default-gateway",
                "gatewayAddress": gateway,
                "vnic": vcns_const.EXTERNAL_VNIC_INDEX
            }
        try:
            self.vcns.update_routes(edge_id, request)
            status = TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.exception(_("VCNS: Failed to update routes:\n%s"),
                          e.response)
            status = TaskStatus.ERROR

        return status

    def update_routes(self, router_id, edge_id, gateway, routes,
                      skippable=True, jobdata=None):
        if gateway:
            gateway = gateway.split('/')[0]

        userdata = {
            'edge_id': edge_id,
            'gateway': gateway,
            'routes': routes,
            'skippable': skippable,
            'jobdata': jobdata
        }
        task_name = "update-routes-%s" % (edge_id)
        task = tasks.Task(task_name, router_id, self._update_routes,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.routes_update_result)
        self.updated_task['route'][edge_id] = task
        self.task_manager.add(task)
        return task

    def create_lswitch(self, name, tz_config, tags=None,
                       port_isolation=False, replication_mode="service"):
        lsconfig = {
            'display_name': utils.check_and_truncate(name),
            "tags": tags or [],
            "type": "LogicalSwitchConfig",
            "_schema": "/ws.v1/schema/LogicalSwitchConfig",
            "transport_zones": tz_config
        }
        if port_isolation is bool:
            lsconfig["port_isolation_enabled"] = port_isolation
        if replication_mode:
            lsconfig["replication_mode"] = replication_mode

        response = self.vcns.create_lswitch(lsconfig)[1]
        return response

    def delete_lswitch(self, lswitch_id):
        self.vcns.delete_lswitch(lswitch_id)

    def get_loadbalancer_config(self, edge_id):
        try:
            header, response = self.vcns.get_loadbalancer_config(
                edge_id)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to get service config"))
        return response

    def enable_service_loadbalancer(self, edge_id):
        config = self.get_loadbalancer_config(
            edge_id)
        if not config['enabled']:
            config['enabled'] = True
        try:
            self.vcns.enable_service_loadbalancer(edge_id, config)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to enable loadbalancer "
                                "service config"))
