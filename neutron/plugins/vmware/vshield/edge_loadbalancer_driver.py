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

from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.dbexts import vcns_db
from neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from neutron.plugins.vmware.vshield.common import (
    exceptions as vcns_exc)
from neutron.services.loadbalancer import constants as lb_constants

LOG = logging.getLogger(__name__)

BALANCE_MAP = {
    lb_constants.LB_METHOD_ROUND_ROBIN: 'round-robin',
    lb_constants.LB_METHOD_LEAST_CONNECTIONS: 'leastconn',
    lb_constants.LB_METHOD_SOURCE_IP: 'source'
}
PROTOCOL_MAP = {
    lb_constants.PROTOCOL_TCP: 'tcp',
    lb_constants.PROTOCOL_HTTP: 'http',
    lb_constants.PROTOCOL_HTTPS: 'tcp'
}
SESSION_PERSISTENCE_METHOD_MAP = {
    lb_constants.SESSION_PERSISTENCE_SOURCE_IP: 'sourceip',
    lb_constants.SESSION_PERSISTENCE_APP_COOKIE: 'cookie',
    lb_constants.SESSION_PERSISTENCE_HTTP_COOKIE: 'cookie'}
SESSION_PERSISTENCE_COOKIE_MAP = {
    lb_constants.SESSION_PERSISTENCE_APP_COOKIE: 'app',
    lb_constants.SESSION_PERSISTENCE_HTTP_COOKIE: 'insert'}


class EdgeLbDriver():
    """Implementation of driver APIs for
       Edge Loadbalancer feature configuration
    """

    def _convert_lb_vip(self, context, edge_id, vip, app_profileid):
        pool_id = vip.get('pool_id')
        poolid_map = vcns_db.get_vcns_edge_pool_binding(
            context.session, pool_id, edge_id)
        pool_vseid = poolid_map['pool_vseid']
        return {
            'name': vip.get(
                'name', '') + vip['id'][-vcns_const.SUFFIX_LENGTH:],
            'description': vip.get('description'),
            'ipAddress': vip.get('address'),
            'protocol': vip.get('protocol'),
            'port': vip.get('protocol_port'),
            'connectionLimit': max(0, vip.get('connection_limit')),
            'defaultPoolId': pool_vseid,
            'applicationProfileId': app_profileid
        }

    def _restore_lb_vip(self, context, edge_id, vip_vse):
        pool_binding = vcns_db.get_vcns_edge_pool_binding_by_vseid(
            context.session,
            edge_id,
            vip_vse['defaultPoolId'])

        return {
            'name': vip_vse['name'][:-vcns_const.SUFFIX_LENGTH],
            'address': vip_vse['ipAddress'],
            'protocol': vip_vse['protocol'],
            'protocol_port': vip_vse['port'],
            'pool_id': pool_binding['pool_id']
        }

    def _convert_lb_pool(self, context, edge_id, pool, members):
        vsepool = {
            'name': pool.get(
                'name', '') + pool['id'][-vcns_const.SUFFIX_LENGTH:],
            'description': pool.get('description'),
            'algorithm': BALANCE_MAP.get(
                pool.get('lb_method'),
                'round-robin'),
            'transparent': True,
            'member': [],
            'monitorId': []
        }
        for member in members:
            vsepool['member'].append({
                'ipAddress': member['address'],
                'weight': member['weight'],
                'port': member['protocol_port']
            })
        ##TODO(linb) right now, vse only accept at most one monitor per pool
        monitors = pool.get('health_monitors')
        if not monitors:
            return vsepool
        monitorid_map = vcns_db.get_vcns_edge_monitor_binding(
            context.session,
            monitors[0],
            edge_id)
        vsepool['monitorId'].append(monitorid_map['monitor_vseid'])
        return vsepool

    def _restore_lb_pool(self, context, edge_id, pool_vse):
        #TODO(linb): Get more usefule info
        return {
            'name': pool_vse['name'][:-vcns_const.SUFFIX_LENGTH],
        }

    def _convert_lb_monitor(self, context, monitor):
        return {
            'type': PROTOCOL_MAP.get(
                monitor.get('type'), 'http'),
            'interval': monitor.get('delay'),
            'timeout': monitor.get('timeout'),
            'maxRetries': monitor.get('max_retries'),
            'name': monitor.get('id')
        }

    def _restore_lb_monitor(self, context, edge_id, monitor_vse):
        return {
            'delay': monitor_vse['interval'],
            'timeout': monitor_vse['timeout'],
            'max_retries': monitor_vse['maxRetries'],
            'id': monitor_vse['name']
        }

    def _convert_app_profile(self, name, sess_persist, protocol):
        vcns_app_profile = {
            'insertXForwardedFor': False,
            'name': name,
            'serverSslEnabled': False,
            'sslPassthrough': False,
            'template': protocol,
        }
        # Since SSL Termination is not supported right now, so just use
        # sslPassthrough mehtod if the protocol is HTTPS.
        if protocol == lb_constants.PROTOCOL_HTTPS:
            vcns_app_profile['sslPassthrough'] = True

        if sess_persist.get('type'):
            # If protocol is not HTTP, only sourceip is supported
            if (protocol != lb_constants.PROTOCOL_HTTP and
                sess_persist['type'] != (
                    lb_constants.SESSION_PERSISTENCE_SOURCE_IP)):
                msg = (_("Invalid %(protocol)s persistence method: %(type)s") %
                       {'protocol': protocol,
                        'type': sess_persist['type']})
                raise vcns_exc.VcnsBadRequest(resource='sess_persist', msg=msg)
            persistence = {
                'method': SESSION_PERSISTENCE_METHOD_MAP.get(
                    sess_persist['type'])}
            if sess_persist['type'] in SESSION_PERSISTENCE_COOKIE_MAP:
                if sess_persist.get('cookie_name'):
                    persistence['cookieName'] = sess_persist['cookie_name']
                else:
                    persistence['cookieName'] = 'default_cookie_name'
                persistence['cookieMode'] = SESSION_PERSISTENCE_COOKIE_MAP.get(
                    sess_persist['type'])
            vcns_app_profile['persistence'] = persistence
        return vcns_app_profile

    def create_vip(self, context, edge_id, vip):
        app_profile = self._convert_app_profile(
            vip['name'], (vip.get('session_persistence') or {}),
            vip.get('protocol'))
        try:
            header, response = self.vcns.create_app_profile(
                edge_id, app_profile)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to create app profile on edge: %s"),
                              edge_id)
        objuri = header['location']
        app_profileid = objuri[objuri.rfind("/") + 1:]

        vip_new = self._convert_lb_vip(context, edge_id, vip, app_profileid)
        try:
            header, response = self.vcns.create_vip(
                edge_id, vip_new)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to create vip on vshield edge: %s"),
                              edge_id)
                self.vcns.delete_app_profile(edge_id, app_profileid)
        objuri = header['location']
        vip_vseid = objuri[objuri.rfind("/") + 1:]

        # Add the vip mapping
        map_info = {
            "vip_id": vip['id'],
            "vip_vseid": vip_vseid,
            "edge_id": edge_id,
            "app_profileid": app_profileid
        }
        vcns_db.add_vcns_edge_vip_binding(context.session, map_info)

    def _get_vip_binding(self, session, id):
        vip_binding = vcns_db.get_vcns_edge_vip_binding(session, id)
        if not vip_binding:
            msg = (_("vip_binding not found with id: %(id)s "
                     "edge_id: %(edge_id)s") % {
                   'id': id,
                   'edge_id': vip_binding[vcns_const.EDGE_ID]})
            LOG.error(msg)
            raise vcns_exc.VcnsNotFound(
                resource='router_service_binding', msg=msg)
        return vip_binding

    def get_vip(self, context, id):
        vip_binding = vcns_db.get_vcns_edge_vip_binding(context.session, id)
        edge_id = vip_binding[vcns_const.EDGE_ID]
        vip_vseid = vip_binding['vip_vseid']
        try:
            response = self.vcns.get_vip(edge_id, vip_vseid)[1]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to get vip on edge"))
        return self._restore_lb_vip(context, edge_id, response)

    def update_vip(self, context, vip, session_persistence_update=True):
        vip_binding = self._get_vip_binding(context.session, vip['id'])
        edge_id = vip_binding[vcns_const.EDGE_ID]
        vip_vseid = vip_binding.get('vip_vseid')
        if session_persistence_update:
            app_profileid = vip_binding.get('app_profileid')
            app_profile = self._convert_app_profile(
                vip['name'], vip.get('session_persistence', {}),
                vip.get('protocol'))
            try:
                self.vcns.update_app_profile(
                    edge_id, app_profileid, app_profile)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Failed to update app profile on "
                                    "edge: %s") % edge_id)

        vip_new = self._convert_lb_vip(context, edge_id, vip, app_profileid)
        try:
            self.vcns.update_vip(edge_id, vip_vseid, vip_new)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update vip on edge: %s") % edge_id)

    def delete_vip(self, context, id):
        vip_binding = self._get_vip_binding(context.session, id)
        edge_id = vip_binding[vcns_const.EDGE_ID]
        vip_vseid = vip_binding['vip_vseid']
        app_profileid = vip_binding['app_profileid']

        try:
            self.vcns.delete_vip(edge_id, vip_vseid)
        except vcns_exc.ResourceNotFound:
            LOG.exception(_("vip not found on edge: %s") % edge_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete vip on edge: %s") % edge_id)

        try:
            self.vcns.delete_app_profile(edge_id, app_profileid)
        except vcns_exc.ResourceNotFound:
            LOG.exception(_("app profile not found on edge: %s") % edge_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete app profile on edge: %s") %
                              edge_id)

        vcns_db.delete_vcns_edge_vip_binding(context.session, id)

    def create_pool(self, context, edge_id, pool, members):
        pool_new = self._convert_lb_pool(context, edge_id, pool, members)
        try:
            header = self.vcns.create_pool(edge_id, pool_new)[0]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to create pool"))

        objuri = header['location']
        pool_vseid = objuri[objuri.rfind("/") + 1:]

        # update the pool mapping table
        map_info = {
            "pool_id": pool['id'],
            "pool_vseid": pool_vseid,
            "edge_id": edge_id
        }
        vcns_db.add_vcns_edge_pool_binding(context.session, map_info)

    def get_pool(self, context, id, edge_id):
        pool_binding = vcns_db.get_vcns_edge_pool_binding(
            context.session, id, edge_id)
        if not pool_binding:
            msg = (_("pool_binding not found with id: %(id)s "
                     "edge_id: %(edge_id)s") % {'id': id, 'edge_id': edge_id})
            LOG.error(msg)
            raise vcns_exc.VcnsNotFound(
                resource='router_service_binding', msg=msg)
        pool_vseid = pool_binding['pool_vseid']
        try:
            response = self.vcns.get_pool(edge_id, pool_vseid)[1]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to get pool on edge"))
        return self._restore_lb_pool(context, edge_id, response)

    def update_pool(self, context, edge_id, pool, members):
        pool_binding = vcns_db.get_vcns_edge_pool_binding(
            context.session, pool['id'], edge_id)
        pool_vseid = pool_binding['pool_vseid']
        pool_new = self._convert_lb_pool(context, edge_id, pool, members)
        try:
            self.vcns.update_pool(edge_id, pool_vseid, pool_new)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update pool"))

    def delete_pool(self, context, id, edge_id):
        pool_binding = vcns_db.get_vcns_edge_pool_binding(
            context.session, id, edge_id)
        pool_vseid = pool_binding['pool_vseid']
        try:
            self.vcns.delete_pool(edge_id, pool_vseid)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete pool"))
        vcns_db.delete_vcns_edge_pool_binding(
            context.session, id, edge_id)

    def create_health_monitor(self, context, edge_id, health_monitor):
        monitor_new = self._convert_lb_monitor(context, health_monitor)
        try:
            header = self.vcns.create_health_monitor(edge_id, monitor_new)[0]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to create monitor on edge: %s"),
                              edge_id)

        objuri = header['location']
        monitor_vseid = objuri[objuri.rfind("/") + 1:]

        # update the health_monitor mapping table
        map_info = {
            "monitor_id": health_monitor['id'],
            "monitor_vseid": monitor_vseid,
            "edge_id": edge_id
        }
        vcns_db.add_vcns_edge_monitor_binding(context.session, map_info)

    def get_health_monitor(self, context, id, edge_id):
        monitor_binding = vcns_db.get_vcns_edge_monitor_binding(
            context.session, id, edge_id)
        if not monitor_binding:
            msg = (_("monitor_binding not found with id: %(id)s "
                     "edge_id: %(edge_id)s") % {'id': id, 'edge_id': edge_id})
            LOG.error(msg)
            raise vcns_exc.VcnsNotFound(
                resource='router_service_binding', msg=msg)
        monitor_vseid = monitor_binding['monitor_vseid']
        try:
            response = self.vcns.get_health_monitor(edge_id, monitor_vseid)[1]
        except vcns_exc.VcnsApiException as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to get monitor on edge: %s"),
                              e.response)
        return self._restore_lb_monitor(context, edge_id, response)

    def update_health_monitor(self, context, edge_id,
                              old_health_monitor, health_monitor):
        monitor_binding = vcns_db.get_vcns_edge_monitor_binding(
            context.session,
            old_health_monitor['id'], edge_id)
        monitor_vseid = monitor_binding['monitor_vseid']
        monitor_new = self._convert_lb_monitor(
            context, health_monitor)
        try:
            self.vcns.update_health_monitor(
                edge_id, monitor_vseid, monitor_new)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update monitor on edge: %s"),
                              edge_id)

    def delete_health_monitor(self, context, id, edge_id):
        monitor_binding = vcns_db.get_vcns_edge_monitor_binding(
            context.session, id, edge_id)
        monitor_vseid = monitor_binding['monitor_vseid']
        try:
            self.vcns.delete_health_monitor(edge_id, monitor_vseid)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete monitor"))
        vcns_db.delete_vcns_edge_monitor_binding(
            context.session, id, edge_id)
