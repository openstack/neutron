# Copyright 2014 Cisco Systems, Inc.
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
#


from keystoneclient.v3 import client
from oslo.config import cfg
from oslo import messaging

from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_exceptions as dexc
from neutron.plugins.ml2.drivers.cisco.dfa import projects_cache_db_v2


LOG = logging.getLogger(__name__)


notif_params = {
    'keystone': {
        'admin_token': 'ADMIN',
        'admin_endpoint': 'http://localhost:%(admin_port)s/',
        'admin_port': '35357',
        'default_notification_level': 'INFO',
        'notification_topics': 'notifications',
        'control_exchange': 'openstack',
    }
}

proj_exceptions_list = [
    'admin', 'service', 'invisible_to_admin', 'demo', 'alt_demo']


class NotificationEndpoint(object):
    def __init__(self, evnt_hndlr):
        self._event_hndlr = evnt_hndlr

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        self._event_hndlr.callback(event_type, payload)


class EventsHandler(projects_cache_db_v2.ProjectsInfoCache):
    """This class defines methods to listen and process the project events."""

    def __init__(self, ser_name, dcnm_client):
        self._keystone = None
        self._service = ser_name
        self._notif_params = {}
        self._set_notif_params()
        self._dcnm_client = dcnm_client
        self.events_handler = {
            'identity.project.created': self.project_create_event,
            'identity.project.deleted': self.project_delete_event,
            'identity.user.created': self.no_op_event,
            'identity.user.deleted': self.no_op_event,
        }

    def no_op_event(self, keyc, project_id, dcnmc):
        pass

    def project_create_event(self, keyc, project_id, dcnmc):
        """Create a project on the DCNM.

        :param keyc: keystoneclient object
        :param project_id: UUID of the project
        :param dcnmc: DCNM client object
        """
        proj = keyc.projects.get(project_id)
        proj_name = proj.name
        desc = proj.description
        LOG.debug("project_create_event: %(proj)s %(proj_name)s %(desc)s." %
                  {'proj': proj, 'proj_name': proj_name, 'desc': desc})
        if proj_name not in proj_exceptions_list:
            try:
                dcnmc.create_project(proj_name, desc)
            except dexc.DFAClientConnectionFailed as ex:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_('Failed to create %(proj)s. '
                                  'Error:%(err)s.'),
                                  {'proj': proj_name, 'err': ex})
            proj_info = {'project_id': project_id,
                         'project_name': proj_name}
            self.create_projects_cache_db(proj_info)

    def project_delete_event(self, keyc, project_id, dcnmc):
        """Delete a project on the DCNM.

        :param keyc: keystoneclient object
        :param project_id: UUID of the project
        :param dcnmc: DCNM client object
        """
        try:
            proj_info = self.delete_projects_cache_db(project_id)
            LOG.debug("project_delete_event: proj_info: %s." % proj_info)
            dcnmc.delete_tenant(proj_info.project_name)
        except dexc.ProjectIdNotFound:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete %(id)s"), {'id': project_id})
        except dexc.DFAClientConnectionFailed:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete %(proj)s in DCNM."),
                              {'proj': proj_info.project_name})

    def _set_notif_params(self):
        """Read notification parameters from the config file."""
        self._notif_params.update(notif_params[self._service])
        temp_db = {}
        cfgfile = cfg.find_config_files(self._service)
        multi_parser = cfg.MultiConfigParser()
        cfgr = multi_parser.read(cfgfile)
        if len(cfgr) == 0:
            LOG.error(_("Failed to read %s."), cfgfile)
            return
        for parsed_file in multi_parser.parsed:
            for parsed_item in parsed_file.keys():
                for key, value in parsed_file[parsed_item].items():
                    if key in self._notif_params:
                        val = notif_params[self._service].get(key)
                        if val != value[0]:
                            temp_db[key] = value[0]

        self._notif_params.update(temp_db)
        self._token = self.get_notif_params().get('admin_token')
        _endpoint = self.get_notif_params().get('admin_endpoint')
        self._endpoint_url = _endpoint % self.get_notif_params() + 'v3/'
        self._keystone = client.Client(token=self._token,
                                       endpoint=self._endpoint_url)

    def callback(self, event_type, payload):
        """Callback method for processing events in notification queue.

        :param event_type: event type in the notification queue such as
                           identity.project.created, identity.project.deleted.
        :param payload: Contains information of an event
        """
        try:
            event = event_type
            if event in self.events_handler:
                project_id = payload['resource_info']
                self.events_handler[event](self._keystone, project_id,
                                           self._dcnm_client)
        except KeyError:
            LOG.error(_('event_type %s does not have payload/resource_info '
                      'key'), event)

    def event_handler(self):
        """Prepare connection and channels for listenning to the events."""
        topicname = self.get_notif_params().get('notification_topics')
        transport = messaging.get_transport(cfg.CONF)
        targets = [messaging.Target(topic=topicname)]
        endpoints = [NotificationEndpoint(self)]
        server = messaging.get_notification_listener(transport, targets,
                                                     endpoints)
        server.start()
        server.wait()

    def get_notif_params(self):
        """Return notification parameters."""
        return self._notif_params

    def is_valid_project(self, project_id):
        """Check the validity of project.

        :param project_id: UUID of project
        :returns: True if project is valid.
        """
        proj = self._keystone.projects.get(project_id)
        proj_name = proj.name
        if proj_name in proj_exceptions_list:
            LOG.debug("Project %s is not created by user." % proj_name)
            return False
        return True
