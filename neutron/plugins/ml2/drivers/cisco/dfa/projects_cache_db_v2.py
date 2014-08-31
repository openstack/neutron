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


from sqlalchemy.orm import exc

import neutron.db.api as db
from neutron.plugins.ml2 import db as ml2db
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_exceptions as dexc
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_models_v2


class ProjectsInfoCache(object):
    """Project DB API."""

    def _get_project_entry(self, db_session, pid):
        """Get a project entry from the table.

        :param db_session: database session object
        :param pid: project ID
        """
        try:
            return db_session.query(
                dfa_models_v2.ProjectNameCache).filter_by(project_id=pid).one()
        except exc.NoResultFound:
            raise dexc.ProjectIdNotFound(project_id=pid)

    def create_projects_cache_db(self, proj_info):
        """Create an entry in the database.

        :param proj_info: dictionary that contains information of the project
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            projid = proj_info["project_id"]
            projname = proj_info["project_name"]
            thisproj = dfa_models_v2.ProjectNameCache(project_id=projid,
                                                      project_name=projname)
            db_session.add(thisproj)
            return thisproj

    def delete_projects_cache_db(self, proj_id):
        """Delete a project from the table.

        :param proj_id: UUID of the project
        """
        db_session = db.get_session()
        thisproj = None
        with db_session.begin(subtransactions=True):
            thisproj = self._get_project_entry(db_session, proj_id)
            db_session.delete(thisproj)
        return thisproj

    def get_project_name(self, proj_id):
        """Returns project's name.

        :param proj_id: UUID of the project
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            thisproj = self._get_project_entry(db_session, proj_id)
            return thisproj.project_name

    def update_projects_cache_db(self, pid, proj_info):
        """Update projects DB.

        :param pid: project ID
        :param proj_info: dictionary that contains information of the project
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            thisproj = self._get_project_entry(db_session, pid)
            thisproj.update(proj_info)

    def get_network_segid(self, sid):
        """Get network segmentation id.

        :param sid: requested segment id
        """
        db_session = db.get_session()
        seg_entry = ml2db.get_network_segments(db_session, sid)
        return seg_entry[0]['segmentation_id']
