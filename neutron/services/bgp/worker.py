# Copyright 2025 Red Hat, Inc.
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

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services.bgp import ovn
from neutron.services.bgp import reconciler
from neutron import worker


class BGPWorker(worker.NeutronBaseWorker):
    def __init__(self):
        super().__init__(worker_process_count=0)

    def start(self):
        super().start(desc="bgp worker")

        self.nb_api = ovn.OvnNbIdl(ovn_conf.get_ovn_nb_connection()).start(
            timeout=ovn_conf.get_ovn_ovsdb_timeout())
        self.nb_api.set_lock()

        self.sb_api = ovn.OvnSbIdl(ovn_conf.get_ovn_sb_connection()).start(
            timeout=ovn_conf.get_ovn_ovsdb_timeout())
        self._reconciler = reconciler.BGPTopologyReconciler(
            self.nb_api,
            self.sb_api)

    def wait(self):
        self._reconciler.full_sync()

    def stop(self):
        pass

    def reset(self):
        self.nb_api.restart_connection()
        self.sb_api.restart_connection()
