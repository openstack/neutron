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

from oslo_log import log as logging

from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespaces
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.i18n import _LE

LOG = logging.getLogger(__name__)


class NamespaceManager(object):

    """Keeps track of namespaces that need to be cleaned up.

    This is a context manager that looks to clean up stale namespaces that
    have not been touched by the end of the "with" statement it is called
    in.  This formalizes the pattern used in the L3 agent which enumerated
    all of the namespaces known to the system before a full sync.  Then,
    after the full sync completed, it cleaned up any that were not touched
    during the sync. The agent and this context manager use method keep_router
    to communicate. In the "with" statement, the agent calls keep_router to
    record the id's of the routers whose namespaces should be preserved.
    Any other router and snat namespace present in the system will be deleted
    by the __exit__ method of this context manager

    This pattern can be more generally applicable to other resources
    besides namespaces in the future because it is idempotent and, as such,
    does not rely on state recorded at runtime in the agent so it handles
    agent restarts gracefully.
    """

    def __init__(self, agent_conf, driver, clean_stale, metadata_driver=None):
        """Initialize the NamespaceManager.

        :param agent_conf: configuration from l3 agent
        :param driver: to perform operations on devices
        :param clean_stale: Whether to try to clean stale namespaces
        :param metadata_driver: used to cleanup stale metadata proxy processes
        """
        self.agent_conf = agent_conf
        self.driver = driver
        self._clean_stale = clean_stale
        self.metadata_driver = metadata_driver
        if metadata_driver:
            self.process_monitor = external_process.ProcessMonitor(
                config=agent_conf,
                resource_type='router')

    def __enter__(self):
        self._all_namespaces = set()
        self._ids_to_keep = set()
        if self._clean_stale:
            self._all_namespaces = self.list_all()
        return self

    def __exit__(self, exc_type, value, traceback):
        # TODO(carl) Preserves old behavior of L3 agent where cleaning
        # namespaces was only done once after restart.  Still a good idea?
        if exc_type:
            # An exception occurred in the caller's with statement
            return False
        if not self._clean_stale:
            # No need to cleanup
            return True
        self._clean_stale = False

        for ns in self._all_namespaces:
            _ns_prefix, ns_id = self.get_prefix_and_id(ns)
            if ns_id in self._ids_to_keep:
                continue
            if _ns_prefix == namespaces.NS_PREFIX:
                ns = namespaces.RouterNamespace(ns_id,
                                                self.agent_conf,
                                                self.driver,
                                                use_ipv6=False)
            else:
                ns = dvr_snat_ns.SnatNamespace(ns_id,
                                               self.agent_conf,
                                               self.driver,
                                               use_ipv6=False)
            try:
                if self.metadata_driver:
                    # cleanup stale metadata proxy processes first
                    self.metadata_driver.destroy_monitored_metadata_proxy(
                        self.process_monitor, ns_id, ns.name, self.agent_conf)
                ns.delete()
            except RuntimeError:
                LOG.exception(_LE('Failed to destroy stale namespace %s'), ns)

        return True

    def keep_router(self, router_id):
        self._ids_to_keep.add(router_id)

    def get_prefix_and_id(self, ns_name):
        """Get the prefix and id from the namespace name.

        :param ns_name: The name of the namespace
        :returns: tuple with prefix and id or None if no prefix matches
        """
        for prefix in [namespaces.NS_PREFIX, dvr_snat_ns.SNAT_NS_PREFIX]:
            if ns_name.startswith(prefix):
                return (prefix, ns_name[len(prefix):])

    def is_managed(self, ns_name):
        """Return True if the namespace name passed belongs to this manager."""
        return self.get_prefix_and_id(ns_name) is not None

    def list_all(self):
        """Get a set of all namespaces on host managed by this manager."""
        try:
            root_ip = ip_lib.IPWrapper()

            namespaces = root_ip.get_namespaces()
            return set(ns for ns in namespaces if self.is_managed(ns))
        except RuntimeError:
            LOG.exception(_LE('RuntimeError in obtaining namespace list for '
                              'namespace cleanup.'))
            return set()
