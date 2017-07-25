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
import re

from neutron_lib.utils import runtime
from oslo_concurrency import lockutils
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.agent.linux import ip_lib
from neutron.plugins.ml2.drivers.linuxbridge.agent.common import utils as lutil

LOG = logging.getLogger(__name__)


class Plumber(object):
    """Object responsible for VLAN interface CRUD.

    This handles the creation/deletion/listing of VLAN interfaces for
    a trunk within a namespace.
    """

    def __init__(self, namespace=None):
        self.namespace = namespace

    def trunk_on_host(self, trunk):
        """Returns true if trunk device is present else False."""
        trunk_dev = self._trunk_device_name(trunk)
        return ip_lib.device_exists(trunk_dev, namespace=self.namespace)

    def ensure_trunk_subports(self, trunk):
        """Idempotent wiring for a trunk's subports.

        Given a trunk object, delete any vlan subinterfaces belonging to a
        trunk that aren't on the object. Create any which are on the object
        which do not exist.
        """
        trunk_dev = self._trunk_device_name(trunk)
        with self._trunk_lock(trunk_dev):
            # lock scoped to trunk device so two diffs don't interleave
            expected = self._get_subport_devs_and_vlans(trunk.sub_ports)
            existing = self._get_vlan_children(trunk_dev)
            to_delete = existing - expected
            to_create = expected - existing
            for devname, vlan_id in to_delete:
                LOG.debug("Deleting subport %(name)s with vlan tag %(tag)s",
                          dict(name=devname, tag=vlan_id))
                self._safe_delete_device(devname)
            for devname, vlan_id in to_create:
                LOG.debug("Creating subport %(name)s with vlan tag %(tag)s",
                          dict(name=devname, tag=vlan_id))
                self._create_vlan_subint(trunk_dev, devname, vlan_id)

    def delete_trunk_subports(self, trunk):
        return self.delete_subports_by_port_id(trunk.port_id)

    def delete_subports_by_port_id(self, port_id):
        device = self._get_tap_device_name(port_id)
        if not ip_lib.device_exists(device, namespace=self.namespace):
            LOG.debug("Device %s not present on this host", device)
            return
        with self._trunk_lock(device):
            for subname, vlan_id in self._get_vlan_children(device):
                LOG.debug("Deleting subport %(name)s with vlan tag %(tag)s",
                          dict(name=subname, tag=vlan_id))
                self._safe_delete_device(subname)

    def _trunk_lock(self, trunk_dev):
        lock_name = 'trunk-%s' % trunk_dev
        return lockutils.lock(lock_name, runtime.SYNCHRONIZED_PREFIX)

    def _create_vlan_subint(self, trunk_name, devname, vlan_id):
        ip_wrap = ip_lib.IPWrapper(namespace=self.namespace)
        try:
            dev = ip_wrap.add_vlan(devname, trunk_name, vlan_id)
            dev.disable_ipv6()
        except Exception:
            with excutils.save_and_reraise_exception() as ectx:
                ectx.reraise = ip_lib.IPDevice(
                    devname, namespace=self.namespace).exists()

    def _safe_delete_device(self, devname):
        dev = ip_lib.IPDevice(devname, namespace=self.namespace)
        try:
            dev.link.set_down()
            dev.link.delete()
        except Exception:
            with excutils.save_and_reraise_exception() as ectx:
                ectx.reraise = dev.exists()

    def _trunk_device_name(self, trunk):
        return self._get_tap_device_name(trunk.port_id)

    def _get_subport_devs_and_vlans(self, subports):
        return {(self._get_tap_device_name(s.port_id),
                 s.segmentation_id)
                for s in subports}

    def _get_tap_device_name(self, devname):
        return lutil.get_tap_device_name(devname)

    def _get_vlan_children(self, dev):
        """Return set of (devname, vlan_id) tuples for children of device."""
        # TODO(kevinbenton): move into ip-lib after privsep stuff settles
        ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        output = ip_wrapper.netns.execute(["ip", "-d", "link", "list"],
                                          check_exit_code=True)
        return {(i.devname, i.vlan_tag)
                for i in _iter_output_by_interface(output)
                if i.parent_devname == dev}


def _iter_output_by_interface(output):
    interface = []
    for line in output.splitlines():
        if not line.startswith(' '):
            # no space indicates new interface info
            interface_str = ' '.join(interface)
            if interface_str.strip():
                yield _InterfaceInfo(interface_str)
                interface = []
        interface.append(line)
    if interface:
        yield _InterfaceInfo(' '.join(interface))


class _InterfaceInfo(object):
    def __init__(self, line):
        try:
            name_section = line.split(': ')[1]
        except IndexError:
            name_section = None
            LOG.warning("Bad interface line: %s", line)
        if not name_section or '@' not in name_section:
            self.devname = name_section
            self.parent_devname = self.vlan_tag = None
        else:
            self.devname, parent = name_section.split('@')
            m = re.match(r'.*802\.1Q id (\d+).*', line)
            self.vlan_tag = int(m.group(1)) if m else None
            # we only care about parent interfaces if it's a vlan sub-interface
            self.parent_devname = parent if self.vlan_tag is not None else None

    def __repr__(self):
        return ('_InterfaceInfo(devname=%s, parent=%s, vlan=%s)' %
                (self.devname, self.parent_devname, self.vlan_tag))
