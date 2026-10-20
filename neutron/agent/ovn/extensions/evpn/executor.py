# Copyright 2026 Red Hat, LLC
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

import collections
import dataclasses
import threading
import time
import typing

from oslo_log import log

LOG = log.getLogger(__name__)


@dataclasses.dataclass
class _Task:
    """A single provisioning or deprovisioning command."""
    action: typing.Callable
    args: tuple
    retries_left: int
    backoff: float
    retry_after: float = 0.0


class EvpnExecutor:
    """Single-threaded EVPN provisioning executor with dedup queue.

    Public methods ``provision(evpn)`` and ``deprovision(evpn)`` are
    fire-and-forget: they place a command on the ``_ready`` queue and
    return immediately.  A single daemon worker thread processes the
    queue in FIFO order.

    Submitting a new command for the same VRF overwrites any pending
    entry in both ``_ready`` and ``_deferred`` (automatic dedup).
    Both queues are keyed by VRF name, matching EvpnFSM.instances.

    On failure, a command is moved to ``_deferred`` with an
    exponential backoff.  The worker continues processing other ready
    items while deferred commands wait.
    """

    def __init__(self, svd, br_mtu, driver,
                 max_retries=4,
                 initial_backoff=1.0,
                 max_backoff=60.0):
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._ready = collections.OrderedDict()   # vrf -> _Task
        self._deferred = {}                        # vrf -> _Task
        self._cond = threading.Condition()
        self._svd = svd
        self._br_mtu = br_mtu
        self._driver = driver
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def provision(self, evpn):
        """Queue a provision command for *evpn*.

        Captures vrf/vni/vid/mac eagerly so concurrent FSM mutations
        cannot affect the worker thread.
        """
        vrf, vni, vid, mac = evpn.vrf, evpn.vni, evpn.vid, evpn.mac
        task = _Task(
            action=self._do_provision,
            args=(vrf, vni, vid, mac),
            retries_left=self._max_retries,
            backoff=self._initial_backoff)
        self._submit(vrf, task)

    def deprovision(self, evpn):
        """Queue a deprovision command for *evpn*.

        Captures vrf/vni/vid eagerly so the FSM can clear the instance
        fields immediately after this call returns.
        """
        # NOTE: If deprovision fails in the FRR driver, the VNI can remain
        # mapped to the old VRF. A later provision of a different EVPN
        # instance that reuses the same VNI will then fail, e.g.
        # "Failed to create cfgdata: vni 100 is already mapped to another
        # vrf". FRR does not support force-updating a VNI mapping; the
        # stale mapping must be deleted before the VNI can be reused.
        # This is a known limitation and is not addressed yet.
        vrf, vni, vid = evpn.vrf, evpn.vni, evpn.vid
        task = _Task(
            action=self._do_deprovision,
            args=(vrf, vni, vid),
            retries_left=self._max_retries,
            backoff=self._initial_backoff)
        self._submit(vrf, task)

    def _do_provision(self, vrf, vni, vid, mac):
        self._svd.add_vni(vni, vid, vrf, mac, self._br_mtu)
        self._driver.create_router(vrf, vni)

    def _do_deprovision(self, vrf, vni, vid):
        self._svd.del_vni(vni, vid)
        self._driver.delete_router(vrf, vni)

    def _submit(self, vrf, task):
        """Insert or overwrite a command for *vrf* and wake the worker."""
        with self._cond:
            self._ready[vrf] = task
            self._ready.move_to_end(vrf)
            self._deferred.pop(vrf, None)
            self._cond.notify()

    def _promote_deferred(self):
        """Move deferred items whose retry_after has passed into _ready.

        Must be called with self._cond held.
        """
        now = time.monotonic()
        due = [vrf for vrf, task in self._deferred.items()
               if task.retry_after <= now]
        for vrf in due:
            task = self._deferred.pop(vrf)
            self._ready[vrf] = task
            self._ready.move_to_end(vrf)

    def _earliest_retry(self):
        """Return seconds until the soonest deferred item is due.

        Must be called with self._cond held.  Returns None if
        _deferred is empty.
        """
        if not self._deferred:
            return None
        now = time.monotonic()
        earliest = min(task.retry_after for task in self._deferred.values())
        return max(0, earliest - now)

    def _run(self):
        while True:
            with self._cond:
                self._promote_deferred()
                while not self._ready:
                    if self._deferred:
                        timeout = self._earliest_retry()
                        self._cond.wait(timeout=timeout)
                        self._promote_deferred()
                    else:
                        self._cond.wait()
                vrf, task = self._ready.popitem(last=False)

            # A newer command for the same vrf may have been submitted
            # between the two lock acquisitions; skip the stale task.
            with self._cond:
                if vrf in self._ready:
                    continue
            try:
                task.action(*task.args)
            except Exception:
                task.retries_left -= 1
                if task.retries_left <= 0:
                    LOG.exception("Exhausted %d retries", self._max_retries)
                    continue
                LOG.warning("Attempt failed (%d retries left)",
                            task.retries_left, exc_info=True)
                with self._cond:
                    if vrf not in self._ready:
                        task.retry_after = time.monotonic() + task.backoff
                        task.backoff = min(
                            task.backoff * 2, self._max_backoff)
                        self._deferred[vrf] = task
