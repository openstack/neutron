..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


Segments Extension
==================

Neutron has an extension that allows CRUD operations on the ``/segments``
resource in the API, that corresponds to the ``NetworkSegment`` entity in the
DB layer. The extension is implemented as a service plug-in.

Details about the DB models, API extension, and use cases can be found here: `routed networks spec <http://specs.openstack.org/openstack/neutron-specs/specs/newton/routed-networks.html>`_

.. note:: The ``segments`` service plug-in is not configured by default. To
   configure it, add ``segments`` to the ``service_plugins`` parameter in
   ``neutron.conf``

Core plug-ins can coordinate with the ``segments`` service plug-in by
subscribing callbacks to events associated to the ``SEGMENT`` resource.
Currently, the segments plug-in notifies subscribers of the following events:

* ``PRECOMMIT_CREATE``
* ``AFTER_CREATE``
* ``BEFORE_DELETE``
* ``PRECOMMIT_DELETE``
* ``AFTER_DELETE``

As of this writing, ``ML2`` and ``OVN`` register callbacks to receive events
from the ``segments`` service plug-in. The ``ML2`` plug-in defines the
callback ``_handle_segment_change`` to process all the relevant segments
events.

Segments extension relevant modules
-----------------------------------

* ``neutron/extensions/segment.py`` defines the extension
* ``neutron/db/models/segment.py`` defines the DB models for segments and for
  the segment host mapping, that is used in the implementation of routed
  networks.
* ``neutron/db/segments_db.py`` has functions to add, retrieve and delete
  segments from the DB.
* ``neutron/services/segments/db.py`` defines a mixin class with the methods
  that perform API CRUD operations for the ``segments`` plug-in. It also has a
  set of functions to create and maintain the mapping of segments to hosts,
  which is necessary in the implementation of routed networks.
* ``neutron/services/segments/plugin.py`` defines the ``segments`` service
  plug-in.
