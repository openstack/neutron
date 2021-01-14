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


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Service Extensions
==================

Historically, Neutron supported the following advanced services:

#. **FWaaS** (*Firewall-as-a-Service*): runs as part of the L3 agent.
#. **VPNaaS** (*VPN-as-a-Service*): derives from L3 agent to add
   VPNaaS functionality.

.. note::

   neutron-fwaas is deprecated and no more maintained!

Starting with the Kilo release, these services are split into separate
repositories, and more extensions are being developed as well. Service
plugins are a clean way of adding functionality in a cohesive manner
and yet, keeping them decoupled from the guts of the framework. The
aforementioned features are developed as extensions (also known as
service plugins), and more capabilities are being added to Neutron
following the same pattern. For those that are deemed 'orthogonal'
to any network service (e.g. tags, timestamps, auto_allocate, etc),
there is an informal `mechanism <https://github.com/openstack/neutron/blob/aadf2f30f84dff3d85f380a7ff4e16dbbb0c6bb0/neutron/plugins/common/constants.py#L41>`_
to have these loaded automatically at server startup. If you
consider adding an entry to the dictionary, please be kind and
reach out to your PTL or a member of the drivers team for approval.

#. http://opendev.org/openstack/neutron-fwaas/
#. http://opendev.org/openstack/neutron-vpnaas/


Calling the Core Plugin from Services
-------------------------------------

There are many cases where a service may want to create a resource
managed by the core plugin (e.g. ports, networks, subnets). This
can be achieved by importing the plugins directory and getting a direct
reference to the core plugin:

.. code:: python

   from neutron_lib.plugins import directory

   plugin = directory.get_plugin()
   plugin.create_port(context, port_dict)


However, there is an important caveat. Calls to the core plugin in
almost every case should not be made inside of an ongoing transaction.
This is because many plugins (including ML2), can be configured to
make calls to a backend after creating or modifying an object. If
the call is made inside of a transaction and the transaction is
rolled back after the core plugin call, the backend will not be
notified that the change was undone. This will lead to consistency
errors between the core plugin and its configured backend(s).

ML2 has a guard against certain methods being called with an active
DB transaction to help prevent developers from accidentally making
this mistake. It will raise an error that says explicitly that the
method should not be called within a transaction.
