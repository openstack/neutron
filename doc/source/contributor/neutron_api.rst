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


Neutron public API
==================

Neutron main tree serves as a library for multiple subprojects that rely on
different modules from neutron.* namespace to accommodate their needs.
Specifically, advanced service repositories and open source or vendor
plugin/driver repositories do it.

Neutron modules differ in their API stability a lot, and there is no part of it
that is explicitly marked to be consumed by other projects.

That said, there are modules that other projects should definitely avoid
relying on.


Breakages
---------

Neutron API is not very stable, and there are cases when a desired change in
neutron tree is expected to trigger breakage for one or more external
repositories under the neutron tent. Below you can find a list of known
incompatible changes that could or are known to trigger those breakages.
The changes are listed in reverse chronological order (newer at the top).

* change: QoS plugin refactor

  - commit: I863f063a0cfbb464cedd00bddc15dd853cbb6389
  - solution: implement the new abstract methods in
              neutron.extensions.qos.QoSPluginBase.
  - severity: Low (some out-of-tree plugins might be affected).

* change: Consume ConfigurableMiddleware from oslo_middleware.

  - commit: If7360608f94625b7d0972267b763f3e7d7624fee
  - solution: switch to oslo_middleware.base.ConfigurableMiddleware;
              stop using neutron.wsgi.Middleware and neutron.wsgi.Debug.
  - severity: Low (some out-of-tree plugins might be affected).

* change: Consume sslutils and wsgi modules from oslo.service.

  - commit: Ibfdf07e665fcfcd093a0e31274e1a6116706aec2
  - solution: switch using oslo_service.wsgi.Router; stop using
              neutron.wsgi.Router.
  - severity: Low (some out-of-tree plugins might be affected).

* change: oslo.service adopted.

  - commit: 6e693fc91dd79cfbf181e3b015a1816d985ad02c
  - solution: switch using oslo_service.* namespace; stop using ANY
              neutron.openstack.* contents.
  - severity: low (plugins must not rely on that subtree).

* change: oslo.utils.fileutils adopted.

  - commit: I933d02aa48260069149d16caed02b020296b943a
  - solution: switch using oslo_utils.fileutils module; stop using
              neutron.openstack.fileutils module.
  - severity: low (plugins must not rely on that subtree).

* change: Reuse caller's session in DB methods.

  - commit: 47dd65cf986d712e9c6ca5dcf4420dfc44900b66
  - solution: Add context to args and reuse.
  - severity: High (mostly undetected, as 3rd party CI run Tempest tests only).

* change: switches to oslo.log, removes neutron.openstack.common.log.

  - commit: 22328baf1f60719fcaa5b0fbd91c0a3158d09c31
  - solution: a) switch to oslo.log; b) copy log module into your tree and
              use it (may not work due to conflicts between the module
              and oslo.log configuration options).
  - severity: High (most CI systems are affected).

* change: Implements reorganize-unit-test-tree spec.

  - commit: 1105782e3914f601b8f4be64939816b1afe8fb54
  - solution: Code affected needs to update existing unit tests to reflect
              new locations.
  - severity: High (mostly undetected, as 3rd party CI run Tempest tests only).

* change: drop linux/ovs_lib compat layer.

  - commit: 3bbf473b49457c4afbfc23fd9f59be8aa08a257d
  - solution: switch to using neutron/agent/common/ovs_lib.py.
  - severity: High (most CI systems are affected).
