Neutron public API
==================

Neutron main tree serves as a library for multiple subprojects that rely on
different modules from neutron.* namespace to accommodate their needs.
Specifically, advanced service repositories and open source or vendor
plugin/driver repositories do it.

Neutron modules differ in their API stability a lot, and there is no part of it
that is explicitly marked to be consumed by other projects.

That said, there are modules that other projects should definitely avoid relying on.

Specifically, no external repository should use anything located under
neutron.openstack.common.* import path. This code belongs to oslo-incubator
modules and is not meant to work for consumers other than neutron main tree
itself. (The only exception is made for advanced service repositories that are
tightly controlled by neutron community.) Long story short, if your repository
uses those modules, please switch to corresponding oslo libraries or use your
own copy of oslo-incubator files.


Breakages
---------

Neutron API is not very stable, and there are cases when a desired change in
neutron tree is expected to trigger breakage for one or more external
repositories under the neutron tent. Below you can find a list of known
incompatible changes that could or are known to trigger those breakages.

* change: oslo.service adopted.

  - commit: 6e693fc91dd79cfbf181e3b015a1816d985ad02c
  - solution: switch using oslo_service.* namespace; stop using ANY neutron.openstack.* contents.
  - severity: low (plugins must not rely on that subtree).

* change: oslo.utils.fileutils adopted.

  - commit: I933d02aa48260069149d16caed02b020296b943a
  - solution: switch using oslo_utils.fileutils module; stop using neutron.openstack.fileutils module.
  - severity: low (plugins must not rely on that subtree).

* change: Reuse caller's session in DB methods.

  - commit: 47dd65cf986d712e9c6ca5dcf4420dfc44900b66
  - solution: Add context to args and reuse.
  - severity: High (mostly undetected, because 3rd party CI run Tempest tests only).

* change: switches to oslo.log, removes neutron.openstack.common.log.

  - commit: 22328baf1f60719fcaa5b0fbd91c0a3158d09c31
  - solution: a) switch to oslo.log; b) copy log module into your tree and use it
    (may not work due to conflicts between the module and oslo.log configuration options).
  - severity: High (most CI systems are affected).

* change: Implements reorganize-unit-test-tree spec.

  - commit: 1105782e3914f601b8f4be64939816b1afe8fb54
  - solution: Code affected need to update existing unit tests to reflect new locations.
  - severity: High (mostly undetected, because 3rd party CI run Tempest tests only).

* change: drop linux/ovs_lib compat layer.

  - commit: 3bbf473b49457c4afbfc23fd9f59be8aa08a257d
  - solution: switch to using neutron/agent/common/ovs_lib.py.
  - severity: High (most CI systems are affected).
