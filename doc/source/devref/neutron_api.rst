Neutron public API
==================

Neutron main tree serves as a library for multiple subprojects that rely on
different modules from neutron.* namespace to accomodate their needs.
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
