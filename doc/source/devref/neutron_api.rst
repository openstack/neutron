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
