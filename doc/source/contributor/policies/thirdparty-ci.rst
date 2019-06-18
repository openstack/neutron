Neutron Third-party CI
======================

What Is Expected of Third Party CI System for Neutron
-----------------------------------------------------

As of the Liberty summit, Neutron no longer *requires* a third-party CI,
but it is strongly encouraged, as internal neutron refactoring can break
external plugins and drivers at any time.

Neutron expects any Third Party CI system that interacts with gerrit to
follow the requirements set by the Infrastructure team [1]_ as well as the
Neutron Third Party CI guidelines below. Please ping the PTL in
#openstack-neutron or send an email to the openstack-discuss ML (with subject
[neutron]) with any questions. Be aware that the Infrastructure documentation
as well as this document are living documents and undergo changes. Track
changes to the infrastructure documentation using this url [2]_ (and please
review the patches) and check this doc on a regular basis for updates.

What Changes to Run Against
---------------------------

If your code is a neutron plugin or driver, you should run against every
neutron change submitted, except for docs, tests, tools, and top-level
setup files. You can skip your CI runs for such exceptions by using
``skip-if`` and ``all-files-match-any`` directives in Zuul.
You can see a programmatic example of the exceptions here [3]_.

If your code is in a neutron-\*aas repo, you should run against the tests
for that repo. You may also run against every neutron change, if your service
driver is using neutron interfaces that are not provided by your service
plugin (e.g. firewall/fwaas_plugin_v2.py). If you are using only plugin
interfaces, it should be safe to test against only the service repo tests.

What Tests To Run
-----------------

Network API tests (git link).
Network scenario tests (The test_network_* tests here).
Any tests written specifically for your setup.
http://opendev.org/openstack/tempest/tree/tempest/api/network

Run with the test filter: 'network'. This will include all neutron specific
tests as well as any other tests that are tagged as requiring networking. An
example tempest setup for devstack-gate::

   export DEVSTACK_GATE_NEUTRON=1
   export DEVSTACK_GATE_TEMPEST_REGEX='(?!.*\[.*\bslow\b.*\])((network)|(neutron))'

Third Party CI Voting
---------------------

The Neutron team encourages you to NOT vote -1 with a third-party CI. False
negatives are noisy to the community, and have given -1 from third-party
CIs a bad reputation. Really bad, to the point of people ignoring them all.
Failure messages are useful to those doing refactors, and provide you
feedback on the state of your plugin.

If you insist on voting, by default, the infra team will not allow voting
by new 3rd party CI systems. The way to get your 3rd party CI system to vote
is to talk with the Neutron PTL, who will let infra know the system is ready
to vote. The requirements for a new system to be given voting rights are as
follows:

* A new system must be up and running for a month, with a track record of
  voting on the sandbox system.
* A new system must correctly run and pass tests on patches for the third
  party driver/plugin for a month.
* A new system must have a logfile setup and retention setup similar to the
  below.

Once the system has been running for a month, the owner of the third party CI
system can contact the Neutron PTL to have a conversation about getting voting
rights upstream.

The general process to get these voting rights is outlined here. Please follow
that, taking note of the guidelines Neutron also places on voting for it's CI
systems.

A third party system can have it's voting rights removed as well. If the
system becomes unstable (stops running, voting, or start providing inaccurate
results), the Neutron PTL or any core reviewer will make an attempt to contact
the owner and copy the openstack-discuss mailing list. If no response is received
within 2 days, the Neutron PTL will remove voting rights for the third party
CI system. If a response is received, the owner will work to correct the
issue. If the issue cannot be addressed in a reasonable amount of time, the
voting rights will be temporarily removed.

Log & Test Results Filesystem Layout
------------------------------------

Third-Party CI systems MUST provide logs and configuration data to help
developers troubleshoot test failures. A third-party CI that DOES NOT post
logs should be a candidate for removal, and new CI systems MUST post logs
before they can be awarded voting privileges.

Third party CI systems should follow the filesystem layout convention of the
OpenStack CI system. Please store your logs as viewable in a web browser, in
a directory structure. Requiring the user to download a giant tarball is not
acceptable, and will be reason to not allow your system to vote from the
start, or cancel it's voting rights if this changes while the system is
running.

At the root of the results - there should be the following:

* console.html.gz - contains the output of stdout of the test run
* local.conf / localrc - contains the setup used for this run
* logs - contains the output of detail test log of the test run

The above "logs" must be a directory, which contains the following:

* Log files for each screen session that DevStack creates and launches an
  OpenStack component in
* Test result files
* testr_results.html.gz
* tempest.txt.gz

List of existing plugins and drivers
------------------------------------

https://wiki.openstack.org/wiki/Neutron_Plugins_and_Drivers#Existing_Plugin_and_Drivers

References
----------

.. [1] http://ci.openstack.org/third_party.html
.. [2] https://review.opendev.org/#/q/status:open+project:openstack-infra/system-config+branch:master+topic:third-party,n,z
.. [3] https://github.com/openstack-infra/project-config/blob/master/dev/zuul/layout.yaml
