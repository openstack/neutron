Neutron Gate Failure Triage
===========================

This page provides guidelines for spotting and assessing neutron gate failures. Some hints for triaging
failures are also provided.

Spotting Gate Failures
----------------------
This can be achieved using several tools:

* `Grafana dashboard <http://grafana.openstack.org/dashboard/db/neutron-failure-rate>`_
* `logstash <http://logstash.openstack.org/>`_

For checking gate failures with logstash the following query will return failures for a specific job:

> build_status:FAILURE AND message:Finished  AND build_name:"check-tempest-dsvm-neutron" AND build_queue:"gate"

And divided by the total number of jobs executed:

> message:Finished  AND build_name:"check-tempest-dsvm-neutron" AND build_queue:"gate"

It will return the failure rate in the selected period for a given job. It is important to remark that
failures in the check queue might be misleading as the problem causing the failure is most of the time in
the patch being checked. Therefore it is always advisable to work on failures occurred in the gate queue.
However, these failures are a precious resource for assessing frequency and determining root cause of
failures which manifest in the gate queue.

The step above will provide a quick outlook of where things stand. When the failure rate raises above 10% for
a job in 24 hours, it's time to be on alert. 25% is amber alert. 33% is red alert. Anything above 50% means
that probably somebody from the infra team has already a contract out on you. Whether you are relaxed, in
alert mode, or freaking out because you see a red dot on your chest, it is always a good idea to check on
daily bases the elastic-recheck pages.

Under the `gate pipeline <http://status.openstack.org/elastic-recheck/gate.html>`_ tab, you can see gate
failure rates for already known bugs. The bugs in this page are ordered by decreasing failure rates (for the
past 24 hours). If one of the bugs affecting Neutron is among those on top of that list, you should check
that the corresponding bug is already assigned and somebody is working on it. If not, and there is not a good
reason for that, it should be ensured somebody gets a crack at it as soon as possible. The other part of the
story is to check for `uncategorized <http://status.openstack.org/elastic-recheck/data/uncategorized.html>`_
failures. This is where failures for new (unknown) gate breaking bugs end up; on the other hand also infra
error causing job failures end up here. It should be duty of the diligent Neutron developer to ensure the
classification rate for neutron jobs is as close as possible to 100%. To this aim, the diligent Neutron
developer should adopt the procedure outlined in the following sections.

.. _troubleshooting-tempest-jobs:

Troubleshooting Tempest jobs
----------------------------
1. Open logs for failed jobs and look for logs/testr_results.html.gz.
2. If that file is missing, check console.html and see where the job failed.
    1. If there is a failure in devstack-gate-cleanup-host.txt it's likely to be an infra issue.
    2. If the failure is in devstacklog.txt it could a devstack, neutron, or infra issue.
3. However, most of the time the failure is in one of the tempest tests. Take note of the error message and go to
   logstash.
4. On logstash, search for occurrences of this error message, and try to identify the root cause for the failure
   (see below).
5. File a bug for this failure, and push an :ref:`Elastic Recheck Query <elastic-recheck-query>` for it.
6. If you are confident with the area of this bug, and you have time, assign it to yourself; otherwise look for an
    assignee or talk to the Neutron's bug czar to find an assignee.

Troubleshooting functional/fullstack job
----------------------------------------
1. Go to the job link provided by Jenkins CI.
2. Look at logs/testr_results.html.gz for which particular test failed.
3. More logs from a particular test are stored at
   logs/dsvm-functional-logs/<path_of_the_test> (or dsvm-fullstack-logs
   for fullstack job).
4. Find the error in the logs and search for similar errors in existing
   launchpad bugs. If no bugs were reported, create a new bug report. Don't
   forget to put a snippet of the trace into the new launchpad bug. If the
   log file for a particular job doesn't contain any trace, pick the one
   from testr_results.html.gz.
5. Create an :ref:`Elastic Recheck Query <elastic-recheck-query>`

Advanced Troubleshooting of Gate Jobs
-------------------------------------
As a first step of troubleshooting a failing gate job, you should always check
the logs of the job as described above.
Unfortunately, sometimes when a tempest/functional/fullstack job is
failing, it might be hard to reproduce it in a local environment, and might
also be hard to understand the reason of such a failure from only reading
the logs of the failed job.  In such cases there are some additional ways
to debug the job directly on the test node in a ``live`` setting.

This can be done in two ways:

1. Using the `remote_pdb <https://pypi.org/project/remote-pdb>`_ python
   module and ``telnet`` to directly access the python debugger while in the
   failed test.

   To achieve this, you need to send a ``Do not merge`` patch to gerrit with
   changes as described below:

   * Add an iptables rule to accept incoming telnet connections to remote_pdb.
     This can be done in one of the ansible roles used in the test job.
     Like for example in ``neutron/roles/configure_functional_tests`` file
     for functional tests::

        sudo iptables -I openstack-INPUT -p tcp -m state --state NEW -m tcp --dport 44444 -j ACCEPT

   * Increase the ``OS_TEST_TIMEOUT`` value to make the test wait longer when
     remote_pdb is active to make debugging easier.  This change can also be
     done in the ansible role mentioned above::

        export OS_TEST_TIMEOUT=999999

     Please note that the overall job will be limited by the job timeout,
     and that cannot be changed from within the job.

   * To make it easier to find the IP address of the test node, you should
     add to the ansible role so it prints the IPs configured on the test node.
     For example::

        hostname -I

   * Add the package ``remote_pdb`` to the ``test-requirements.txt`` file.
     That way it will be automatically installed in the venv of the test
     before it is run::

         $ tail -1 test-requirements.txt
         remote_pdb

   * Finally, you need to import and call the remote_pdb module in the part
     of your test code where you want to start the debugger::

        $ diff --git a/neutron/tests/fullstack/test_connectivity.py b/neutron/tests/fullstack/test_connectivity.py
        index c8650b0..260207b 100644
        --- a/neutron/tests/fullstack/test_connectivity.py
        +++ b/neutron/tests/fullstack/test_connectivity.py
        @@ -189,6 +189,8 @@ class
        TestLinuxBridgeConnectivitySameNetwork(BaseConnectivitySameNetworkTest):
                ]

             def test_connectivity(self):
        +        import remote_pdb; remote_pdb.set_trace('0.0.0.0', port=44444)
        +
        self._test_connectivity()

     Please note that discovery of public IP addresses is necessary because by
     default remote_pdb will only bind to the ``127.0.0.1`` IP address.
     Above is just an example of one of possible method, there could be other
     ways to do this as well.

   When all the above changes are done, you must commit them and go to the
   `Zuul status page <https://zuul.openstack.org>`_ to find the status of the
   tests for your ``Do not merge`` patch.  Open the console log for your job
   and wait there until ``remote_pdb`` is started.
   You then need to find the IP address of the test node in the console log.
   This is necessary to connect via ``telnet`` and start debugging. It will be
   something like::

        RemotePdb session open at 172.99.68.50:44444, waiting for connection ...

   An example of such a ``Do not merge`` patch described above can be found at
   `<https://review.opendev.org/#/c/558259/>`_.

   Please note that after adding new packages to the ``requirements.txt`` file,
   the ``requirements-check`` job for your test patch will fail, but it is not
   important for debugging.

2. If root access to the test node is necessary, for example, to check if VMs
   have really been spawned, or if router/dhcp namespaces have been configured
   properly, etc., you can ask a member of the infra-team to hold the
   job for troubleshooting.  You can ask someone to help with that on the
   ``openstack-infra`` IRC channel.  In that case, the infra-team will need to
   add your SSH key to the test node, and configure things so that if the job
   fails, the node will not be destroyed.  You will then be able to SSH to it
   and debug things further.  Please remember to tell the infra-team when you
   finish debugging so they can unlock and destroy the node being held.

The above two solutions can be used together. For example, you should be
able to connect to the test node with both methods:

* using ``remote_pdb`` to connect via ``telnet``;
* using ``SSH`` to connect as a root to the test node.

You can then ask the infra-team to add your key to the specific node on
which you have already started your ``remote_pdb`` session.

Root Causing a Gate Failure
---------------------------
Time-based identification, i.e. find the naughty patch by log scavenging.

.. _elastic-recheck-query:

Filing An Elastic Recheck Query
-------------------------------
The `elastic recheck <http://status.openstack.org/elastic-recheck/>`_ page has all the current open ER queries.
To file one, please see the `ER Wiki <https://wiki.openstack.org/wiki/ElasticRecheck>`_.
