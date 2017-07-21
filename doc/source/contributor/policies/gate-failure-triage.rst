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

Root Causing a Gate Failure
---------------------------
Time-based identification, i.e. find the naughty patch by log scavenging.

.. _elastic-recheck-query:

Filing An Elastic Recheck Query
-------------------------------
The `elastic recheck <http://status.openstack.org/elastic-recheck/>`_ page has all the current open ER queries.
To file one, please see the `ER Wiki <https://wiki.openstack.org/wiki/ElasticRecheck>`_.
