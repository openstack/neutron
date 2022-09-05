Prepare archive with the tests' logs

**Role Variables**

.. zuul:rolevar:: logs_path
   :default: /opt/stack/logs/dsvm-functional-logs

   Path where logs from the tests are stored on job's node.

.. zuul:rolevar:: log_archive_file_name
   :default: /opt/stack/logs/dsvm-functional-logs.tar.gz

   Name of archive with the logs.

