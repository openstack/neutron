# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
#
# @author: Sumit Naiksatam, Cisco Systems, Inc.
#
#

import MySQLdb
import sys, traceback

from nova import flags
from nova import log as logging

FLAGS = flags.FLAGS
LOG = logging.getLogger('nova.virt.libvirt_conn')
#
# TODO (Sumit): The following are defaults, but we might need to make it conf file driven as well
#

flags.DEFINE_string('db_server_ip', "127.0.0.1", 'IP address of nova DB server')
flags.DEFINE_string('db_username', "root", 'DB username')
flags.DEFINE_string('db_password', "nova", 'DB paswwprd')
flags.DEFINE_string('db_name', "nova", 'DB name')
flags.DEFINE_string('nova_proj_name', "demo", 'project created in nova')
flags.DEFINE_string('nova_host_name', "openstack-0203", 'nova cloud controller hostname')

class CiscoUCSComputeDriver(object):
    def __init__(self):
	pass
    
    def _get_db_connection(self):
	self.db = MySQLdb.connect(FLAGS.db_server_ip, FLAGS.db_username, FLAGS.db_password, FLAGS.db_name)
	return self.db
	
    def _execute_db_query(self, sql_query):
	db = self._get_db_connection()
	cursor = db.cursor()
	try:
   		cursor.execute(sql_query)
		results = cursor.fetchall()
   		db.commit()
		print "DB query execution succeeded: %s" % sql_query
	except:
   		db.rollback()
		print "DB query execution failed: %s" % sql_query
		traceback.print_exc()
	db.close()
	return results

    def reserve_port(self, instance_name, instance_nic_name):
	sql_query = "SELECT * from ports WHERE used='0'"
	results = self._execute_db_query(sql_query)
	if len(results) == 0:
		print "No ports available/n"
		return 0
	else:
		for row in results:
			port_id = row[0];
			sql_query = "UPDATE ports SET instance_name = '%s', instance_nic_name = '%s' WHERE port_id = '%s'" % (instance_name, instance_nic_name, port_id)
			results = self._execute_db_query(sql_query)
			return port_id;
	return 0

    def get_port_details(self, port_id):
	port_details = {}
	sql_query = "SELECT * from ports WHERE port_id='%s'" % (port_id)
	results = self._execute_db_query(sql_query)
	if len(results) == 0:
		print "Could not fetch port from DB for port_id = %s/n" % port_id
		return 
	else:
		for row in results:
			profile_name = row[1];
			dynamic_vnic = row[2];
			sql_query = "UPDATE ports SET used = %d WHERE port_id = '%s'" % (1, port_id)
			results = self._execute_db_query(sql_query)
			port_details = {'profile_name':profile_name, 'dynamic_vnic':dynamic_vnic}
			return port_details;

    def release_port(self, instance_name, instance_nic_name):
	sql_query = "SELECT * from ports WHERE instance_name='%s' and instance_nic_name='%s'" % (instance_name, instance_nic_name)
	results = self._execute_db_query(sql_query)
	if len(results) == 0:
		print "No matching ports found for releasing/n"
		return 0
	else:
		for row in results:
			port_id = row[0];
			sql_query = "UPDATE ports SET instance_name = NULL, instance_nic_name = NULL, used = 0  WHERE port_id = '%s'" % (port_id)
			results = self._execute_db_query(sql_query)
			return port_id;
	return 0

def main():
	client = CiscoUCSComputeDriver()
	port_id = client.reserve_port("instance-1", "eth1")
	port_details = client.get_port_details(port_id)
	print "profile_name %s dynamic_vnic %s\n" % (port_details['profile_name'], port_details['dynamic_vnic'])
	port_id = client.release_port("instance-1", "eth1")

if __name__ == '__main__': 
	main() 
