#!/usr/bin/python
# asnpc
# abyle simple nagios passive checker
#
# Copyright (C) 2014 Stefan Nistelberger (scuq(at)abyle.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# http://www.gnu.org/licenses/gpl.txt
#
# purpose:
# if you have a setup where passive checks a ruling, this script may
# help you to don't end up with hundreds of shell-scripts which are
# wrapping the send_nsca command via cronjobs
# 
# if you call this script with the --setup arg, it would setup some
# basic stuff needed to get your nsca passive checks managed 
# (on a debian system)
# - creates a user with the name asnpc
# - generates a random long password for the asnpc user
# - creates the main config directory /etc/asnpc and
#   it's subdirectories /etc/asnpc/checks-available and
#   /etc/asnpc/checks-enabled
# - builtin basic checks like "disk" will be written as 
#   example to /etc/asnpc/checks-available
# - /etc/send_nsca.cfg setup
#    - asks for nagios/icinga server's ip or hostname
#    -  asks for nsca password
#    - asks for the service-hostname = your local hostname
#      the name how it is called in the nagios config
# so finally you should end up with a working send_nsca.cfg
# 
# the idea of the checks-available and checks-enabled is just
# the same like debian is doing it for apache2 - see a2ensite 
# for more information.
#
# you could list available checks with the -l arg
#
# example:
# asnpc.py -l
# available checks:
# disk
#
# if you want to enable a check, e.g. disk, just softlink (ln -s)
# the "disk" from /etc/asnpc/checks-available to /etc/asnpc/checks-enabled
#
# if you call the script with -c ALL enabled check will be executed
# in one after the other, keep that in mind while configuring your
# icinga passive check freshness timeouts
# 
#
#
# changelog:
# 2014-03-18: initial release
#
scriptname="asnpc"

from optparse import OptionParser
import sys
import os
import uuid
import pwd
from shutil import copyfile
import subprocess


import logging
from logging.handlers import SysLogHandler
logger = logging.getLogger(scriptname)
logger.setLevel(logging.INFO)
syslog = SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
syslog.setFormatter(formatter)
logger.addHandler(syslog)

# nagios exit codes
OK   = 0
WARN = 1
CRIT = 2
UNKN = 3

def writeBuiltinChecks():

		# general disk space
		f = open("/etc/"+scriptname+"/checks-available/disk."+scriptname, 'w')
		f.write("/usr/lib/nagios/plugins/check_disk -w 70 -c 95 -x /dev -x /run -x /run/lock -x /run/shm\n")
		f.close()

		# general check load
		f = open("/etc/"+scriptname+"/checks-available/load."+scriptname, 'w')
		f.write("/usr/lib/nagios/plugins/check_load -w 5.0,4.0,3.0 -c 10.0,6.0,4.0\n")
		f.close()

		# general iptables loaded check
		f = open("/etc/"+scriptname+"/checks-available/iptables."+scriptname, 'w')
		f.write("sudo /home/asnpc/scripts/check_iptables.sh\n")
		f.close()

		# openfire jabber server process running
		f = open("/etc/"+scriptname+"/checks-available/proc-openfire."+scriptname, 'w')
		f.write("/usr/lib/nagios/plugins/check_procs -c 1:1 -C java -a 'openfire'\n")
		f.close()
	
		# mumble server process running
		f = open("/etc/"+scriptname+"/checks-available/proc-mumbleserver."+scriptname, 'w')
		f.write("/usr/lib/nagios/plugins/check_procs -c 1:1 -C murmurd\n")
		f.close()


		# check free memory
		f = open("/etc/"+scriptname+"/checks-available/memory."+scriptname, 'w')
		f.write("/home/asnpc/scripts/check_memory.pl -w 30% -c 8%\n")
		f.close()


def main():

	parser = OptionParser()
	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="enable debug, use with caution, prints passwords!")
	parser.add_option("", "--setup", action="store_true", dest="setup", default=False, help="setup asnpc default config and user")
	parser.add_option("", "--check-setup", action="store_true", dest="checksetup", default=False, help="write builtin checks to checks-available")
	parser.add_option("-l", "--list-checks", action="store_true", dest="listchecks", default=False, help="print a list of available checks")
	parser.add_option("-e", "--list-enabled-checks", action="store_true", dest="listenabledchecks", default=False, help="print a list of enabled checks")
	parser.add_option("-c", "--execute-checks", action="store_true", dest="executechecks", default=False, help="execute all enabled checks")
	parser.add_option("-p", "--execute-host-check", action="store_true", dest="executehostchecks", default=False, help="execute passive host check use with -c")
	(options, args) = parser.parse_args()

	logger.info("script started.")

	if options.checksetup:

		print "writing builtin-checks, use -l to list available checks"
		writeBuiltinChecks()

	if options.executechecks:

		nagiosServer = "127.0.0.1"
		mynagiosHostname = "localhost"

		f = open("/etc/send_nsca.cfg",'r')
		nscalines = f.readlines()
		f.close()

		for line in nscalines:
			if line.count("##abyle##server=") > 0:
				nagiosServer = line.replace("##abyle##server=","").strip()
			if line.count("##abyle##myhostname=") > 0:
				mynagiosHostname = line.replace("##abyle##myhostname=","").strip()

		if options.executehostchecks:
			logger.info("executing host passive check")
			msg = "%s\t%d\t%s\n" % (mynagiosHostname, 0, 'Output: Passive Host Check OK')
			nsca = subprocess.Popen(['/usr/sbin/send_nsca', '-H', nagiosServer], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
			(nsca_out, nsca_err) = nsca.communicate(msg)
			if nsca.returncode != 0:
				logger.error('send_nsca failed with returncode '+str(nsca.returncode)+' and ouput:'+nsca_out)
			sys.exit(0)

                if os.path.isdir("/etc/"+scriptname+"/checks-enabled/"):
                        for dirname, dirnames, filenames in os.walk("/etc/"+scriptname+"/checks-enabled/"):
                                for filename in filenames:
                                        if filename.endswith("."+scriptname):
                                                logger.info("executing: "+filename.replace("."+scriptname,""))
						f = open("/etc/"+scriptname+"/checks-enabled/"+filename,'r')
						command = f.readline()
						f.close()	
						logger.debug("executing check-command: "+command)

						process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
						process.wait()



						msg = "%s\t%s\t%d\t%s\n" % (mynagiosHostname, filename.replace("."+scriptname,""), process.returncode, 'Output: ' + str(process.stdout.readline()))
						nsca = subprocess.Popen(['/usr/sbin/send_nsca', '-H', nagiosServer], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
						(nsca_out, nsca_err) = nsca.communicate(msg)

						if nsca.returncode != 0:
							logger.error('send_nsca failed with returncode '+str(nsca.returncode)+' and ouput:'+nsca_out)	
						

	if options.listenabledchecks:
                print "enabled checks:"
                print "to enable checks use ln -s and link an available check to the checks-enabled dir"

                if os.path.isdir("/etc/"+scriptname+"/checks-enabled/"):
                        for dirname, dirnames, filenames in os.walk("/etc/"+scriptname+"/checks-enabled/"):
                                for filename in filenames:
                                        if filename.endswith("."+scriptname):
                                                print filename.replace("."+scriptname,"")

	if options.listchecks:
		print "available checks:"

		if os.path.isdir("/etc/"+scriptname+"/checks-available/"):
			for dirname, dirnames, filenames in os.walk("/etc/"+scriptname+"/checks-available/"):
				for filename in filenames:
					if filename.endswith("."+scriptname):
						print filename.replace("."+scriptname,"")

	if options.setup:
		username="asnpc"
		userExists=False

		try:
			pwd.getpwnam(username)
			userExists=True
		except KeyError:
			userExists=False
			
		if not userExists:
		
			os.system ("useradd -p "+str(uuid.uuid1())+str(uuid.uuid1())+ " -s "+ "/bin/bash "+ "-d "+ "/home/" + username+ " -m "+ " -c \""+ username+"\" " + username)
			print "user: "+username+" added."
		else:
			print "user: "+username+" already exist."

		if os.path.isdir("/etc/"+scriptname):
			print "config directory: /etc/"+scriptname+" already exist."
		else:
			os.makedirs("/etc/"+scriptname) 
			os.makedirs("/etc/"+scriptname+"/checks-available/") 
			os.makedirs("/etc/"+scriptname+"/checks-enabled/") 
			print "config directory: /etc/"+scriptname+" created."

			writeBuiltinChecks()




		os.system ("apt-get install nsca-client nagios-plugins-basic libnagios-plugin-perl sudo")


		if os.path.exists('/etc/send_nsca.cfg'):
			print "file /etc/send_nsca.cfg already exists creating backup: /etc/send_nsca.cfg.bck"
			copyfile ("/etc/send_nsca.cfg", "/etc/send_nsca.cfg.bck")

			
		nagiosServer = raw_input("Enter Nagios servername or ip: ")
		nscaPassword = raw_input("Enter NSCA Password: ")
		myNagiosHostname = raw_input("Enter local hostname (as it is defined in nagios): ")

		f = open('/etc/send_nsca.cfg', 'w')
		f.write("####################################################\n")
		f.write("# Abyle NSCA Client Config File\n")
		f.write("####################################################\n")
		f.write("\n")
		f.write("password="+nscaPassword+"\n")
		f.write("\n")
		f.write("# 8 = BLOWFISH\n")
		f.write("encryption_method=8\n")
		f.write("\n")
		f.write("##abyle##port=5667\n")
		f.write("##abyle##server="+nagiosServer+"\n")
		f.write("##abyle##myhostname="+myNagiosHostname+"\n")
		f.close()

		print "/etc/send_nsca.cfg created."

		sys.exit(0)

if __name__ == '__main__':
        main()
