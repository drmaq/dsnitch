#!/usr/bin/env python3
"""
Name: Tcpdump-db
Creator: Shemaiah Telemaque
Email: shemaiah@telemaque.net
Decsribtion: The program execute tcpdump then captures the output and stores the mac addresses of rouge devices in a mysql database.

"""

import configparser as cg
import logging as logger
import sys
from multiprocessing import Process, Pipe
from subprocess import Popen, PIPE, STDOUT

import MySQLdb as sql

# Logging Config settings
logger.basicConfig(level=logger.DEBUG,
				format='[%(asctime)s] [%(levelname)-8s] [%(message)s]',
				datefmt='%a %d %b %Y] [%H:%M:%S',
				filename='dsnitch.log',
				filemode='a')

#logger = log.getLogger(__name__)

# DEFINE CONFIG VARIABLES
config = cg.RawConfigParser()
config.read('config.cfg')
config.sections()

# Configure Database
host = config.get('DataBase', 'db_host')
user = config.get('DataBase', 'db_user')
password = config.get('DataBase', 'db_password')
db = config.get('DataBase', 'db')


class ExternalProcess(Process):
	def __init__(self, command, pipe):
		super(ExternalProcess, self).__init__()
		self.command = command
		self.pipe = pipe

	def run(self):
		with Popen(self.command, stdout=PIPE, stderr=STDOUT, shell=True, universal_newlines=True) as process:
			for line in process.stdout:
				self.pipe.send(line)


def tcpdump():
	logger.info("================START OF LOG=================")
	conn = sql.connect(host, user, password, db)
	logger.info(conn)
	c = conn.cursor()
	logger.info(c)
	try:	
		c.execute(
			'''CREATE TABLE IF NOT EXISTS DSNITCH(
		ID  INTEGER PRIMARY KEY AUTO_INCREMENT NOT NULL,
		source_mac  CHAR(24) NOT NULL,
		destination_mac CHAR(24) NOT NULL,
		timestamp DATETIME NOT NULL
		)''')
		logger.info(c)
		#logger.debug("DATABASE: Table Created successfully")
		conn.commit()
		logger.info(conn)
	except sql.OperationalError as e:
		raise e
		logger.debug(e)
	except sql.Warning as e:
		raise e
		logger.debug(e)
	except sql.InterfaceError as e:
		raise e
		logger.debug(e)
	except sql.DatabaseError as e:
		raise e
		logger.debug(e)
	except sql.DataError as e:
		raise e
		logger.debug(e)
	except sql.IntegrityError as e:
		raise e
		logger.debug(e)
	except sql.InternalError as e:
		raise e
		logger.debug(e)
	except sql.ProgrammingError as e:
		raise e
		logger.debug(e)
	except sql.NotSupportedError as e:
		raise e 
		logger.debug(e)
	logger.info(conn)

	tcpdump_cmd = ['tcpdump -tttt -en -l -i ens192 "src port 67 and net not 143.207.0.0/16"']
	print(tcpdump_cmd)
	logger.info(tcpdump_cmd)
	tcpdump_send_con, tcpdump_recv_con = Pipe()
	tcpdump_process = ExternalProcess(tcpdump_cmd, tcpdump_send_con)
	logger.debug(tcpdump_process)
	tcpdump_process.start()
	#output = tcpdump_recv_con()
	while True:
		try:
			output = tcpdump_recv_con.recv()
			logger.debug(output)
			output_split = output.rsplit(',')
			logger.debug(output_split)
			#print(output_split)
			for i in range(6):
				if len(output_split) == 5: 

					[data, ether_type, ip_info, reply, length] = output_split
					logger.info("RAW OUTPUT:\t{}{}{}{}{}".format(data, ether_type, ip_info, reply, length))

					[date, time, Source_Mac, to, Destination_Mac] = data.rsplit(' ')

					sourceMac = Source_Mac.replace(':', '')
					logger.info("Source Mac Address:\t{}".format(sourceMac))

					destinationMac = Destination_Mac.replace(':', '')
					logger.info("Destination Mac Address:\t{}".format(destinationMac))

#	                print('TCPDUMP DHCP OFFENDERS: ', date, time, Source_Mac, Destination_Mac)
					logger.info("TCPDUMP DHCP OFFENDERS:\t{}".format(Source_Mac))

					insert_q = "INSERT INTO BAD_MAC2 (source_mac,destination_mac,timestamp) VALUES('%s','%s',NOW())" % (
					sourceMac, destinationMac)

					c.execute(insert_q)
					#logger.info(c.execute(insert_q))
					logger.debug("Database:\t{}\t{}".format(sourceMac, destinationMac))

					conn.commit()
					#logger.info(conn.commit())
		except KeyboardInterrupt:
			tcpdump_process.terminate()
			logger.error(tcpdump_process,exc_info=True)
			conn.close()
			logger.error(conn)
			sys.exit(0)
		'''finally:
			logger.info("User Terminated program")
			logger.info("================END OF LOG=================")'''


def tshark():
	tshark_cmd = ['tshark', '-ni', 'eno16777736', '-Y', 'bootp.option.type == 53']
	tshark_send_con, tshark_recv_con = Pipe()
	tshark_process = ExternalProcess(tshark_cmd, tshark_send_con)
	tshark_process.start()
	while True:
		try:
			print('tshark output:', tshark_recv_con.recv())
		except KeyboardInterrupt:
			tshark_process.terminate()
			sys.exit(0)


tcpdump()
	
