#!/usr/bin/python
# __author__ = 'Clay'

# Description
# clayScripts.py
# Clay Michaels
# Jan, Feb 2015
# Gets data points from a vehicle or whole fleet
#
version = '1.1.2'
# Changelog
# 1.1.2
# Fixed after somehow removing the shebang line.
# 1.1.1
# Set logger to clear log file after it reaches 1mb
# 1.1
# Remove characters from argument argv after match to definitions.
# 1.0
# Grabs fleetman db credentials from config file.
# Fleet list derived from this list instead of separate config file.
# Sorts vehicle list
# 0.9.2
# Changed config file format
# 0.9.1
# Handling a new exception "Error reading SSH banner"
# 0.9
# Reads in arguments from config file!
# 0.8
# Added logging
# 0.7
# Allow single vehicle target
# 0.6
# Print man-page-ish help output
# 0.5
# reads in vehicle list from config file
#
#
# To do:
# * Implement port forwarding to portal
#       ssh -p8022 via.3451 cat /mnt/md0/ND/WowzaMediaServer/conf/Server.license
# * Store output in local db
# * might be able to swing multiple SIMS at once
#       cat file1 <(echo) file2 <(echo) file3 <(echo)


# Imported modules
import ast
import paramiko
from sys import exit, argv
import logging
from logging.handlers import RotatingFileHandler
from cStringIO import StringIO
import re
from ConfigParser import SafeConfigParser
import MySQLdb


DATAPOINTS_CONFIG_FILENAME = 'scan-fleet-datapoints.cfg'
FLEETMAN_CREDENTIALS_FILENAME = 'scan-fleet-databases.cfg'
CCU_USER = '<SNIPPED>'
SSH_KEY_NAME = '<SNIPPED>'
SSH_KEY = ('''<SNIPPED!>
        -----END DSA PRIVATE KEY-----''')


# Set up logging
LOG_FILE = 'var/log/clay/scan-fleet.log'
logging.basicConfig(
    filename=LOG_FILE,
    filemode='w',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
handler = RotatingFileHandler(LOG_FILE,maxBytes=1000000)
logger.addHandler(handler)


def get_datapoints(config_filename):
    # Read data point config file
    parser = SafeConfigParser()
    datapoints = {}
    try:
        parser.read(config_filename)
        for section_name in parser.sections():
            inner_dict = {}
            inner_dict['enabled'] = False
            inner_dict['name'] = section_name
            for name, value in parser.items(section_name):
                inner_dict[name] = value
            datapoints[section_name] = inner_dict
    except SafeConfigParser:
        logger.error('Unable to parse argument config file!')
        logger.error('Expected %s' % config_filename)
        exit()
    for option in datapoints:
        logger.debug(option)
        for key in datapoints[option]:
            logger.debug('\t%s=%s' % (key, datapoints[option][key]))
    return datapoints


def get_fleetman_credentials(config_filename):
    # Read data point config file
    parser = SafeConfigParser()
    creds = {}
    fleet_list = []
    try:
        parser.read(config_filename)
        for section_name in parser.sections():
            fleet_list.append(section_name)
            inner_dict = {}
            inner_dict['user'] = '<SNIPPED>'
            inner_dict['password'] = '<SNIPPED>'
            inner_dict['db'] = '<SNIPPED DB NAME>'
            for name, value in parser.items(section_name):
                inner_dict[name] = value
            creds[section_name] = inner_dict
    except SafeConfigParser:
        logger.error('Unable to parse fleetman config file!')
        logger.error('Expected %s' % config_filename)
        exit()
    for option in creds:
        logger.debug(option)
        for key in creds[option]:
            logger.debug('\t%s=%s' % (key, creds[option][key]))
    return creds, fleet_list


def get_fleetman_vehicle_list(credentials):
    logger.debug('Credentials: %s' % credentials)
    fm_connection = None
    try:
        fm_connection = MySQLdb.connect(
            credentials['ip'], credentials['user'],
            credentials['password'], credentials['db'])
    # except MySQLdb.OperationalError, e:
        # Example output: (2003, "Can't connect to MySQL server on '172.30.6.140' (10060)")
    except MySQLdb.Error, e:
        print(repr(e))
        if 'Access denied for user' in e[1]:
            logger.error('Unable to log in to MySQL server.')
            logger.error('Check the user name, password, and database.')
            logger.error('USER = %s' % credentials['user'])
            logger.error('PASS = %s' % credentials['password'])
            logger.error('DB   = %s' % credentials['db'])
        elif 'connect to MySQL server on' in e[1]:
            logger.error('Unable to find MySQL server. Please check the IP Address and try again.')
            logger.error('Ask your friendly neighborhood SysAdmin if a firewall rule is preventing access.')
            logger.error('IP = %s' % credentials['ip'])
        exit()
    cursor = fm_connection.cursor()
    sql_response = []
    try:
        cursor.execute(credentials['query'])
        sql_response = cursor.fetchall()
    except MySQLdb.Error, e:
        logger.error(repr(e))
        if 'column' in e[1]:
            logger.error('This Fleetman database is non-standard!')
            missing_column = re.search(r'Unknown column \'(.*)\' in \'', e[1]).group(1)
            logger.error('Unable to find column "%s".' % missing_column)
        elif 'Table' in e[1] and 'doesn\'t exist' in e[1]:
            logger.error('This Fleetman database is non-standard!')
            missing_table = re.search(r'Table \'(.*)\' doesn\'t exist', e[1]).group(1)
            logger.error('Unable to find table "%s".' % missing_table)
        else:
            logger.error('Other MySQL error!')
        exit()
    vehicle_list = []
    for vehicle in sql_response:
        vehicle_list.append(''.join(sql_response[sql_response.index(vehicle)]))
    vehicle_list.sort()
    vehicle_list_sorted = []
    for vehicle in vehicle_list:
        vehicle_list_sorted.append(vehicle.replace('TS0', '').replace('TS', ''))
    return vehicle_list_sorted


def usage(error, datapoints):
    if error:
        print('ERROR: ' + error)
        logger.error(error)
    print('\nNAME')
    print('\t' + argv[0][:argv[0].rindex('.')] + ' ' + version + ' - poll one or more CCUs for data.')
    print('\nSYNOPSIS')
    print('\t' + argv[0] + ' <Fleet> [CCU] <Options>')
    print('\nDESCRIPTION')
    print('\tPolls one or all CCUs in a fleet for between one and all available data points.')
    print('\tIf no CCU is selected, the whole fleet will be polled.')
    print('\tThe options may be entered in any order and the results will be printed to the console.')
    print('\n\tSupported options:')
    print('\t\tARGUMENT\tDEFINITION')
    print('\t\t--------------------------')
    for arg_section in sorted(datapoints):
        print('\t\t' + datapoints[arg_section]['arg'] + '\t:\t' + datapoints[arg_section]['name'])
    print('\nEXAMPLES')
    print('\t' + argv[0] + ' acela -pfm2')
    print('\tOutput for each vehicle in Acela:')
    print('\t1')
    print('\tPROJECT.conf version : 2.4.1')
    print('\tFirmware release : 4.19.3-1')
    print('\tWAN2 IMEI : 012773002012399')
    print('\n\t' + argv[0] + ' amfleet 9646 -P')
    print('\tOutput for Amfleet.9646:')
    print('\t9646')
    print('\tPROJECT.conf MD5sum : 8a13438ddb12192293e85449da58ecad\n')
    exit()


def get_arguments(fleet_list, credential_list, datapoint_list):
    """Updates list of argument flags and returns list of vehicle(s) in fleet"""
    fleet = None
    list_of_vehicles = []
    logger.debug('Reading in %d arguments' % len(argv))
    logger.debug('Args: %s' % argv)
    if len(argv) not in [3, 4]:
        usage('Incorrect number of arguments!', datapoint_list)
    else:
        fleet = argv[1]
        logger.debug('Fleet = %s' % argv[1])
        if fleet.lower()  == 'uta':
            list_of_vehicles = ['101', '102', '103', '104', '105', '106', '107', '108', '109', '110', '111', '112', '113', '114', '115', '116', '117', '118', '119', '120', '121', '122' ]
            if len(argv) is 4:
                if argv[2] in list_of_vehicles:
                    list_of_vehicles = [argv[2]]
        elif fleet in fleet_list:
            list_of_vehicles = get_fleetman_vehicle_list(credential_list[fleet])
            logger.debug('List of vehicles in fleet: %s' % list_of_vehicles)
            logger.info('Fleet %s contains %d vehicles' % (fleet, len(list_of_vehicles)))
            logger.debug('list_of_vehicles: %s' % list_of_vehicles)
            if len(argv) is 4:
                if argv[2] in list_of_vehicles:
                    list_of_vehicles = [argv[2]]
                else:
                    usage('Target CCU not found in fleet config file for fleet %s!' % fleet, datapoint_list)
        else:
            usage('Fleet %s not found in fleet list!' % fleet, datapoint_list)
        if argv[-1][0] is '-':
            arguments = argv[-1][1:]
            logger.debug('Args input: %s' % arguments)
            for option in datapoint_list:
                if datapoint_list[option]['arg'] in arguments:
                    logger.debug('%s set to True' % option)
                    datapoint_list[option]['enabled'] = True
                    arguments = arguments[:arguments.index(datapoint_list[option]['arg'])]+arguments[arguments.index(datapoint_list[option]['arg'])+1:]
        else:
            usage('Last argument must start with "-" and contain valid args!', datapoint_list)
    return datapoint_list, list_of_vehicles, fleet


class Connection:
    def __init__(self, target):
        """Connect to CCU and iterate through enabled flags"""
        self.target = target
        self.ccu = paramiko.SSHClient()
        self.key = paramiko.DSSKey.from_private_key(StringIO(SSH_KEY))
        self.ccu.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            logger.info('Creating SSH connection to CCU %s' % self.target)
            self.ccu.connect(self.target, username=CCU_USER, pkey=self.key, timeout=10)
            logger.info('SSH connection successful')
            self.online = True
        except paramiko.BadAuthenticationType:
            logger.error('Error: Bad SSH password or wrong key type.')
            logger.error('Attempted to log in as %s with key %s' % (CCU_USER, SSH_KEY_NAME))
            self.online = False
        except paramiko.SSHException:
            logger.error('SSH Error')
            self.online = False
        except KeyboardInterrupt:
            logger.info('Keyboard interrupt received!')
            exit()
        except:
            logger.info('CCU %s offline' % self.target)
            self.online = False

    def execute_command(self, command):
        """Executes the command. Can be run multiple times."""
        logger.debug('Sending command %s' % command)
        try:
            stdin, stdout, stderr = self.ccu.exec_command(command)
            cmd_out = stdout.read()
            logger.debug('Received %s' % cmd_out)
            return cmd_out
        except KeyboardInterrupt:
            logger.info('Keyboard interrupt received!')
            exit()

    def disconnect(self):
        """Close the Paramiko connection"""
        logger.debug('Closing SSH session')
        self.ccu.close()
        logger.info('SSH session closed')


def main():
    datapoints = get_datapoints(DATAPOINTS_CONFIG_FILENAME)
    fleetman_creds, fleets = get_fleetman_credentials(FLEETMAN_CREDENTIALS_FILENAME)
    datapoints_updated, vehicle_list, fleet_name,  = get_arguments(fleets, fleetman_creds, datapoints)
    try:
        for vehicle in vehicle_list:
            print(fleet_name + ' ' + vehicle)
            con = Connection(fleet_name + '.' + vehicle)
            if con.online:
                for section in sorted(datapoints.keys()):
                    logger.debug('Arg: %s = %s' % (datapoints[section]['name'],
                                                   datapoints[section]['enabled']))
                    if datapoints[section]['enabled'] is True:
                        response = con.execute_command(datapoints[section]['command'])
                        logger.debug('Response: %s' % response)
                        logger.debug('Regex pattern is %s' % datapoints[section]['pattern'])
                        response = re.search(datapoints[section]['pattern'], response)
                        if 'pattern' in datapoints[section]['type']:
                            logger.debug('Option is of pattern-matched type')
                            if response:
                                print datapoints[section]['name'], ':', response.group()
                                logger.info('Pattern-matched response is %s' % response.group())
                            else:
                                logger.info('No valid response received')
                        elif 'boolean' in datapoints[section]['type']:
                            logger.debug('Option is of boolean type')
                            if response:
                                boolean = 'True'
                            else:
                                boolean = 'False'
                            print datapoints[section]['name'], ':', boolean
                            logger.info('Boolean-matched response is %s' % boolean)
                con.disconnect()
    except KeyboardInterrupt:
        logger.info('Keyboard interrupt received!')
        exit()


main()
