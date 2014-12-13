#!/usr/bin/python2
#
#    mitmprotector.py - protect's you from any kind of MITM-attacks.
#
#    Copyright (C) 2014 by Jan Helbling <jan.helbling@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from os import popen,getuid,path,fork,mkdir,execvp,waitpid,WEXITSTATUS,unlink,chmod

from sys import exit,argv,stdout

from time import sleep

from logging import info,warning,critical,basicConfig,DEBUG
from re import findall,compile
import ConfigParser
from struct import pack
from socket import inet_ntoa
from uuid import getnode
from signal import signal,SIGTERM
from optparse import OptionParser
import daemon,daemon.pidlockfile


ip_regex 	= compile('\d+\.\d+\.\d+\.\d+')
mac_regex	= compile('[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+')

config_path	= '/etc/mitmprotector.cfg'

log_path	= '/var/log/mitmprotector.log'

pid_file	= '/var/run/mitmprotector.pid'

class mitm_protect:
	def __init__(self):
		basicConfig(filename=log_path,filemode='a',level=DEBUG,format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%d.%m.%Y - %H:%M:%S')
		info('mitmprotector started!')
		self.devices	=	[]
		self.counter	=	0
		signal(SIGTERM, self.__sigterm_handler)
		try:
			self.__run()
		except KeyboardInterrupt:
			info('delete Firewall')
			print('exit mitmprotector')
			print('delete arptables-firewall')
			self.__remove_firewall()
		info('mitmprotector ended!')
		return
	
	def __sigterm_handler(self,a,b):
		self.__remove_firewall()
		daemon.pidlockfile.remove_existing_pidfile(pid_file)
		exit(0)
	
	def __get_hw_addr(self):
		return ':'.join(findall('..', '%012x' % getnode()))
	
	def __read_config(self):
		print('loading configuration oddments =)')
		config		=	ConfigParser.RawConfigParser()
		if not path.exists(config_path):
			info('Creating new configfile {}'.format(config_path))
			config.add_section('attack')
			config.set('attack','exec','/usr/bin/notify-send "MITM-Attack" "from IP: {0}  MAC: {1}" -u critical -t 3000 -c "Security"')
			config.set('attack','interfaces','wlan0')
			config.set('attack','put-interfaces-down','1')
			config.set('attack','shutdown-interface-command','ifconfig {0} down')
			config.add_section('arp-scanner')
			config.set('arp-scanner','timeout','5')
			config.set('arp-scanner','command','arp -an')
			with open(config_path,'w') as configfile:
				config.write(configfile)
			configfile.close()
			if argv[2] == '-C':
				print('First execution: Created {}!'.format(config_path))
				print('You need to edit it before you run {}!'.format(argv[0]))
				exit(0)
		info('Reading configfile {}'.format(config_path))
		config.read(config_path)
		self.exec_cmd		=	config.get('attack','exec')
		self.interfaces		=	config.get('attack','interfaces')
		self.putinterfacesdown	=	bool(	config.get('attack','put-interfaces-down'))
		self.shutdown_iface_cmd	=		config.get('attack','shutdown-interface-command')
		self.scan_timeout	=	float(	config.get('arp-scanner','timeout'))
		self.arp_command	=		config.get('arp-scanner','command')
	
	def __arptable_firewall(self):
		self.routerip		=	self.__getrouterip()
		if popen('arptables --help 2>/dev/null').read() == '':
			print('arptables not found!!! Could not create a firewall!!!')
			critical('arptables not found!!! Could not create a firewall!!!')
			return
		info('creating a firewall with arptables and arp!')
		print('creating a firewall with arptables and arp!')
		self.iface		=	self.interfaces.split(',')[0]
		print('Interface: {0}\nRouter-IP: {1}'.format(self.iface,self.routerip))
		self.fd			=	popen('arp-scan -I {0} {1} | grep {1}'.format(self.iface,self.routerip),'r')
		try:
			self.mac		=	mac_regex.findall(self.fd.read())[0]
			print('Router-MAC: {}'.format(self.mac))
		except IndexError:
			sleep(1)
			self.fd.close()
			self.fd			=	popen('arp-scan -I {0} {1} | grep {1}'.format(self.iface,self.routerip),'r')
			self.mac		=	mac_regex.findall(self.fd.read())[0]
			print('Router-MAC: {}'.format(self.mac))
		self.fd.close()
		self.fd			=	popen('arptables --zero && arptables -P INPUT DROP && arptables -P OUTPUT DROP && arptables -A INPUT -s {0} --source-mac {1} -j ACCEPT && arptables -A OUTPUT -d {0} --destination-mac {1} -j ACCEPT && arp -s {0} {1}'.format(self.routerip,self.mac), 'r')
		self.fd.read()
		self.fd.close()
		self.fd			=	popen('arptables --list','r')
		self.lst		=	self.fd.read()
		self.fd.close()
		print('arptables --list:\n{}'.format(self.lst))
	
	def __remove_firewall(self):
		info('Shutting down mitmprotector. remove arptables firewall...')
		popen('arptables --zero && arptables --flush').read()
	
	def __run(self):
		self.__read_config()
		self.__arptable_firewall()
		info('starting endless loop')
		while True:
			self.counter = self.counter + 1
			self.__arp()
			self.__check()
			if self.attacker != ():
				print('ALARM! arppoisoning detected!!!')
				print('Exexute predefined command: \'{}\'!'.format(self.cmd.format(self.attacker[0],self.attacker[1])))
				warning('ALARM! arppoisoning detected!!!')
				if not fork():
					popen(self.exec_cmd.format(self.attacker[0],self.attacker[1]),'r').read()
					if self.putinterfacesdown:
						print('Shut down the networkinterfaces: {}'.format(self.interfaces))
						critical('Shut down the networkinterfaces: {}'.format(self.interfaces))
						for interface in self.interfaces.split(','):
							popen(self.shutdown_iface_cmd.format(interface),'r').read()
							print('{}: turned off!'.format(interface))
							critical('{}: turned off!'.format(interface))
					exit(0)
			print('[{0}] sleeping {1} seconds until the next check.'.format(self.counter,self.scan_timeout))
			sleep(self.scan_timeout)
	
	def __arp(self):
		self.fd		=	popen(self.arp_command,'r')
		self.lines	=	(self.fd.read()).split('\n')
		self.fd.close()
		print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>ARP-LIST START<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
		for line in self.lines:
			if line == '':
				break
			try:
				ip	=	ip_regex.findall(line)[0]
				mac	=	mac_regex.findall(line)[0]
				print('>>> IP: {0}  MAC: {1}'.format(ip,mac))
				self.devices.append((ip,mac))
			except IndexError:
				pass
		print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>ARP-LIST END<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n')

	def __check(self):
		self.attacker	=	()
		for device in self.devices:
			for _device in self.devices:
				if device[0] != _device[0] and device[0] != self.routerip:
					if device[1] == _device[1]:
						self.attacker	=	device
						critical('MITM ATTACK DETECTED!!! IP: {0} , MAC: {1}'.format(self.attacker[0],self.attacker[1]))
						print('MITM ATTACK DETECTED!!! IP: {0} , MAC: {1}'.format(self.attacker[0],self.attacker[1]))
						return self.attacker
		self.devices = []
					
	
	def __getrouterip(self):
		try:
			with open('/proc/net/route') as fh:
				for line in fh:
					fields = line.strip().split()
					if fields[1] != '00000000' or not int(fields[3], 16) & 2:
						continue
					return inet_ntoa(pack('<L', int(fields[2], 16)))
		except IOError:
			critical('Error: File /proc/net/route not found!')
			print('Error: File /proc/net/route not found!')
			exit(1)
	
if __name__ == '__main__':
	if getuid() != 0:
		print('Must be run as root (uid=0)!')
		exit(1)
	
	parser	=	OptionParser()
	parser.add_option('-d','--daemon',dest='daemon',action='store_true',default=False,help='Run mitmprotector as a daemon.')
	parser.add_option('-f','--foreground',dest='nodaemon',action='store_true',default=True,help='Run mitmprotector in foreground.')
	parser.add_option('-n','--nm-aoc',dest='nmaoc',action='store_true',default=False,help='Enable  Autostart/stop -scripts on /etc/network/if-post-down.d/ and /etc/network/if-up.d/')
	parser.add_option('-r','--rm-aoc',dest='rmaoc',action='store_true',default=False,help='Disable the Autostart/stop scripts'
)
	
	(options, args) = parser.parse_args()
	
	if not path.exists(config_path):
		argv = ['mitmprotector.py','-F','-C']
	
	if popen('arp-scan 2>/dev/null').read() == '':
		print('You must install arp-scan to use this tool!')
		print('Ubuntu:    sudo apt-get install arp-scan')
		print('ArchLinux: sudo pacman -S arp-scan')
		print('Fedora:    sudo yum install arp-scan')
		exit(1)
	if options.nmaoc:
		mitmprotector_down		=	open('/etc/network/if-post-down.d/mitmprotector','w')
		mitmprotector_up		=	open('/etc/network/if-up.d/mitmprotector','w')
		mitmprotector_down.write('#!/bin/bash\npkill -TERM -F /var/run/mitmprotector.pid')
		mitmprotector_up.write('#!/bin/bash\nmitmprotector.py -D')
		mitmprotector_down.close()
		mitmprotector_up.close()
		chmod('/etc/network/if-post-down.d/mitmprotector',0755)
		chmod('/etc/network/if-up.d/mitmprotector',0755)
		popen('/etc/init.d/networking reload').read()
		print('Done! Scripts added. to remove the scripts: mitmprotector.py --rm-aoc')
		exit(0)
	elif options.rmaoc:
		unlink('/etc/network/if-post-down.d/mitmprotector')
		unlink('/etc/network/if-up.d/mitmprotector')
		print('Done! Scripts removed!')
		exit(0)
	try:
		pid	=	open(pid_file,'r').read().rstrip('\n')
		print('mitmprotector is already running! {}: {}'.format(pid_file,pid))
		exit(1)
	except IOError:
		pass
	if options.nodaemon and not options.daemon:
		x = mitm_protect()
		exit(0)
	elif options.daemon:
		with daemon.DaemonContext():
			daemon.pidlockfile.write_pid_to_pidfile(pid_file)
			x = mitm_protect()
