#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
#    mitmprotector.py - protect's you from any kind of MITM-attacks.
#
#    Copyright (C) 2018 by Jan Helbling <jan.helbling@gmail.com>
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

from os import popen,getuid,path,fork,execvp,waitpid,unlink,chmod,getpid
from sys import exit
from time import sleep
from logging import info,warning,critical,basicConfig,DEBUG
from re import findall,compile
from struct import pack
from socket import inet_ntoa
from uuid import getnode
from signal import signal,SIGTERM
from optparse import OptionParser
try:
	import daemon,daemon.pidfile
except ImportError:
	print "You must install python(2)-daemon to run this programm!"
	exit(1)
import ConfigParser

ip_regex 	= compile('\d+\.\d+\.\d+\.\d+')
mac_regex	= compile('[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+')

config_path	= '/etc/mitmprotector.conf'
log_path	= '/var/log/mitmprotector.log'
pid_file	= '/var/run/mitmprotector.pid'

prog_name	= 'mitmprotector.py'
version		= '25'

pf		= daemon.pidfile.PIDLockFile(pid_file)

class mitm_protect:
	global pf
	def __init__(self):
		basicConfig(filename=log_path,filemode='a',level=DEBUG,format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%d.%m.%Y - %H:%M:%S')
		info('=> mitmprotector started!')
		print('=> mitmprotector started!')
		self.devices	=	[]
		self.counter	=	0
		signal(SIGTERM, self.__sigterm_handler)
		try:
			self.__run()
		except KeyboardInterrupt:
			if pf.is_locked():
				pf.release()
			self.__remove_firewall()
		info('=> mitmprotector ended!')
		print('=> mitmprotector ended!')
	
	def __sigterm_handler(self,a,b):
		self.__remove_firewall()
		if pf.is_locked():
			pf.release()
		exit(0)
	
	def __get_hw_addr(self):
		return ':'.join(findall('..', '%012x' % getnode()))
	
	def __read_config(self):
		print('Loading configuration oddments =)')
		config		=	ConfigParser.RawConfigParser()
		if not path.exists(config_path):
			info('Creating new configfile: {}.'.format(config_path))
			print('Creating new configfile: {}.'.format(config_path))
			config.add_section('attack')
			config.set('attack','exec','/usr/bin/notify-send "MITM-Attack" "from IP: {0}  MAC: {1}" -u critical -t 3000 -c "Security"')
			config.set('attack','interface','wlan0')
			config.set('attack','put-interface-down','1')
			config.set('attack','shutdown-interface-command','ifconfig {0} down')
			config.add_section('arp-scanner')
			config.set('arp-scanner','timeout','5')
			config.set('arp-scanner','command','arp -an')
			with open(config_path,'w') as configfile:
				config.write(configfile)
			configfile.close()
			print('==> First execution <==')
			print('Created configurationfile {}!'.format(config_path))
			print('You need to edit it before run {}!'.format(prog_name))
			exit(0)
		info('Reading configfile {}.'.format(config_path))
		if config.read(config_path) != [config_path]:
			critical('Could not read config {}!'.format(config_path))
			critical('Shutting down mitmprotector.')
			print('Could not read config {}!'.format(config_path))
			print('Shutting down mitmprotector.')
			if pf.is_locked():
				pf.release()
			exit(1)
		try:
			self.exec_cmd		=	config.get('attack','exec')
			self.interface		=	config.get('attack','interface')
			self.putinterfacedown	=	bool(	config.get('attack','put-interface-down'))
			self.shutdown_iface_cmd	=		config.get('attack','shutdown-interface-command')
			self.scan_timeout	=	float(	config.get('arp-scanner','timeout'))
			self.arp_command	=		config.get('arp-scanner','command')
		except ConfigParser.NoSectionError, e:
			critical('Could not read config {}: {}.'.format(config_path,e))
			critical('Shutting down mitmprotector.')
			print('Could not read config {}: {}.'.format(config_path,e))
			print('Shutting down mitmprotector.')
			if pf.is_locked():
				pf.release()
			exit(1)
		except ConfigParser.NoOptionError, e:
			critical('Could not read config {}: {}.'.format(config_path,e.message))
			critical('Shutting down mitmprotector.')
			print('Could not read config {}: {}.'.format(config_path,e.message))
			print('Shutting down mitmprotector.')
			if pf.is_locked():
	                        pf.release()
			exit(1)
		except ValueError, e:
			critical('Could not read floatvalue [arp-scanner]->timeout: {}'.format(e.message))
			critical('Shutting down mitmprotector.')
			print('Could not read floatvalue [arp-scanner]->timeout: {}'.format(e.message))
			print('Shutting down mitmprotector.')
			if pf.is_locked():
				pf.release()
			exit(1)
	
	def __arptable_firewall(self):
		self.routerip		=	self.__getrouterip()
		if popen('arptables --help 2>/dev/null').read() == '':
			print('Command "arptables" not found!!! Could not create a firewall!!!')
			critical('Command "arptables" not found!!! Could not create a firewall!!!')
			return
		info('Creating a firewall with arptables and arp!')
		print('creating a firewall with arptables and arp!')
		print('Interface: {0}\nRouter-IP: {1}'.format(self.interface,self.routerip))
		self.data			=	popen('arp-scan -I {0} {1} | grep {1}'.format(self.interface,self.routerip),'r').read()
		try:
			self.mac		=	mac_regex.findall(self.data)[0]
			print('Router-MAC: {}'.format(self.mac))
		except IndexError:
			sleep(2)
			self.data		=	popen('arp-scan -I {0} {1} | grep {1}'.format(self.interface,self.routerip),'r').read()
			try:
				self.mac		=	mac_regex.findall(self.data)[0]
			except IndexError:
				critical('Could not find the MAC of {}'.format(self.routerip))
				critical('Shutting down mitmprotector.')
				print('Could not find the MAC of {}'.format(self.routerip))
				print('Shutting down mitmprotector.')
				if pf.is_locked():
					pf.release()
				exit(1)
			print('Router-MAC: {}'.format(self.mac))
		popen('arptables --zero && arptables -P INPUT DROP && arptables -P OUTPUT DROP && arptables -A INPUT -s {0} --source-mac {1} -j ACCEPT && arptables -A OUTPUT -d {0} --destination-mac {1} -j ACCEPT && arp -s {0} {1}'.format(self.routerip,self.mac), 'r')
		print('arptables --list:\n{}'.format(popen('arptables --list','r').read().rstrip('\n')))
	
	def __remove_firewall(self):
		info('Shutting down mitmprotector. Removing arptables firewall...')
		popen('arptables --zero && arptables --flush')
	
	def __run(self):
		self.__read_config()
		self.__arptable_firewall()
		info('Starting endless loop.')
		while True:
			self.counter = self.counter + 1
			self.__arp()
			self.__check()
			if self.attacker != ():
				print('ALARM! arppoisoning detected!!!')
				print('Exexute predefined command: \'{}\'!'.format(self.cmd.format(self.attacker[0],self.attacker[1])))
				critical('ALARM! arppoisoning detected!!!')
				critical('Exexute predefined command: \'{}\'!'.format(self.cmd.format(self.attacker[0],self.attacker[1])))
				self.pid = fork()
				if not self.pid:
					popen(self.exec_cmd.format(self.attacker[0],self.attacker[1]),'r')
					if self.putinterfacedown:
						print('Shut down the networkinterface {}!'.format(self.interface))
						critical('Shut down the networkinterface {}!'.format(self.interface))
						popen(self.shutdown_iface_cmd.format(self.interface),'r')
						print('{}: turned off!'.format(self.interface))
						critical('{}: turned off!'.format(self.interface))
					exit(0)
				wait()
				if self.putinterfacedown:
					info('Disconnected from Network!')
					print('Disconnected from Network!')
					self.__remove_firewall()
					if pf.is_locked():
						pf.release()
					exit(0)
			print('[{0}] Sleeping {1} seconds until the next check.'.format(self.counter,self.scan_timeout))
			sleep(self.scan_timeout)
	
	def __arp(self):
		self.fd		=	popen(self.arp_command,'r')
		self.lines	=	(self.fd.read()).split('\n')
		self.fd.close()
		print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>  ARP-LIST START  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
		for line in self.lines:
			if line == '':
				break
			try:
				ip	=	ip_regex.findall(line)[0]
				mac	=	mac_regex.findall(line)[0]
				print('>>> IP: {0}  MAC: {1}'.format(ip,mac))
				self.devices.append((ip,mac))
			except IndexError:
				print('IndexError: Failed to regex a line from "arp -an" => IP & MAC')
				print('The line: "{}".'.format(line.rstrip('\n')))
		print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>  ARP-LIST END    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n')

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
		if path.exists('/proc/net/route'):
			try:
				with open('/proc/net/route') as fh:
					for line in fh:
						fields = line.strip().split()
						if fields[1] != '00000000' or not int(fields[3], 16) & 2:
							continue
						return inet_ntoa(pack('<L', int(fields[2], 16)))
			except OSError, e:
				critical('Error: Couldn\'t open "/proc/net/route": {}.'.format(e.strerror))
				info('Trying 4 alternate methods to get the RouterIP.')
				print('Error: Couldn\'t open "/proc/net/route": {}.'.format(e.strerror))
				print('Trying 4 alternate methods to get the RouterIP.')
		else:
			info('File "/proc/net/route" doesn\'t exists! Trying 4 alternate methods to get the RouterIP.')
			print('File "/proc/net/route" doesn\'t exists! Trying 4 alternate methods to get the RouterIP.')
		try:
			info('=> Method 2: route -n')
			print('=> Method 2: route -n')
			return findall('\d+\.\d+\.\d+\.\d+',popen('route -n').read().split("\n")[2])[1]
		except IndexError:
			try:
				info('=> Method 3: ifconfig {} | grep inet'.format(self.interface))
				print('=> Method 3: ifconfig {} | grep inet'.format(self.interface))
				return findall('\d+\.\d+\.\d+\.\d+',popen('ifconfig {} | grep inet\ '.format(self.interface)).read())[0].rstrip('1234567890') + '1'
			except IndexError:
				info('=> Method 4: Guessing (ping -c 1 -W 1 -I {} 192.168.0.1/192.168.1.1/192.168.8.1)'.format(self.interface))
				print('=> Method 4: Guessing (ping -c 1 -W 1 -I {} 192.168.0.1/192.168.1.1/192.168.2.1)'.format(self.interface))
				if popen('ping -W 1 -I {} 192.168.0.1 -c 1 | grep -E "1 received"'.format(self.interface)).read() != '':
					return '192.168.0.1'
				elif popen('ping -W 1 -I {} 192.168.1.1 -c 1 | grep -E "1 received"'.format(self.interface)).read() != '':
					return '192.168.1.1'
				elif popen('ping -W 1 -I {} 192.168.2.1 -c 1 | grep -E "1 received"'.format(self.interface)).read() != '':
					return '192.168.2.1'
				else:
					critical('Failed to get RouterIP!')
					critical('Shutting down mitmprotector.')
					print('Failed to get RouterIP!')
					print('Shutting down mitmprotector.')
					if pf.is_locked():
						pf.release()
					exit(1)

if __name__ == '__main__':
	if getuid() != 0:
		print('{} must be run as root (uid == 0)!'.format(prog_name))
		exit(1)
	
	parser	=	OptionParser(version='%prog version {}\nCopyright (C) 2014 by Jan Helbling <jan.helbling@gmail.com>\nLicense: GPL3+\nlp:~jan-helbling/+junk/mitmprotector\nhttps://github.com/JanHelbling/mitmprotector.git'.format(version))
	parser.add_option('-d','--daemon',dest='daemon',action='store_true',default=False,help='Run mitmprotector as a daemon.')
	parser.add_option('-f','--foreground',dest='nodaemon',action='store_true',default=True,help='Run mitmprotector in foreground.')
	parser.add_option('-k','--kill',dest='kill',action='store_true',default=False,help='Kill mitmprotector with a SIGTERM!')
	parser.add_option('-n','--nm-aoc',dest='nmaoc',action='store_true',default=False,help='Enable  NetworkManager/WICD -autostartscripts')
	parser.add_option('-r','--rm-aoc',dest='rmaoc',action='store_true',default=False,help='Disable NetworkManager/WICD -autostartscripts')
	
	(options, args) = parser.parse_args()
	
	if not path.exists(config_path):
		options.daemon		=	False
		options.nodaemon	=	True
	
	if popen('arp-scan --help 2>&1 | grep 0x0800').read() == '':
		print('You must install arp-scan to use this tool!')
		print('Ubuntu:    sudo apt-get install arp-scan')
		print('ArchLinux: sudo pacman -S arp-scan')
		print('Fedora:    sudo yum install arp-scan')
		exit(1)
	if options.kill:
		print('[EXEC] pkill -TERM mitmprotector.p')
		popen('pkill -TERM mitmprotector.p 2>/dev/null')
	if options.nmaoc:
		if path.exists('/etc/network/if-post-down.d/') and path.exists('/etc/network/if-up.d/'):
			if path.exists('/etc/network/if-post-down.d/mitmprotector') and path.exists('/etc/network/if-up.d/mitmprotector'):
				print('[NetworkManager] Scripts already installed!')
			else:
				print('[NetworkManager] Found! Installing scripts.')
				try:
					mitmprotector_down		=	open('/etc/network/if-post-down.d/mitmprotector','w')
					mitmprotector_up		=	open('/etc/network/if-up.d/mitmprotector','w')
					mitmprotector_down.write('#!/bin/bash\npkill -TERM -F /var/run/mitmprotector.pid')
					mitmprotector_up.write('#!/bin/bash\n{} -d'.format(prog_name))
					mitmprotector_down.close()
					mitmprotector_up.close()
				except OSError, e:
					print('[NetworkManager] Failed to create {}: {}.'.format(e.filename,e.strerror))
					exit(1)
				try:
					chmod('/etc/network/if-post-down.d/mitmprotector',0755)
					chmod('/etc/network/if-up.d/mitmprotector',0755)
				except OSError, e:
					print('[NetworkManager] Failed to chmod->755 {}: {}.'.format(e.filename,e.strerror))
					print('    You must manual chmod 755 these files:')
					print('    /etc/network/if-post-down.d/mitmprotector')
					print('    /etc/network/if-up.d/mitmprotector')
					exit(1)
				print('[NetworkManager] Created /etc/network/if-post-down.d/mitmprotector and /etc/network/if-up.d/mitmprotector => 755')
				print('[NetworkManager] execute /etc/init.d/networking reload...')
				popen('/etc/init.d/networking reload 2>/dev/null')
		else:
			print('[NetworkManager] Not found!')
		if path.exists('/etc/wicd/scripts/postconnect/') and path.exists('/etc/wicd/scripts/predisconnect/'):
			if path.exists('/etc/wicd/scripts/predisconnect/mitmprotector') and path.exists('/etc/wicd/scripts/postconnect/mitmprotector'):
				print('[WICD] Scripts already installed!')
			else:
				print('[WICD] Found! Installing scripts.')
				try:
					mitmprotector_down		=	open('/etc/wicd/scripts/predisconnect/mitmprotector','w')
					mitmprotector_up		=	open('/etc/wicd/scripts/postconnect/mitmprotector','w')
					mitmprotector_down.write('#!/bin/bash\npkill -TERM -F /var/run/mitmprotector.pid')
					mitmprotector_up.write('#!/bin/bash\n{} -d'.format(prog_name))
					mitmprotector_down.close()
					mitmprotector_up.close()
				except OSError, e:
					print('[WICD] Failed to create {}: {}.'.format(e.filename,e.strerror))
					exit(1)
				try:
					chmod('/etc/wicd/scripts/predisconnect/mitmprotector',0755)
					chmod('/etc/wicd/scripts/postconnect/mitmprotector',0755)
				except OSError, e:
					print('[WICD] Failed to chmod->755 {}: {}.'.format(e.filename,e.strerror))
					print('    You must manual chmod 755 these files:')
					print('    /etc/wicd/scripts/predisconnect/mitmprotector')
					print('    /etc/wicd/scripts/postconnect/mitmprotector')
					exit(1)
				print('[WICD] Created /etc/wicd/scripts/predisconnect/mitmprotector and /etc/wicd/scripts/postconnect/mitmprotector => 755')
				print('[WICD] execute /etc/init.d/wicd force-reload...')
				popen('/etc/init.d/wicd force-reload 2>/dev/null')
		else:
			print('[WICD] Not found!')
		print('[+++] Done! Scripts added!')
		exit(0)
	elif options.rmaoc:
		if path.exists('/etc/network/if-post-down.d/mitmprotector') and path.exists('/etc/network/if-up.d/mitmprotector'):
			print('[NetworkManager] Found! Removing scripts.')
			try:
				unlink('/etc/network/if-post-down.d/mitmprotector')
				unlink('/etc/network/if-up.d/mitmprotector')
			except OSError, e:
				print('Error: Couldn\'t remove {}: {}.'.format(e.filename,e.strerror))
				exit(1)
		if path.exists('/etc/wicd/scripts/predisconnect/mitmprotector') and path.exists('/etc/wicd/scripts/postconnect/mitmprotector'):
			print('[WICD] Found! Removing scripts.')
			try:
				unlink('/etc/wicd/scripts/predisconnect/mitmprotector')
				unlink('/etc/wicd/scripts/postconnect/mitmprotector')
			except OSError, e:
				print('Error: Couldn\'t remove {}: {}.'.format(e.filename,e.strerror))
				exit(1)
		print('[+++] Done! Scripts removed!')
		exit(0)
	else:
		if not pf.read_pid():
			if options.nodaemon and not options.daemon:
				programm = mitm_protect()
			elif options.daemon:
				print('Starting daemon...')
				with daemon.DaemonContext():
					pf.acquire()
					programm = mitm_protect()
		else:
			print "Already running: PID: %d" % pf.read_pid()

