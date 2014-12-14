#!/usr/bin/python2

from distutils.core import setup

setup(name='mitmprotector',
      version='14',
      description='mitmprotector - protect\'s you from any kind of MITM-attacks, arpspoofing, ettercap, sslstrip, droidsheep, zAnti, dsploit, etc.',
      license='GPL3+',
      author='Jan Helbling',
      author_email='jan.helbling@gmail.com',
      url='http://www.jan-helbling.ch/index.php/projekte/18-unix-python-shell-mitm-protector-schutz-vor-arpspoofing',
      platforms=['linux','freebsd','netbsd','unixware7' , 'openbsd'],
      scripts=['bin/mitmprotector.py'],
)
