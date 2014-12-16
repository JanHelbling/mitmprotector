#!/usr/bin/python2

from distutils.core import setup

setup(name='mitmprotector',
      version='24',
      description='mitmprotector - protect\'s you from any kind of MITM-attacks, arpspoofing, ettercap, sslstrip, droidsheep, zAnti, dsploit, etc.',
      license='GPL3+',
      author='Jan Helbling',
      author_email='jan.helbling@gmail.com',
      url='http://www.jan-helbling.ch/~jhelbling/linux.py?gpl3-opensource-programm=mitmprotector-protects-from-arpspoofing-and-man-in-the-middle-attacks',
      platforms=['linux','freebsd','netbsd','unixware7' , 'openbsd'],
      scripts=['bin/mitmprotector.py'],
)
