#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(name='mitmprotector',
      version='29',
      description='mitmprotector - protect\'s you from any kind of MITM-attacks, arpspoofing, ettercap, sslstrip, droidsheep, zAnti, dsploit, etc.',
      license='GPL3+',
      author='Jan Helbling',
      author_email='jan.helbling@gmail.com',
      url='https://github.com/JanHelbling/mitmprotector',
      platforms=['linux','freebsd','netbsd','unixware7' , 'openbsd'],
      scripts=['bin/mitmprotector.py'],
)
