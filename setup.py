#!/usr/bin/python3
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(name='mitmprotector',
      version='29',
      description='mitmprotector - protect\'s you from any kind of MITM-attacks, arpspoofing, ettercap, sslstrip, droidsheep, zAnti, dsploit, etc.',
      license='GPL3+',
      author='Jan Helbling',
      author_email='jh@jan-helbling.ch',
      url='https://github.com/JanHelbling/mitmprotector',
      platforms=['linux'],
      scripts=['bin/mitmprotector.py'],
)
