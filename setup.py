#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2013, Nahuel Riva
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__revision__ = "$Id$"

__all__ = ['metadata', 'setup']

from distutils.core import setup
from distutils import version
from warnings import warn

import re
import os
import sys
import glob

# Distutils hack: in order to be able to build MSI installers with loose
# version numbers, we subclass StrictVersion to accept loose version numbers
# and convert them to the strict format. This works because Distutils will
# happily reinstall a package even if the version number matches exactly the
# one already installed on the system - so we can simply strip all extraneous
# characters and beta/postrelease version numbers will be treated just like
# the base version number.
if __name__ == '__main__':
    StrictVersion = version.StrictVersion
    class NotSoStrictVersion (StrictVersion):
        def parse (self, vstring):
            components = []
            for token in vstring.split('.'):
                token = token.strip()
                match = re.search('^[0-9]+', token)
                if match:
                    number = token[ match.start() : match.end() ]
                    components.append(number)
            vstring = '.'.join(components)
            return StrictVersion.parse(self, vstring)
    version.StrictVersion = NotSoStrictVersion

# Get the base directory
here = os.path.dirname(__file__)
if not here:
    here = os.path.curdir

# Text describing the module (reStructured text)
try:
    readme = os.path.join(here, 'README')
    long_description = open(readme, 'r').read()
except Exception:
    warn("README file not found or unreadable!")
    long_description = """pype32 is python library to read and write PE/PE+ binary files."""

# Get the list of scripts in the "tools" folder
scripts = glob.glob(os.path.join(here, 'tools', '*.py'))

# Set the parameters for the setup script
metadata = {

    # Setup instructions
    'provides'          : ['pype32'],
    'packages'          : ['pype32'],
    'scripts'           : scripts,

    # Metadata
    'name'              : 'pype32',
    'version'           : '0.1-alpha4',
    'description'       : 'PE/PE+ library',
    'long_description'  : long_description,
    'author'            : 'Nahuel Riva',
    'author_email'      : 'crackinglandia'+chr(64)+'gmail'+chr(0x2e)+'com',
    }

# Execute the setup script
if __name__ == '__main__':
    setup(**metadata)
