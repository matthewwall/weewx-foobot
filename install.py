# installer for the weewx-foobot driver
# Copyright 2016-2017 Matthew Wall, all rights reserved
# Distributed under the terms of the GNU Public License (GPLv3)

from weecfg.extension import ExtensionInstaller

def loader():
    return FoobotInstaller()

class FoobotInstaller(ExtensionInstaller):
    def __init__(self):
        super(FoobotInstaller, self).__init__(
            version="0.1",
            name='foobot',
            description='Capture data from foobot air quality monitor',
            author="Matthew Wall",
            author_email="mwall@users.sourceforge.net",
            files=[('bin/user', ['bin/user/foobot.py'])]
            )
