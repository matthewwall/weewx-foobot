weewx-foobot

This is a driver for weewx that captures data from foobot air quality monitor.
The foobot monitors carbon dioxide, carbon monoxide, particulate matter,
volatile organic compounds (formaldehyde, benzene, xylene, toluene), humidity,
and temperature.

http://foobot.io

The driver uses pycap to sniff packets sent by the foobot.

Installation

0) install pre-requisites

a) install weewx

  http://weewx.com/docs/usersguide.htm

b) install pypcap

  sudo pip install pypcap OR sudo apt-get install python-pypcap

1) download the driver

wget -O weewx-foobot.zip https://github.com/matthewwall/weewx-foobot/archive/master.zip

2) install the driver

sudo wee_extension --install weewx-foobot.zip

3) configure the driver

sudo wee_config --reconfigure

4) start weewx

sudo /etc/init.d/weewx start
