weewx-foobot

This is a driver for weewx that captures data from foobot air quality monitor.


Installation

0) install weewx

  http://weewx.com/docs/usersguide.htm

1) download the driver

wget -O weewx-foobot.zip https://github.com/matthewwall/weewx-foobot/archive/master.zip

2) install the driver

wee_extension --install weewx-foobot.zip

3) configure the driver

wee_config --reconfigure

4) start weewx

sudo /etc/init.d/weewx start
