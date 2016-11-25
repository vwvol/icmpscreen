## icmpscreen
It's a script which allows to monitor the status of network hosts in "real-time".

![alt tag](http://i.imgur.com/FqyOPl5.gif)

###Description
ICMPScreen is a script which allows to monitor the state 
of network hosts in "real-time". It can be useful for network engineers,
especially during works on the network when you should to know about
unreachable hosts earlier than your Zabbix/Nagios.
It much easier to know actual state of some subnet using this script,
then using fping again and again, and much faster then waiting for
results of your network monitoring system.

Tested setup:
Debian «Jessie» and CPython 2.7

There are 2 input methods:
- from clipboard (push Ctrl-D to start)
- from text file (-f key)

It supports resizing and scrolling.

Ctrl-C to exit.
UP and DOWN keys to scroll.

###Installation, a kind of.
```
# using Debian «Jessie»
# as user
git clone https://github.com/vwvol/icmpscreen.git
cd icmpscreen/

# as root
chown root icmpscreen.py
chgrp root icmpscreen.py
cp icmpscreen.py /opt/.
# add following string into /etc/sudoers
user ALL=(ALL) NOPASSWD: /usr/bin/python2.7 /opt/icmpscreen.py

# as user
# add following string into ~/.bashrc if you are using bash
alias icmpscreen.py='/usr/bin/python2.7 /opt/icmpscreen.py'
source ~/.bashrc
```
###Known issues:
- After reducing a size of the terminal, there is the content of the first line in top off screen.

