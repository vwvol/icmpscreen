## icmpscreen
It's a script which allows to monitor the status  of network hosts in "real-time".



###Installation, a kind of.
```
#as user
git clone https://github.com/vwvol/icmpscreen.git
cd icmpscreen/

#as root
chown root icmpscreen.py
chgrp root icmpscreen.py
cp icmpscreen.py /opt/.
#add following string into /etc/sudoers
user ALL=(ALL) NOPASSWD: /usr/bin/python2.7 /opt/icmpscreen.py

#as user
#add following string into ~/.bashrc if you are using bash
alias icmpscreen.py='/usr/bin/python2.7 /opt/icmpscreen.py'
```
