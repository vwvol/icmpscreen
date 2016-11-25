"""ICMPScreen is a script which allows to monitor the status 
of network hosts in "real-time". It can be useful for network engineers,
especially during works on the network when you should to know about
unreachable hosts earlier than your Zabbix/Nagios.
It much easier to know actual state of some subnet using this script,
then using fping again and again, and much faster then waiting for
results of your network monitoring system.

There are 2 input methods:
- from clipboard (push Ctrl-D to start)
- from text file

It supports resizing and scrolling.

Ctrl-C to exit.
UP and DOWN keys to scroll.

It's a summation of pure ICMP-client implementation and pseudo 
graphical screen.

There are 3 main components:
- Requester thread which sends requests to the Ping thread
- Ping thread which provides the results of ICMP-requests and sends it 
  to the Terminal class.
- Terminal class which provides pseudo graphical screen with 2 
  subwindows (left for alive hosts, right for unreachable hosts)

On scheme it looks like:

  ##############################
  # Requester (thread)         #
  # sending requests with      #
  # different sequence number  #
  ##############################
        |
        | tuple('10.0.0.1', 1)
        |
        | tuple('10.0.0.1', 0)
        V                          ICMP-req to
  ##############################   8.8.8.8        ###############
  # Ping (thread)              # ---------------> # your
  # sending ICMP requests and  #                  # router
  # sending results            # <--------------- # or something
  ##############################   ICMP reply     ###############
        |
        | tuple('10.0.0.1', 1, 23.2689)
        |
        | tuple('10.0.0.1', 0, 24.8408)
        V
  #############################
  # Terminal (main)           #
  # receives results and      #
  # displays any changes      #
  # if they are               #
  #############################

GitHub: https://github.com/vwvol/icmpscreen
E-mail: vwvol@yandex.ru

"""

import argparse
import array
import curses
import fcntl
import os
import select
import signal
import socket
import struct
import sys
import termios
import thread
import time
from threading import Thread, Event, currentThread
import traceback
import Queue

MAXHOSTS = 1000
ICMPTIMEOUT = 1000
REQINTERVAL = 1
DUPLICATERAISE = False # 0 - ignore, 1 - raise DuplicateFound


class InputInterrupted(Exception):
    def __init__(self):
        self.value = '\nInput has been interrupted'
    def __str__(self):
        return self.value


class OverLimitedInput(Exception):
    def __init__(self, value):
        self.value = 'you have entered ' + \
                     str(value + 1) + \
                     ' lines (' + str(value) + ' allowed)'
    def __str__(self):
        return repr(self.value)


class notIpv4Addr(Exception):
    def __init__(self, value):
        self.value = '\n' + repr(value) + ' is not an IPv4 address'
    def __str__(self):
        return self.value


class DuplicateOccur(Exception):
    def __init__(self, value):
        self.value = '\n' + repr(value) + \
                     ' there are at least 2 same addresses'
    def __str__(self):
        return self.value


class TerminalSizeErr(Exception):
    def __init__(self):
        self.value = 'too small terminal window ' + \
                     '(it should be at least 24 lines and 80 columns)'
    def __str__(self):
        return self.value


class IntErrorOccur(Exception):
    def __init__(self, value):
        excType = value[1].__class__.__name__
        self.value = value
    def __str__(self):
        return self.value


class GotIntError(Exception):
    def __init__(self):
        pass


class Ping:
    """Class Ping is a pure ping implementation.
    As the basis for this class was taken ping.py from
    https://gist.github.com/pklaus/856268
    It was adapted for using in thread with 2 queues 
    (for requests and results)
    """
    ICMP_ECHO = 8			# Echo request (per RFC792)
    ICMP_MAX_RECV = 2048		# Max size of incoming buffer
    
    def __init__(self, ICMPTimeOut = 1000, numDataBytes = 64):
        
        self.numDataBytes = numDataBytes
        self.timeOut = ICMPTimeOut
        self.sended = {}
        
    def checksum(self, source_string):
        """
        A port of the functionality of in_cksum() from ping.c
        Ideally this would act on the string as a series of 16-bit ints (host
        packed), but this works.
        Network data is big-endian, hosts are typically little-endian
        """
        if (len(source_string) % 2):
            source_string += "\x00"
        converted = array.array("H", source_string)
        if sys.byteorder == "big":
            converted.bytewap()
        val = sum(converted)
        
        val &= 0xffffffff
        
        val = (val >> 16) + (val & 0xffff)
        val += (val >> 16)
        answer = ~val & 0xffff
        answer = socket.htons(answer)
        return answer
    
    def main(self, qIn, qOut):
        """main method takes as arguments 2 queues which
        used for taken requests (tuple with IPv4 address 
        and ICMP sequence) and given results (tuple with IPv4 address, 
        ICMP sequence and latency).
        This method creates icmp socket, starts receiving thread,
        and enters into the main loop for requests receiving, sending
        ICMP-req packets and starting timeout-threads for each request.
        """
        try:
            currThr = currentThread()
            
            sock = socket.socket(socket.AF_INET, \
                                 socket.SOCK_RAW, \
                                 socket.getprotobyname('icmp'))
            sock.setsockopt(socket.SOL_SOCKET, \
                            socket.SO_BROADCAST, 1)
            sock.settimeout(0.5)

            self.pid = os.getpid() & 0xFFFF
            
            recvThr = Thread(target = self.receiver, args = (sock, 
                                                             qIn,
                                                             qOut))
            recvThr.start()
            
            while getattr(currThr, 'run', True):
                try:
                    data = qIn.get(timeout = 0.5)
                    if isinstance(data, Exception):
                        qOut.put(data)
                        raise GotIntError
                        
                    host, seq = data
                    sentTime = self.sendIcmpReq(sock, \
                                                host, \
                                                self.pid, \
                                                seq)
                    self.sended[(host, seq)] = sentTime
                    
                    thread.start_new_thread(self.hostTimeout, (qIn, \
                                                               qOut, \
                                                               host, \
                                                               seq, ))
                except Queue.Empty:
                    continue
        except GotIntError:
            pass
        except:
            t = traceback.format_exc()
            qOut.put(IntErrorOccur(t))
        finally:
            if 'recvThr' in locals():
                if recvThr.isAlive():
                    recvThr.run = False
                    recvThr.join()
            if 'sock' in locals():
                sock.close()
    
    def hostTimeout(self, qIn, qOut, host, seq):
        """hostTimeout method needs for timeout counting for current 
        ICMP-request. When timeout running out it checks state of
        current request in self.sended dictionary and if record about
        this request still exist, it will send result into qOut queue
        with False instead of delay value
        It takes 4 arguments:
            qIn - queue for Exception object sending to the loop
                  of main method if something going wrong.
            qOut - queue for timeout expired message sending.
            host - IPv4 address of current request
            seq - ICMP sequence of current request
        """
        try:
            begin = time.time()
            time.sleep(self.timeOut / 1000)
            
            hasSleeped = time.time() - begin
            if self.sended.has_key((host, seq)):
                self.sended.pop((host, seq))
                qOut.put((host, seq, False))
        except:
            t = traceback.format_exc()
            qIn.put(IntErrorOccur(t))
    
    def receiver(self, sock, qIn, qOut):
        """receiver method needs for cyclic data receiving
        and packet handling with responseHandler method.
        It takes 3 arguments:
            sock - socket object
            qIn - queue for Exception object sending to the loop
                  of main method if something going wrong.
            qOut - queue for result message sending.
        """
        currThr = currentThread()
        while getattr(currThr, 'run', True):
            try:
                recPacket, addr = sock.recvfrom(self.ICMP_MAX_RECV)
                timeRecv = time.time()
                
                self.responseHandler(qOut, \
                                     recPacket, \
                                     addr[0], \
                                     timeRecv)
            except socket.timeout:
                continue
            except:
                t = traceback.format_exc()
                qIn.put(IntErrorOccur(t))
                break
    
    def responseHandler(self, qOut, data, host, timeRecv):
        """responseHandler needs for parsing of receiving packet,
        and making decision about timeout expiring for current request.
        It takes 4 arguments:
            qOut - queue for result message sending.
            data - receiving packet
            host - source IPv4 address
            timeRecv - receiving timestamp
        """
        icmpHeader = data[20:28]
        icmpType, \
        icmpCode, \
        icmpChecksum, \
        icmpPacketID, \
        icmpSeqNumber = struct.unpack("!BBHHH", icmpHeader)

        # Match only the packets we care about
        if icmpType == 8:
            return
        if icmpPacketID != self.pid:
            return
        if self.sended.has_key((host, icmpSeqNumber)):
            timeSend = self.sended.pop((host, icmpSeqNumber))
            timeLeft = (timeRecv - timeSend) * 1000
            if timeLeft >= self.timeOut:
                qOut.put((host, icmpSeqNumber, False))
            else:
                qOut.put((host, icmpSeqNumber, timeLeft))
    
    def sendIcmpReq(self, sock, destIP, pid, seq):
        """sendIcmpReq takes 4 arguments (socket, destination IPv4 
        address, PID and ICMP sequence).
        This method compiles ICMP-req packet, sends it and returns
        sending timestamp.
        """
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # (numDataBytes - 8) - Remove header size from packet size
        checksum = 0

        # Make a dummy heder with a 0 checksum.
        header = struct.pack("!BBHHH", \
                             self.ICMP_ECHO, \
                             0, \
                             checksum, \
                             pid, \
                             seq)
        
        padBytes = []
        startVal = 0x42
        # 'cose of the string/byte changes in python 2/3 we have
        # to build the data differnely for different version
        # or it will make packets with unexpected size.
        if sys.version[:1] == '2':
            bytes = struct.calcsize("d")
            data = ((self.numDataBytes - 8) - bytes) * "Q"
            data = struct.pack("d", 0) + data
        else:
            for i in range(startVal, \
                           startVal + (self.numDataBytes - 8)):
                padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
            data = bytearray(padBytes)
        
        checksum = self.checksum(header + data)
        
        header = struct.pack("!BBHHH", \
                             self.ICMP_ECHO, \
                             0, \
                             checksum, \
                             pid, \
                             seq)

        packet = header + data
        sock.sendto(packet, (destIP, 1)) 
        
        sendTime = time.time()
        return sendTime


class Terminal:
    """Terminal class uses curses module to create pseudographic
    window with 2 subwindows: left - for displaying alive hosts
                              right - for unreachable hosts
    It supports resizing of terminal window and requires at least 24
    lines and 80 columns.
    It also supports "scrolling" using UP and DOWN keys.
    Terminal class takes results from Ping thread by queue.
    """
    def __init__(self, hosts, queue_in):
        
        self.states = [' alive ', ' unreachable ']
        self.topbot = ['above: ', 'below: ']
        self.empty = ' ' * 15
        self.lineLen = len(self.empty)
        
        self.hosts = hosts
        self.queue_in = queue_in
        self.slots = {}
        
    def main(self):
        """main method do a lot of stuff:
            - it initiates and configures pseudographic screen
            - it calculates and creates subwindows
            - it calculate a lot of stuff
            - it sets handler method for SIGWINCH (for resizing)
            - it runs queue handler thread for data receiving
            - and it enters into the main loop to handle keys
              pushing and checking for incoming exceptions.
        """
        try:
            self.thr2main = Queue.Queue()
            
            self.stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.stdscr.keypad(1)
            curses.curs_set( 0 )
            self.stdscr.timeout(500)
            
            height, width = self.termsize()
            if height < 24 or width < 80:
                    raise TerminalSizeErr
            
            self.lwc, self.rwc = self.splitScreen(height, width)
            
            self.lWin = self.stdscr.subwin(self.lwc['y_len'],
                                           self.lwc['x_len'],
                                           self.lwc['y_loc'],
                                           self.lwc['x_loc'])
            
            self.rWin = self.stdscr.subwin(self.rwc['y_len'],
                                           self.rwc['x_len'],
                                           self.rwc['y_loc'],
                                           self.rwc['x_loc'])
            
            self.lWin.border(0)
            self.rWin.border(0)
            
            self.slots = self.slotDef(self.hosts, self.lwc, self.rwc)
            
            self.linesMax = max([max([self.slots[key][1][0], \
                                     self.slots[key][2][0]]) \
                               for key in self.slots.keys()])
            
            self.cLine = 1
            self.yLen = height - 2
            self.rowsOnScr = range(self.cLine, self.yLen + self.cLine)
            
            self.stdscr.refresh()
            
            signal.signal(signal.SIGWINCH, self.resizeHandler)
            
            qH = Thread(target = self.queueHandler, \
                        args = (self.queue_in, self.thr2main))
            qH.start()
            
            key = -1
            while True:
                key = self.stdscr.getch()
                if not self.thr2main.empty():
                    exception = self.thr2main.get()
                    raise exception
                if key == curses.KEY_DOWN:
                    if self.rowsOnScr[-1] <= self.linesMax:
                        self.rowsOnScr = [x + 1 for x in self.rowsOnScr]
                        for host in self.hosts:
                            self.move(host, 'up')
                elif key == curses.KEY_UP:
                    if self.rowsOnScr[0] >= 2:
                        self.rowsOnScr = [x - 1 for x in self.rowsOnScr]
                        for host in self.hosts:
                            self.move(host, 'down')
                else:
                    continue
                
                counters = self.countValue(self.slots, self.rowsOnScr)
                self.countPrinter(counters, (self.lwc, self.rwc))
                self.stdscr.refresh()
        except KeyboardInterrupt:
            raise
        except IntErrorOccur:
            raise
        except:
            raise
        finally:
            signal.signal(signal.SIGWINCH, signal.SIG_IGN) #ignore
            if 'qH' in locals():
                if qH.isAlive():
                    qH.run = False
                    qH.join()
            if hasattr(self, 'stdscr'):
                self.stdscr.refresh()
                self.stdscr.keypad(0)
                curses.echo()
                curses.nocbreak()
                curses.endwin()
    
    def resizeHandler(self, signum, frame):
        """resizeHandler method serves for reacting on resizing of
        terminal window.
        At first it disables resize handling for next signals and 
        clears screen.
        After it gets and checks new size (if size if less then 
        required, exception will be raised).
        After it makes the same things as main method after configuring
        of pseudographic screen:
            - calculates and creates subwindows
            - calculates a lot of stuff
            - prints all displayed hosts
            - refreshs screen and enables resize handling with 
              the same methods
        """
        try:
            if signum == 28:
                signal.signal(signal.SIGWINCH, signal.SIG_IGN)
                self.stdscr.clear()
                height, width = self.termsize()
                if height < 24 or width < 80:
                    raise TerminalSizeErr
                
                self.yLen = height - 2
                self.rowsOnScr = range(self.cLine, \
                                       self.yLen + self.cLine)
                
                curses.resizeterm(height, width)
                self.lwc, self.rwc = self.splitScreen(height, width)
                self.lWin = self.stdscr.subwin(self.lwc['y_len'],
                                               self.lwc['x_len'],
                                               self.lwc['y_loc'],
                                               self.lwc['x_loc'])
                
                self.rWin = self.stdscr.subwin(self.rwc['y_len'],
                                               self.rwc['x_len'],
                                               self.rwc['y_loc'],
                                               self.rwc['x_loc'])
                
                self.slots = self.slotDef(self.hosts, \
                                          self.lwc, \
                                          self.rwc)
                
                self.linesMax = max([max([self.slots[key][1][0], \
                                         self.slots[key][2][0]]) \
                                   for key in self.slots.keys()])
                
                for host in self.hosts:
                    way = 'left' if self.slots[host][0] == 1 else 'right'
                    self.move(host, way)

                counters = self.countValue(self.slots, self.rowsOnScr)
                self.countPrinter(counters, (self.lwc, self.rwc))
                
                self.stdscr.refresh()
                signal.signal(signal.SIGWINCH, self.resizeHandler)
        except TerminalSizeErr:
            t = traceback.format_exc()
            self.thr2main.put(IntErrorOccur(t))
        except:
            t = traceback.format_exc()
            self.thr2main.put(IntErrorOccur(t))
    
    def queueHandler(self, queue_in, thr2main):
        """queueHandler method needs to handle incoming messages
        from Ping thread and display changes in current positions
        of hisplayed hosts if they are.
        """
        thr = currentThread()
        try:
            while getattr(thr, 'run', True):
                try:
                    result = queue_in.get(timeout = 0.5)
                    if isinstance(result, Exception):
                        thr2main.put(result)
                        raise GotIntError
                    host = result[0]
                    newState = 0 if result[2] == False else 1
                    
                    if newState != self.slots[host][0]:
                        way = 'left' if newState == 1 else 'right'
                        self.slots[host][0] = newState
                        self.move(host, way)
                        
                        counters = self.countValue(self.slots, \
                                                 self.rowsOnScr)
                        self.countPrinter(counters, (self.lwc, self.rwc))
                        
                        self.stdscr.refresh()
                except Queue.Empty:
                    continue
                except:
                    raise
        except GotIntError:
            pass
        except:
            t = traceback.format_exc()
            thr2main.put(IntErrorOccur(t))
    
    def countValue(self, slots, rowsOnScr):
        """countValue needs to calculate a value of counters which
        show quantity of out-of-screen hosts.
        As arguments it takes:
            - dictinary with current hosts status and their possible
              positions.
            - list with currently displayed lines.
        It returns tuples with quantities of non-displayed hosts 
        above and below for each subwindow.
        """
        highLeft = 0
        lowLeft = 0
        highRight = 0
        lowRight = 0
        
        for host in slots.keys():
            State = slots[host][0]
            lSlot = slots[host][1]
            rSlot = slots[host][2]
            y = lSlot[0] or rSlot[0] 
            
            if State == 1 and y < rowsOnScr[0]: highLeft += 1; continue
            if State == 1 and y > rowsOnScr[-1]: lowLeft += 1; continue
            if State == 0 and y < rowsOnScr[0]: highRight += 1; continue
            if State == 0 and y > rowsOnScr[-1]: lowRight += 1; continue
        
        return (highLeft, lowLeft), (highRight, lowRight)
    
    def countPrinter(self, counters, wins):
        """countPrinter takes as arguments tuple with values of 
        counters of out-of-screen hosts and tuple with coordinates of
        subwindows. This method displays counters of out-of-screen 
        hosts depending on coordinates of subwindows
        """
        rowMin = self.rowsOnScr[0]
        rowMax = self.rowsOnScr[-1]
        
        self.lWin.border(0)
        self.rWin.border(0)
        self.lWin.refresh()
        self.rWin.refresh()
        
        for w in range(2):
            countPosition = self.countPosition(wins[w])
            for i in range(2):
                if (rowMin > 1 and i == 0) or \
                   (rowMax < self.linesMax and i == 1):
                    countStr = self.states[w] + \
                               self.topbot[i] + \
                               str(counters[w][i]) + ' '
                    xOffset = len(countStr) / 2
                    self.stdscr.addstr(countPosition[i][0], \
                                       countPosition[i][1] - xOffset, \
                                       countStr)
                elif i == 0:
                    countStr = self.states[w][:-1] + ': '
                    xOffset = len(countStr) / 2
                    self.stdscr.addstr(countPosition[i][0], \
                                       countPosition[i][1] - xOffset, \
                                       countStr)
    
    def countPosition(self, win):
        """countPosition method calculates center positions on x-axis
        for both top and bottom counters for current subwindow.
        It takes dictionary with coordinates of subwindow, and returns
        2 tuples with coordinates.
        """
        y_len, x_len, y_loc, x_loc = win['y_len'], \
                                     win['x_len'], \
                                     win['y_loc'], \
                                     win['x_loc']
        
        top = (0, x_loc + x_len / 2)
        bot = (y_len - 1, x_loc + x_len / 2)
        
        return top, bot
    
    def move(self, host, way):
        """move method needs to move position of displayed host
        on pseudographic screen. It takes host's address and 
        direction for moving as arguments.
        If required host should be on screen, method displays it.
        """
        State = self.slots[host][0]
        lSlot = self.slots[host][1]
        rSlot = self.slots[host][2]
        y = lSlot[0] or rSlot[0] 
        if y in self.rowsOnScr and State != 3:
            yOffset = y - self.rowsOnScr[0] + 1
            
            if way == 'up' or way == 'down':
                hostCol, emptCol = (lSlot[1], rSlot[1]) \
                                   if State == 1 \
                                   else (rSlot[1], lSlot[1])
                self.stdscr.addstr(yOffset, \
                                   hostCol, \
                                   self.empty)
                self.stdscr.addstr(yOffset, \
                                   hostCol, \
                                   host)
                self.stdscr.addstr(yOffset, \
                                   emptCol, \
                                   self.empty)
                if way == 'up' and y != self.rowsOnScr[-1]:
                    self.stdscr.addstr(yOffset + 1, \
                                       hostCol, \
                                       self.empty)
                    self.stdscr.addstr(yOffset + 1, \
                                       emptCol, \
                                       self.empty)
                
            elif way == 'left' or way == 'right':
                hostCol, emptCol = (lSlot[1], rSlot[1]) \
                                   if way == 'left' \
                                   else (rSlot[1], lSlot[1])
                self.stdscr.addstr(yOffset, \
                                   hostCol, \
                                   host)
                self.stdscr.addstr(yOffset, \
                                   emptCol, \
                                   self.empty)
    
    def termsize(self):
        """termsize method returns current size of terminal.
        Thanks to cas from blog.taz.net.au.
        Source:
        http://blog.taz.net.au/2012/04/09/getting-the-terminal-size-in-python/
        """
        try:
            hw = struct.unpack('hh', fcntl.ioctl(1, \
                                                 termios.TIOCGWINSZ, \
                                                 '1234'))
            return hw[0], hw[1]
        except:
            return None
    
    def splitScreen(self, y, x):
        """splitScreen method takes as arguments height and width
        of terminal and returns 2 dictionaries with parameters of 
        2 subwindows.
        """
        lw_y_len = y
        lw_x_len = x/2
        lw_y_loc = 0
        lw_x_loc = 0
        
        rw_y_len = y
        rw_x_len = x-x/2
        rw_y_loc = 0
        rw_x_loc = x/2
        
        return ({'y_len': lw_y_len,
                 'x_len': lw_x_len,
                 'y_loc': lw_y_loc,
                 'x_loc': lw_x_loc}, 
                {'y_len': rw_y_len,
                 'x_len': rw_x_len,
                 'y_loc': rw_y_loc,
                 'x_loc': rw_x_loc})
    
    def slotCalc(self, colList, y_loc, x_loc):
        xCurLoc = x_loc
        result = []
        
        for rawsInCol in colList:
            for i in range(rawsInCol):
                result.append((y_loc + i, xCurLoc))
            xCurLoc += self.lineLen + 1
        return result
    
    def colCalcMP(self, hostsLen, colLen):
        result = []
        hostsLeft = hostsLen
        for i in range(colLen):
            rawsInCol = hostsLeft / (colLen - i)
            result.append(rawsInCol)
            hostsLeft -= rawsInCol
        return list(reversed(result))
    
    def colCalcOP(self, hostsLen, raws):
        result = []
        hostsLeft = hostsLen
        while True:
            if hostsLeft <= raws:
                result.append(hostsLeft)
                break
            else:
                result.append(raws)
                hostsLeft -= raws
        return result
    
    def slotDef(self, hostsList, lw, rw):
        """slotDef method defines positions for each host depending on
        parameters of subwindows.
        As arguments it take list with all hosts and 2 dictionaries
        with paramenters of subwindows. 
        This method returns dictionary whose keys are hosts whose values
        are lists with current status (0 - unreachable, 1 - alive, 
        3 - unknown), tuple with coordinates in left subwin and tuple 
        with coordinates in right subwin.
        """
        locLwY = lw['y_loc'] + 1
        locLwX = lw['x_loc'] + 1
        lenLwX = lw['x_len'] - 2
        
        locRwY = rw['y_loc'] + 1
        locRwX = rw['x_loc'] + 1
        lenRwX = rw['x_len'] - 2
        
        result = {}
        hostsLen = len(hostsList)
        
        lColumn = max([lenLwX / (self.lineLen + 1),
                       (lenLwX + 1) / (self.lineLen + 1)])
        rColumn = max([lenRwX / (self.lineLen + 1),
                       (lenRwX + 1) / (self.lineLen + 1)])
        
        columns = min([lColumn, rColumn])
        raws = min([lw['y_len'] - 2, 
                    rw['y_len'] - 2])
        
        if hostsLen <= raws * columns:
            colList = self.colCalcOP(hostsLen, raws)
        else:
            colList = self.colCalcMP(hostsLen, columns)
        
        lSlots = self.slotCalc(colList,
                               locLwY,
                               locLwX)
        rSlots = self.slotCalc(colList,
                               locRwY,
                               locRwX)
        
        for host in hostsList:
            if self.slots.has_key(host):
                result[host] = [self.slots[host][0], \
                                lSlots.pop(0), \
                                rSlots.pop(0)]
            else:
                result[host] = [3, lSlots.pop(0), rSlots.pop(0)]
        return result

def requester(hostList, queueOut, interval):
    """This method servs to send requests to Ping thread by queueOut
    queue. It sends tuples (host, seq) for each host every 
    int(interval) seconds.
    """
    try:
        selfthr = currentThread()
        seq = 0
        i = 0
        #first run
        for host in hostList:
            queueOut.put((host, seq))
        seq += 1
        #all the rest
        while getattr(selfthr, 'run', True):
            time.sleep(interval)
            while getattr(selfthr, 'run', True):
                queueOut.put((hostList[i], seq))
                i += 1
                if i == len(hostList): 
                    i = 0
                    break
            seq += 1
            if seq == 65536: seq = 0
    except:
        t = traceback.format_exc()
        queueOut.put(IntErrorOccur(t))

def receiver(limit):
    """This method receives IP addresses through stdin and returns
    list of taken addresses.
    """
    result = []
    try:
        while True:
            line = raw_input()
            if line != '':
                result.append(line)
    except EOFError:
        if len(result) > limit:
            raise OverLimitedInput(limit)
        return result
    except KeyboardInterrupt:
        raise InputInterrupted
    except:
        raise

def reader(limit, path):
    """This method reads IP addresses from file and returns
    list of addresses.
    """
    result = []
    try:
        f = open(path)
        data = f.read()
        f.close()
        for line in data.split('\n'):
            if line != '':
                result.append(line)
                if len(result) > limit:
                    raise OverLimitedInput(limit)
        return result
    except:
        raise

def isIpv4Addr(s):
    if [octet.isdigit() for octet in s.split('.')] != [True] * 4:
        return False
    if [0 <= int(octet) <= 255 for octet in s.split('.')] != [True] * 4:
        return False
    return True

def dupSearcher(shouldraise, l):
    if shouldraise == True:
        for item in l:
            if l.count(item) != 1:
                raise DuplicateOccur(item)
        return l
    elif shouldraise == False:
        #uniq = list(set(l)) #it will violates the order
        uniq = []
        for host in l:
            if host not in uniq:
                uniq.append(host)
        return uniq

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(prog='ICMPScreen')
    inputMethod = parser.add_mutually_exclusive_group()
    inputMethod.add_argument('-f', dest='path', \
                             help='path to text file')
    
    queueResult = Queue.Queue()
    queueHosts = Queue.Queue()
    
    try:
        signal.signal(signal.SIGTSTP, signal.SIG_IGN)
        
        args = parser.parse_args()
        
        if args.path != None:
            hosts = reader(MAXHOSTS, args.path)
        else:
            hosts = receiver(MAXHOSTS)
        
        hosts = dupSearcher(DUPLICATERAISE, hosts)
        
        for host in hosts:
            if not isIpv4Addr(host):
                raise notIpv4Addr(host)
        
        pingThread = Ping(ICMPTIMEOUT)
        pth = Thread(target=pingThread.main, args=(queueHosts, \
                                                   queueResult, ))
        pth.start()
        
        req = Thread(target=requester, args=(hosts, \
                                             queueHosts, \
                                             REQINTERVAL))
        req.start()
        
        screen = Terminal(hosts, queueResult)
        screen.main()
        
    except KeyboardInterrupt:
        print 'done'
    except Exception, e:
        print e
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if 'req' in locals():
            if req.isAlive():
                req.run = False
                req.join()
        if 'pth' in locals():
            if pth.isAlive():
                pth.run = False
                pth.join()

            
