##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2014 Angus Gratton <gus@projectgus.com>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
import re

'''
OUTPUT_PYTHON format:

Packet:
[<ptype>, <pdata>]

<ptype>:
 - 'AP_READ' (AP read)
 - 'DP_READ' (DP read)
 - 'AP_WRITE' (AP write)
 - 'DP_WRITE' (DP write)
 - 'LINE_RESET' (line reset sequence)

<pdata>:
  - tuple of address, ack state, data for the given sequence
'''

swd_states = [
    'IDLE', # Idle/unknown
    'REQUEST', # Request phase (first 8 bits)
    'ACK', # Ack phase (next 3 bits)
    'READ', # Reading phase (next 32 bits for reads)
    'WRITE', # Writing phase (next 32 bits for write)
    'DPARITY', # Data parity phase
]

# Regexes for matching SWD data out of bitstring ('1' / '0' characters) format
RE_SWDSWITCH = re.compile(bin(0xE79E)[:1:-1] + '$')
RE_SWDREQ = re.compile(r'1(?P<apdp>.)(?P<rw>.)(?P<addr>..)(?P<parity>.)01$')
RE_IDLE = re.compile('0' * 50 + '$')

# Sample edges
RISING = 1
FALLING = 0

ADDR_DP_SELECT = 0x8
ADDR_DP_CTRLSTAT = 0x4

BIT_SELECT_CTRLSEL = 1
BIT_CTRLSTAT_ORUNDETECT = 1

ANNOTATIONS = ['bit', 'reset', 'enable', 'read', 'write', 'ack', 'parity', 'wdata', 'rdata', 'start', 'apndp', 'rnw', 'a', 'parity-bit', 'stop', 'park', 'trn', 'ack-bit', 'idle', 'data']

class Decoder(srd.Decoder):
    api_version = 3
    id = 'swd'
    name = 'SWD'
    longname = 'Serial Wire Debug'
    desc = 'Two-wire protocol for debug access to ARM CPUs.'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['swd']
    tags = ['Debug/trace']
    channels = (
        {'id': 'swclk', 'name': 'SWCLK', 'desc': 'Master clock'},
        {'id': 'swdio', 'name': 'SWDIO', 'desc': 'Data input/output'},
    )
    options = (
        {'id': 'strict_start',
         'desc': 'Wait for a line reset before starting to decode',
         'default': 'no', 'values': ('yes', 'no')},
        {'id': 'trn_bits',
         'desc': 'Number of turnaround bits',
         'default': 1},
    )
    annotations = (
        ('bit', 'Bit'),
        
        ('reset', 'RESET'),
        ('enable', 'ENABLE'),
        ('read', 'READ'),
        ('write', 'WRITE'),
        ('ack', 'ACK'),
        ('parity', 'PARITY'),
        ('wdata', 'WDATA'),
        ('rdata', 'RDATA'),
        
        ('start', 'Start'),
        ('apndp', 'APnDP'),
        ('rnw', 'RnW'),
        ('a', 'A'),
        ('parity-bit', 'Parity'),
        ('stop', 'Stop'),
        ('park', 'Park'),
        ('trn', 'Trn'),
        ('ack-bit', 'Ack'),
        ('data', 'DATA'),
        ('idle', 'IDLE'),
    )
    annotation_rows = (
        ('bits', 'Bits', (0,)),
        ('bit-meanings', 'Bit meanings', (9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,)),
        ('packets', 'Packets', (1, 2, 3, 4, 5, 6, 7, 8,)),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        # SWD data/clock state
        self.state = 'UNKNOWN'
        self.sample_edge = RISING
        self.ack = None # Ack state of the current phase
        self.ss_req = 0 # Start sample of current req
        self.turnaround = 0 # Number of turnaround edges to ignore before continuing
        self.bits = '' # Bits from SWDIO are accumulated here, matched against expected sequences
        self.bits_target = ''
        self.samplenums = [] # Sample numbers that correspond to the samples in self.bits
        self.linereset_count = 0
        self.last_clk_rising_samplenum = 0
        self.last_clk_rising_dio_state = 0

        # SWD debug port state
        self.data = None
        self.addr = None
        self.rw = None # Are we inside an SWD read or a write?
        self.ctrlsel = 0 # 'ctrlsel' is bit 0 in the SELECT register.
        self.orundetect = 0 # 'orundetect' is bit 0 in the CTRLSTAT register.

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        if self.options['strict_start'] == 'no':
            self.state = 'REQ' # No need to wait for a LINE RESET.
        self.turnaround_bits = self.options['trn_bits']

    def putbit(self):
        self.put(self.last_clk_rising_samplenum, self.samplenum, self.out_ann, [0, ['Host: %d, Target: %d' % (self.last_clk_rising_dio_state, self.dio), 'H: %d, T: %d' % (self.last_clk_rising_dio_state, self.dio), '%d %d' % (self.last_clk_rising_dio_state, self.dio)]])

    def putbit_host(self):
        self.put(self.last_clk_rising_samplenum, self.samplenum, self.out_ann, [0, ['%d' % self.last_clk_rising_dio_state]])

    def putbit_turnaround(self):
        self.put(self.last_clk_rising_samplenum, self.samplenum, self.out_ann, [0, ['Turnaround', 'Trn', 'T']])

    def putbit_target(self):
        self.put(self.last_clk_rising_samplenum, self.samplenum, self.out_ann, [0, ['%d' % self.dio]])

    def putbitmeaning_host(self, ann, ss_bit, es_bit, data):
        ann = ANNOTATIONS.index(ann)
        try:
            ss = self.samplenums[ss_bit][0]
            es = self.samplenums[es_bit][1]
        except IndexError:
            ss = self.samplenum
            es = self.samplenum
            data = "ERR"
        self.put(ss, es, self.out_ann, [ann, [data]])
        
    def putbitmeaning_target(self, ann, ss_bit, es_bit, data):
        ann = ANNOTATIONS.index(ann)
        try:
            ss = self.samplenums[ss_bit][0]
            es = self.samplenums[es_bit][1]
        except IndexError:
            ss = self.samplenum
            es = self.samplenum
            data = "ERR"
        self.put(ss, es, self.out_ann, [ann, [data]])

    def putx(self, ann, length, data):
        '''Output annotated data.'''
        ann = ANNOTATIONS.index(ann)
        try:
            ss = self.samplenums[-length][0]
        except IndexError:
            ss = self.samplenum
        if self.state == 'REQ':
            self.ss_req = ss
        es = self.samplenum
        self.put(ss, es, self.out_ann, [ann, [data]])

    def putp(self, ptype, pdata):
        self.put(self.ss_req, self.samplenum, self.out_python, [ptype, pdata])

    def put_python_data(self):
        '''Emit Python data item based on current SWD packet contents.'''
        ptype = {
            ('AP', 'R'): 'AP_READ',
            ('AP', 'W'): 'AP_WRITE',
            ('DP', 'R'): 'DP_READ',
            ('DP', 'W'): 'DP_WRITE',
        }[(self.apdp, self.rw)]
        self.putp(ptype, (self.addr, self.data, self.ack))

    def decode(self):
        while True:
            # Wait for any clock edge.
            clk, dio = self.wait({0: 'e'})

            # Count rising edges with DIO held high,
            # as a line reset (50+ high edges) can happen from any state.
            if clk == RISING:
                self.last_clk_rising_samplenum = self.samplenum
                self.last_clk_rising_dio_state = dio
                if dio == 1:
                    self.linereset_count += 1
                else:
                    if self.linereset_count >= 50:
                        self.putx('reset', self.linereset_count, 'LINERESET')
                        self.putp('LINE_RESET', None)
                        self.reset_state()
                    self.linereset_count = 0
            else:
                self.bits += str(self.last_clk_rising_dio_state)
                self.bits_target += str(dio)
                self.dio = dio
                self.samplenums.append([self.last_clk_rising_samplenum, self.samplenum, self.last_clk_rising_dio_state, dio])
                
                # Turnaround bits get skipped.
                if self.turnaround > 0:
                    self.turnaround -= 1
                    self.putbit_turnaround()
                    self.putbitmeaning_host('trn', 0, 0, 'Turnaround')
                    self.samplenums = [];
                    self.bits = ''
                    self.bits_target = ''
                    continue
                else:
                    self.putbit()

            # Otherwise, we only care about either rising or falling edges
            # (depending on sample_edge, set according to current state).
            if clk != FALLING:
                continue

            {
                'UNKNOWN': self.handle_unknown_edge,
                'REQ': self.handle_req_edge,
                'ACK': self.handle_ack_edge,
                'DATA': self.handle_data_edge,
                'DPARITY': self.handle_dparity_edge,
            }[self.state]()

    def next_state(self):
        '''Step to the next SWD state, reset internal counters accordingly.'''
        self.bits = ''
        self.bits_target = ''
        self.samplenums = []
        self.linereset_count = 0
        if self.state == 'UNKNOWN':
            self.state = 'REQ'
            self.sample_edge = RISING
            self.turnaround = 0
        elif self.state == 'REQ':
            self.state = 'ACK'
            self.sample_edge = RISING
            self.turnaround = self.turnaround_bits
        elif self.state == 'ACK':
            self.state = 'DATA'
            self.sample_edge = RISING if self.rw == 'W' else RISING
            self.turnaround = 0 if self.rw == 'R' else self.turnaround_bits
        elif self.state == 'DATA':
            self.state = 'DPARITY'
        elif self.state == 'DPARITY':
            self.put_python_data()
            self.state = 'REQ'
            self.sample_edge = RISING
            self.turnaround = (self.turnaround_bits + 2) if self.rw == 'R' else 0

    def reset_state(self):
        '''Line reset (or equivalent), wait for a new pending SWD request.'''
        if self.state != 'REQ': # Emit a Python data item.
            self.put_python_data()
        # Clear state.
        self.bits = ''
        self.bits_target = ''
        self.samplenums = []
        self.linereset_count = 0
        self.turnaround = 0
        self.sample_edge = RISING
        self.data = ''
        self.ack = None
        self.state = 'REQ'

    def handle_unknown_edge(self):
        '''
        Clock edge in the UNKNOWN state.
        In the unknown state, clock edges get ignored until we see a line
        reset (which is detected in the decode method, not here.)
        '''
        pass

    def handle_req_edge(self):
        '''Clock edge in the REQ state (waiting for SWD r/w request).'''
        # Check for a JTAG->SWD enable sequence.
        m = re.search(RE_SWDSWITCH, self.bits)
        if m is not None:
            self.putx('enable', 16, 'JTAG->SWD')
            self.reset_state()
            return

        # Or a valid SWD Request packet.
        m = re.search(RE_SWDREQ, self.bits)
        if m is not None:
            calc_parity = sum([int(x) for x in m.group('rw') + m.group('apdp') + m.group('addr')]) % 2
            parity = '' if str(calc_parity) == m.group('parity') else 'E'
            self.rw = 'R' if m.group('rw') == '1' else 'W'
            self.apdp = 'AP' if m.group('apdp') == '1' else 'DP'
            self.addr = int(m.group('addr')[::-1], 2) << 2
            parity_valid = 'Valid' if parity == '' else 'Invalid'
            
            self.putbitmeaning_host('idle', 0, -9, "Idle")
            
            self.putbitmeaning_host('start', -8, -8, "Start")
            self.putbitmeaning_host('apndp', -7, -7, self.apdp)
            self.putbitmeaning_host('rnw', -6, -6, self.rw)
            self.putbitmeaning_host('a', -5, -4, self.apdp + " register address: " + str(self.addr) + " (" + self.get_address_description() + ")")
            self.putbitmeaning_host('parity-bit', -3, -3, "Parity (" + parity_valid + ")")
            self.putbitmeaning_host('stop', -2, -2, "Stop")
            self.putbitmeaning_host('park', -1, -1, "Park")
            #self.putbitmeaning('trn', len(self.samplenums)-1, len(self.samplenums)-1, "Turnaround")
            
            self.putx('read' if self.rw == 'R' else 'write', 8, "Host Req: " + self.get_operation_summary())
            self.next_state()
            return

    def handle_ack_edge(self):
        '''Clock edge in the ACK state (waiting for complete ACK sequence).'''
        if len(self.bits_target) < 3:
            return
        
        self.putx('ack', 3, "Target: ACK reply")
        
        if self.bits_target == '100':
            self.putbitmeaning_target('ack-bit', -3, -1, 'OK')
            self.ack = 'OK'
            self.next_state()
        elif self.bits_target == '001':
            self.putbitmeaning_target('ack-bit', -3, -1, 'FAULT')
            self.ack = 'FAULT'
            if self.orundetect == 1:
                self.next_state()
            else:
                self.reset_state()
            self.turnaround = 1
        elif self.bits_target == '010':
            self.putbitmeaning_target('ack-bit', -3, -1, 'WAIT')
            self.ack = 'WAIT'
            if self.orundetect == 1:
                self.next_state()
            else:
                self.reset_state()
            self.turnaround = 1
        elif self.bits_target == '111':
            self.putbitmeaning_target('ack-bit', -3, -1, 'NOREPLY')
            self.ack = 'NOREPLY'
            self.reset_state()
        else:
            self.putbitmeaning_target('ack-bit', -3, -1, 'ERROR')
            self.ack = 'ERROR'
            self.reset_state()

    def handle_data_edge(self):
        '''Clock edge in the DATA state (waiting for 32 bits to clock past).'''
        if len(self.bits) < 33:
            return
            
        self.data = 0
        self.dparity = 0
        paritybit = 0
        
        if self.rw == 'R':
            for x in range(32):
                if self.bits_target[x] == '1':
                    self.data += (1 << x)
                    self.dparity += 1
            self.dparity = self.dparity % 2
            self.putx('rdata', 33, "Target: RDATA")
            self.putbitmeaning_target('data', -33, -2, '0x%08x' % self.data)
            paritybit = self.bits_target[32]
        else:
            for x in range(32):
                if self.bits[x] == '1':
                    self.data += (1 << x)
                    self.dparity += 1
            self.dparity = self.dparity % 2
            self.putx('wdata', 33, "Host: WDATA")
            self.putbitmeaning_host('data', -33, -2, '0x%08x' % self.data)
            paritybit = self.bits[32]
        
        
        
        if str(self.dparity) != paritybit:
            self.putbitmeaning_target('parity-bit', -1, -1, "Parity (Invalid)") # PARITY ERROR
        elif self.rw == 'W':
            self.handle_completed_write()
        else:
            self.putbitmeaning_target('parity-bit', -1, -1, "Parity (Valid)")
        
        self.next_state()
        self.next_state()

    def handle_dparity_edge(self):
        '''Clock edge in the DPARITY state (clocking in parity bit).'''
        
        self.next_state()

    def handle_completed_write(self):
        '''
        Update internal state of the debug port based on a completed
        write operation.
        '''
        if self.apdp != 'DP':
            return
        elif self.addr == ADDR_DP_SELECT:
            self.ctrlsel = self.data & BIT_SELECT_CTRLSEL
        elif self.addr == ADDR_DP_CTRLSTAT and self.ctrlsel == 0:
            self.orundetect = self.data & BIT_CTRLSTAT_ORUNDETECT

    def get_operation_summary(self):
        '''
        Return a human-readable description of the current operation,
        for annotated results.
        '''
        if self.apdp == 'DP':
            if self.rw == 'R':
                # Tables 2-4 & 2-5 in ADIv5.2 spec ARM document IHI 0031C
                return {
                    0: 'Read IDCODE',
                    0x4: 'Read CTRL/STAT' if self.ctrlsel == 0 else 'Read DLCR',
                    0x8: 'Request RESEND',
                    0xC: 'Read Buffer'
                }[self.addr]
            elif self.rw == 'W':
                # Tables 2-4 & 2-5 in ADIv5.2 spec ARM document IHI 0031C
                return {
                    0: 'Abort Write',
                    0x4: 'Write CTRL/STAT' if self.ctrlsel == 0 else 'Write DLCR',
                    0x8: 'Write SELECT',
                    0xC: 'Write RESERVED'
                }[self.addr]
        elif self.apdp == 'AP':
            if self.rw == 'R':
                return 'R AP%x' % self.addr
            elif self.rw == 'W':
                return 'W AP%x' % self.addr

        # Any legitimate operations shouldn't fall through to here, probably
        # a decoder bug.
        return '? %s%s%x' % (self.rw, self.apdp, self.addr)

    def get_address_description(self):
        '''
        Return a human-readable description of the currently selected address,
        for annotated results.
        '''
        if self.apdp == 'DP':
            if self.rw == 'R':
                # Tables 2-4 & 2-5 in ADIv5.2 spec ARM document IHI 0031C
                return {
                    0: 'IDCODE',
                    0x4: 'R CTRL/STAT' if self.ctrlsel == 0 else 'R DLCR',
                    0x8: 'RESEND',
                    0xC: 'RDBUFF'
                }[self.addr]
            elif self.rw == 'W':
                # Tables 2-4 & 2-5 in ADIv5.2 spec ARM document IHI 0031C
                return {
                    0: 'W ABORT',
                    0x4: 'W CTRL/STAT' if self.ctrlsel == 0 else 'W DLCR',
                    0x8: 'W SELECT',
                    0xC: 'W RESERVED'
                }[self.addr]
        elif self.apdp == 'AP':
            if self.rw == 'R':
                return 'R AP%x' % self.addr
            elif self.rw == 'W':
                return 'W AP%x' % self.addr

        # Any legitimate operations shouldn't fall through to here, probably
        # a decoder bug.
        return '? %s%s%x' % (self.rw, self.apdp, self.addr)
