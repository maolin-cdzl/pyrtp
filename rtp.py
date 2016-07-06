import struct
import random

RTP_VERSION = 2
RTP_SEQ_MOD = (1 << 16)

MAX_DROPOUT = 3000
MAX_MISORDER = 100
MIN_SEQUENTIAL = 2

class RtpHeader:
    def __init__(self):
        self.field_byte_1           = 0
        self.field_byte_2           = 0
        self.field_uint16_3         = 0
        self.field_uint32_4         = 0
        self.field_uint32_5         = 0
        self.field_uint32_list_6    = []

    def toByteArray(self):
        self.update_cc()
        buf = bytearray( struct.pack('!BBHII',self.field_byte_1,self.field_byte_2,self.field_uint16_3,self.field_uint32_4,self.field_uint32_5) )
        for v in self.field_uint32_list_6:
            if not isinstance(v,int):
                raise TypeError('every CSRC must be a uint32 number')
            buf.append( struct.pack('!I',v) )
        return buf

    @property
    def version(self):
        return (self.field_byte_1 >> 6) & 0x3
    @version.setter
    def version(self,v):
        self.field_byte_1 = (self.field_byte_1 & 0x3F) | ( (v & 0x3) << 6 )

    @property
    def padding(self):
        return (self.field_byte_1 >> 5) & 0x1
    @padding.setter
    def padding(self,p):
        self.field_byte_1 = (self.field_byte_1 & 0xBF) | ( (p & 0x1) << 5 )

    @property
    def ext(self):
        return (self.field_byte_1 >> 4) & 0x1
    @ext.setter
    def ext(self,e):
        self.field_byte_1 = (self.field_byte_1 & 0xEF ) | ( (e & 0x1) << 4 )

    @property
    def cc(self):
        self.update_cc()
        self.field_byte_1 = (self.field_byte_1 & 0xF0) | ( len(self.field_uint32_list_6) & 0xF )
        return (self.field_byte_1 & 0xF)

    def update_cc(self):
        self.field_byte_1 = (self.field_byte_1 & 0xF0) | ( len(self.field_uint32_list_6) & 0xF )

    @property
    def marker(self):
        return (self.field_byte_2 >> 7) & 0x 1
    @marker.setter
    def marker(self,m):
        self.field_byte_2 = (self.field_byte_2 & 0x7F) | ( (m & 0x1) << 7 )

    @property
    def paytype(self):
        return self.field_byte_2 & 0x7F
    @paytype.setter
    def paytype(self,t):
        self.field_byte_2 = (self.field_byte_2 & 0x80) | (t & 0x7F)

    @property
    def seq(self):
        return self.field_uint16_3
    @seq.setter
    def seq(self,s):
        self.field_uint16_3 = ( s & 0xFFFF )

    @property
    def timestamp(self):
        return self.field_uint32_4
    @timestamp.setter
    def timestamp(self,t):
        self.field_uint32_4 = ( t & 0xFFFFFFFF )

    @property
    def ssrc(self):
        return self.field_uint32_5
    
    @ssrc.setter
    def ssrc(self,s):
        self.field_uint32_5 = (s & 0xFFFFFFFF)

    @property
    def csrc(self):
        return self.field_uint32_list_6
    @csrc.setter(self,cs):
        self.field_uint32_list_6 = cs



class Source:
    def __init__(self):
        self.max_seq = 0            # u_int16 ,highest seq. number seen
        self.cycles = 0             # shifted count of seq. number cycles
        self.base_seq = 0           # base seq number
        self.bad_seq = 0            # last 'bad' seq number + 1
        self.probation = 0          # sequ. packets till source is valid
        self.received = 0           # packets received
        self.expected_prior = 0     # packet expected at last interval
        self.received_prior = 0     # packet received at last interval
        self.transit = 0            # relative trans time for prev pkt
        self.jitter = 0             # estimated jitter

    def init_seq(self,seq):
        self.base_seq = seq
        self.max_seq = seq
        self.bad_seq = RTP_SEQ_MOD + 1
        self.cycles = 0
        self.received = 0
        self.received_prior = 0
        self.expected_prior = 0

    def update_seq(self,seq):
        udelta = seq - self.max_seq
        if udelta < 0:
            udelta += 0xFFFF 
        if self.probation > 0:
            if seq == self.max_seq + 1:
                self.probation -= 1
                self.max_seq = seq
                if self.probation == 0:
                    self.init_seq(seq)
                    self.received += 1
                    return True
            else:
                self.probation = MIN_SEQUENTIAL - 1
                self.max_seq = seq
            return False
        elif udelta < MAX_DROPOUT:
            if seq < self.max_seq:
                self.cycles += RTP_SEQ_MOD
            self.max_seq = seq
        elif udelta < RTP_SEQ_MOD - MAX_MISORDER:
            if seq == self.bad_seq:
                # 
                #  Two sequential packets -- assume that the other side
                #  restarted without telling us so just re-sync
                #  (i.e., pretend this was the first packet).
                # 
                self.init_seq(seq)
            else:
                self.bad_seq = (seq + 1) & (RTP_SEQ_MOD - 1)
                return False
        else:
            # duplicate or reordered packet
            pass
        self.received += 1
        return True

    def expected(self):
        return self.cycles + self.max_seq - self.base_seq + 1

    def lost(self):
        return self.expected() - self.received

    '''
        The resulting fraction is an 8-bit fixed point number with the binary
        point at the left edge
    '''
    def lost_fraction(self):
        expected = self.expected()
        expected_interval = expected - self.expected_prior
        self.expected_prior = expected

        received_interval = self.received - self.received_prior
        self.received_prior = self.received

        lost_interval = expected_interval - received_interval
        if expected_interval == 0 or lost_interval <= 0:
            return 0
        else:
            return ((lost_interval << 8) / expected_interval) & 0xFF


