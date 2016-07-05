import struct

RTP_VERSION = 2
RTP_SEQ_MOD = (1 << 16)
RTP_MAX_SDES = 255

MAX_DROPOUT = 3000
MAX_MISORDER = 100
MIN_SEQUENTIAL = 2

class RTCP_TYPE:
    RTCP_SR         = 200
    RTCP_RR         = 201
    RTCP_SDES       = 202
    RTCP_BYTE       = 203
    RTCP_APP        = 204

class RTCP_SDES_TYPE:
    RTCP_SDES_END   = 0
    RTCP_SDES_CNAME = 1
    RTCP_SDES_NAME  = 2
    RTCP_SDES_EMAIL = 3
    RTCP_SDES_PHONE = 4
    RTCP_SDES_LOC   = 5
    RTCP_SDES_TOOL  = 6
    RTCP_SDES_NOTE  = 7
    RTCP_SDES_PRIV  = 8

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


class RtcpCommonHeader:
    def __init__(self):
        self.field_byte_1       = 0
        self.field_byte_2       = 0
        self.field_uint16_3     = 0

    '''
       The following checks should be applied to RTCP packets.

       .  RTP version field must equal 2.

       .  The payload type field of the first RTCP packet in a compound
          packet must be equal to SR or RR.

       .  The padding bit (P) should be zero for the first packet of a
          compound RTCP packet because padding should only be applied, if it
          is needed, to the last packet.

       .  The length fields of the individual RTCP packets must add up to
          the overall length of the compound RTCP packet as received.  This
          is a fairly strong check. 
    '''
    @staticmethod
    def validity(buf):
        RTCP_VALID_MASK = (0xc000 | 0x2000 | 0xfe)
        RTCP_VALID_VALUE = ((RTP_VERSION << 14) | RTCP_TYPE.RTCP_SR)

        if len(buf) < 20: ##TODO 20 maybe wrong
            return False

        if (buf[0] & 0xe0) != 0xC0 or (buf[1] & 0xFE) != 200:
            return False
        offset = 0
        while offset < len(buf):
            if 2 != ((buf[offset] >> 6) & 0x3):
                return False
            length = int(buf[offset + 2]) << 8 | buf[offset + 3]
            offset += length
        if offset != len(buf)
            return False
        return True

    def toByteArray(self):
        return bytearray(struct.pack('!BBH',self.field_byte_1,self.field_byte_2,self.field_uint16_3))

    '''protocol version'''
    @property
    def version(self):
        return (self.field_byte_1 >> 6) & 0x3
    @version.setter
    def version(self,v):
        self.field_byte_1 = (self.field_byte_1 & 0x3F) | ( (v & 0x3) << 6 )

    '''padding flag'''
    @property
    def padding(self):
        return (self.field_byte_1 >> 5) & 0x1
    @padding.setter
    def padding(self,p):
        self.field_byte_1 = (self.field_byte_1 & 0xBF) | ( (p & 0x1) << 5 )

    '''varies by packet type'''
    @property
    def count(self):
        return (self.field_byte_1 & 0x1F)
    @count.setter
    def count(self,c):
        self.field_byte_1 = (self.field_byte_1 & 0xE0) | ( c & 0x1F )

    '''RTCP packet type'''
    @property
    def packet_type(self):
        return (self.field_byte_2 & 0xFF)
    @packet_type.setter
    def packet_type(self,p):
        self.field_byte_2 = (p & 0xFF)

    '''pkt len in words, w/o this word'''
    @property
    def length(self):
        return (self.field_uint16_3 & 0xFFFF)
    @length.setter
    def length(self,l):
        self.field_uint16_3 = (l & 0xFFFF)



class RtcpReceiverItem:
    def __init__(self):
        self.field_uint32_1         = 0
        self.field_uint32_2         = 0
        self.field_uint32_3         = 0
        self.field_uint32_4         = 0
        self.field_uint32_5         = 0
        self.field_uint32_6         = 0

    def toByteArray(self):
        return bytearray(struct.pack('!IIIIII',self.field_uint32_1,self.field_uint32_2,self.field_uint32_3,self.field_uint32_4,self.field_uint32_5,self.field_uint32_6))
    
    '''data source being reported'''
    @property
    def ssrc(self):
        return self.field_uint32_1 & 0xFFFFFFFF
    @ssrc.setter
    def ssrc(self,v):
        self.field_uint32_1 = (v & 0xFFFFFFFF)

    '''fraction lost since last SR/RR'''
    @property
    def fraction(self):
        return ((self.field_uint32_2 >> 24) & 0xFF)
    @fraction.setter
    def fraction(self,f):
        self.field_uint32_2 = (self.field_uint32_2 & 0x0FFFFFFF) | ( (f & 0xFF) << 24 )
    
    '''cumul. no. pkts lost (signed!)'''
    @property
    def lost(self):
        v = (self.field_uint32_2 & 0x00FFFFFF)
        if v & 0x800000 == 1:   # negative
            v = ~((v & 0x7FFFFF) - 1)
            v = -v
        return v

    @lost.setter(self,v):
        if v < 0:
            v = (((~(v & 0x7FFFFF)) + 1) & 0x7FFFFF) | 0x800000
        self.field_uint32_2 = (self.field_uint32_2 & 0xFF000000) | (v & 0x00FFFFFF)

    '''extended last seq. no. received'''
    @property
    def last_seq(self):
        return self.field_uint32_3 & 0xFFFFFFFF
    @last_seq.setter
    @def last_seq(self,v):
        self.field_uint32_3 = (v & 0xFFFFFFFF)

    '''interarrival jitter'''
    @property
    def jitter(self):
        return self.field_uint32_4 & 0xFFFFFFFF
    @jitter.setter
    @def jitter(self,v):
        self.field_uint32_4 = (v & 0xFFFFFFFF)

    '''last SR packet from this source'''
    @property
    def lsr(self):
        return self.field_uint32_5 & 0xFFFFFFFF
    @lsr.setter
    @def lsr(self,v):
        self.field_uint32_5 = (v & 0xFFFFFFFF)

    '''delay since last SR packet'''
    @property
    def dlsr(self):
        return self.field_uint32_6 & 0xFFFFFFFF
    @dlsr.setter
    @def dlsr(self,v):
        self.field_uint32_6 = (v & 0xFFFFFFFF)




class RtcpReceiverReport:
    def __init__(self):
        self.field_uint32_1     = 0
        self.field_list_2       = []

    def toByteArray(self):
        buf = bytearray(struct.pack('!I',self.field_uint32_1))
        for r in self.field_list_2:
            if not isinstance(r,RtcpReceiverItem):
                raise TypeError('RtcpReceiverReport reports list item MUST be RtcpReceiverItem')
            buf.append(r.toByteArray())
        return buf

    '''receiver generating this report'''
    @property
    def ssrc(self):
        return (self.field_uint32_1 & 0xFFFFFFFF)
    @ssrc.setter(self,v):
        self.field_uint32_1 = (v & 0xFFFFFFFF)

    '''list of RtcpReceiverItem'''
    @property
    def reports(self):
        return self.field_list_2
    @reports.setter
    def reports(self,l):
        self.field_list_2 = l

class RtcpSenderReport:
    def __init__(self):
        self.field_uint32_1     = 0
        self.field_uint32_2     = 0
        self.field_uint32_3     = 0
        self.field_uint32_4     = 0
        self.field_uint32_5     = 0
        self.field_uint32_6     = 0
        self.field_list_7       = []

    def toByteArray(self):
        buf = bytearray(struct.pack('!IIIIII',self.field_uint32_1,self.field_uint32_2,self.field_uint32_3,self.field_uint32_4,self.field_uint32_5,self.field_uint32_6))
        for r in self.field_list_7:
            if not isinstance(r,RtcpReceiverItem):
                raise TypeError('RtcpSenderReport rr list item MUST be RtcpReceiverItem')
            buf.append(r.toByteArray())
        return buf

    '''sender generating this report'''
    @property
    def ssrc(self):
        return self.field_uint32_1
    @ssrc.setter
    def ssrc(self,v):
        self.field_uint32_1 = (v & 0xFFFFFFFF)

    '''NTP timestamp (second part)'''
    @property
    def ntp_sec(self):
        return self.field_uint32_2
    @ntp_sec.setter
    def ntp_sec(self,v):
        self.field_uint32_2 = (v & 0xFFFFFFFF)

    '''NTP timestamp (fraction part)'''
    @property
    def ntp_frac(self):
        return self.field_uint32_3
    @ntp_frac.setter
    def ntp_frac(self,v):
        self.field_uint32_3 = (v & 0xFFFFFFFF)

    '''RTP timestamp'''
    @property
    def rtp_ts(self):
        return self.field_uint32_4
    @rtp_ts.setter
    def rtp_ts(self,v):
        self.field_uint32_4 = (v & 0xFFFFFFFF)

    '''packet sent'''
    @property
    def psent(self):
        return self.field_uint32_5
    @psent.setter
    def psent(self,v):
        self.field_uint32_5 = (v & 0xFFFFFFFF)

    '''octets sent'''
    @property
    def osent(self):
        return self.field_uint32_6
    @osent.setter
    def osent(self,v):
        self.field_uint32_6 = (v & 0xFFFFFFFF)

    '''list of RtcpReceiverReport'''
    @property
    def rr(self):
        return self.field_list_7
    @rr.setter
    def rr(self,l):
        self.field_list_7 = l

class RtcpSdesItem:
    def __init__(self):
        self.field_uint8_1      = 0
        self.field_uint8_2      = 0
        self.field_bytes_3      = None

    def toByteArray(self):
        buf = bytearray(struct.pack('!BB',self.field_uint8_1,self.field_uint8_2))
        if self.field_bytes_3 is not None:
            buf.append(self.field_bytes_3)
        return buf
    @property
    def sdes_type(self):
        return self.field_uint8_1
    @sdes_type.setter
    def sdes_type(self,v):
        self.field_uint8_1 = (v & 0xFF)

    @property
    def length(self):
        return self.field_uint8_2

    '''text,not null-terminated'''
    @property
    @def data(self):
        if self.field_bytes_3 is None:
            return ''
        else:
            return self.field_bytes_3.decode('utf-8')
    @data.setter
    def data(self,s):
        if s is None:
            self.field_bytes_3 = None
            self.field_uint8_2 = 0
        elif isinstance(s,str):
            self.field_bytes_3 = bytes(s)
            if len(self.field_bytes_3) > RTP_MAX_SDES:
                self.field_bytes_3 = self.field_bytes_3[:RTP_MAX_SDES]
            self.field_uint8_2 = len(self.field_bytes_3)
        elif isinstance(s,bytes):
            self.field_bytes_3 = s
            if len(self.field_bytes_3) > RTP_MAX_SDES:
                self.field_bytes_3 = self.field_bytes_3[:RTP_MAX_SDES]
            self.field_uint8_2 = len(self.field_bytes_3)

class RtcpSdes:
    def __init__(self):
        self.field_uint32_1         = 0
        self.field_list_2           = []

    def toByteArray(self):
        buf = bytearray(struct.pack('!I',self.field_uint32_1))
        for v in self.field_list_2:
            if not isinstance(v,RtcpSdesItem):
                raise TypeError('Sdes item MUST be RtcpSdesItem')
            buf.append(v.toByteArray())
        # terminate with end marker and pad to next 4-octet boundary
        pad = 4 - (len(buf) & 0x3)
        while pad > 0:
            buf.append(RTCP_SDES_TYPE.RTCP_SDES_END)
            pad -= 1
        return buf

    '''first SSRC/CSRC'''
    @property
    def src(self):
        return self.field_uint32_1
    @src.setter
    def src(self,s):
        self.field_uint32_1 = (s & 0xFFFFFFFF)

    '''list of RtcpSdesItem'''
    @property
    def item(self):
        return self.field_list_2
    @item.setter
    def item(self,l):
        self.field_list_2 = l

class RtcpBye:
    def __init__(self):
        self.src        = []    # list of sources

    def toByteArray(self):
        if len(self.src) == 0:
            raise ValueError('RtcpBye atleast contains one source')
        buf = bytearray()
        for v in self.src:
            if not isinstance(v,int):
                raise TypeError('src must be uint32 number')
            buf.append(struct.pack('!I',v))
        return buf

class Rtcp:
    def __init__(self):
        self.header =       RtcpCommonHeader()
        self.report =       None        # sender/receiver/sdes/byte 

    def toByteArray(self):
        if self.report is None:
            raise ValueError('Rtcp must has one report')
        buf = self.header.toByteArray()
        buf.append(self.report.toByteArray())
        return buf


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
