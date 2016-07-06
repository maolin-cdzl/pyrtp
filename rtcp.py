import struct
import random

RTP_MAX_SDES = 255

class RTCP_TYPE:
    RTCP_SR         = 200
    RTCP_RR         = 201
    RTCP_SDES       = 202
    RTCP_BYE        = 203
    RTCP_APP        = 204

    EVENT_BYE       = 0
    EVENT_REPORT    = 1
    
    @staticmethod
    def TypeOfEvent(t):
        if RTCP_TYPE.RTCP_BYE == t:
            return RTCP_TYPE.EVENT_BYE
        else:
            return RTCP_TYPE.EVENT_REPORT

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


'''
    Minimum average time between RTCP packets from this site (in
    seconds).  This time prevents the reports from `clumping' when
    sessions are small and the law of large numbers isn't helping
    to smooth out the traffic.  It also keeps the report interval
    from becoming ridiculously small during transient outages like
    a network partition.
'''
RTCP_MIN_TIME = 5.0

''' 
    Fraction of the RTCP bandwidth to be shared among active
    senders.  (This fraction was chosen so that in a typical
    session with one or two active senders, the computed report
    time would be roughly equal to the minimum report time so that
    we don't unnecessarily slow down receiver reports.)  The
    receiver fraction must be 1 - the sender fraction.
'''
RTCP_SENDER_BW_FRACTION = 0.25
RTCP_RCVR_BW_FRACTION = (1-RTCP_SENDER_BW_FRACTION)

'''
To compensate for "timer reconsideration" converging to a
value below the intended average.
'''
COMPENSATION = 2.71828 - 1.5

SESSION_BANDWIDTH = 20.0      # kilobits/second

class Rtcp:
    def __init__(self,bandwidth):
        self.we_ssrc = random.randint(1,0xFFFFFFFF)
        self.initial = True
        self.we_sent = False
        self.bandwidth = bandwidth
        self.rtcp_bw = bandwidth * 6.25   # bandwidth (kb/s) * 1000 / 8 => bandwidth(B/s) * 5%

        #(360.0 / SESSION_BANDWIDTH) * 1000.0 / 8.0
                                        # The target RTCP bandwidth, i.e., the total bandwidth
                                        # that will be used for RTCP packets by all members of this session,
                                        # in octets per second.  This will be a specified fraction of the
                                        # "session bandwidth" parameter supplied to the application at startup.
        self.avg_rtcp_size = 28 + 20
        self.tp = 0                     # the last time an RTCP packet was transmitted
        self.tn = 0                     # the next scheduled transmission time of an RTCP packet
        self.tc = 0                     # the current time
        self.pmembers = 1               # the estimated number of session members at the time tn was last recomputed
        self.members = 1                # the most current estimate for the number of session members
        self.senders = 0                # the most current estimate for the number of senders in the session
        self.member_list = set([self.we_ssrc])
        self.sender_list = set()

        self.Schedule(RTCP_TYPE.RTCP_RR)

    # TODO: need update. this is for multicast algorithm. eChat is unicast.
    def rtcp_interval(self):
        rtcp_min_time = RTCP_MIN_TIME

        '''
            Very first call at application start-up uses half the min
            delay for quicker notification while still allowing some time
            before reporting for randomization and to learn about other
            sources so the report interval will converge to the correct
            interval more quickly.
        '''
        if self.initial:
            rtcp_min_time /= 2

        '''
            Dedicate a fraction of the RTCP bandwidth to senders unless
            the number of senders is large enough that their share is
            more than that fraction.
        '''
        n = self.member_count
        rtcp_bw = self.rtcp_bw
        if self.sender_count <= self.member_count * RTCP_SENDER_BW_FRACTION:
            if self.we_sent:
                rtcp_bw *= RTCP_SENDER_BW_FRACTION
                n = self.sender_count
            else:
                rtcp_bw *= RTCP_RCVR_BW_FRACTION
                n -= self.sender_count

        '''
            The effective number of sites times the average packet size is
            the total number of octets sent when each site sends a report.
            Dividing this by the effective bandwidth gives the time
            interval over which those packets must be sent in order to
            meet the bandwidth target, with a minimum enforced.  In that
            time interval we send one report so this time is also our
            average time between reports.
        '''

        t = self.avg_rtcp_size * n / rtcp_bw
        if t < rtcp_min_time:
            t = rtcp_min_time

        '''
            To avoid traffic bursts from unintended synchronization with
            other sites, we then pick our actual next report interval as a
            random number uniformly distributed between 0.5*t and 1.5*t.
        '''
        t = t * random.uniform(0.5,1.5)
        t = t / COMPENSATION
        return t

    '''
        This function is responsible for deciding whether to send an
        RTCP report or BYE packet now, or to reschedule transmission.
        It is also responsible for updating the pmembers, initial, tp,
        and avg_rtcp_size state variables.  This function should be
        called upon expiration of the event timer used by Schedule().
    '''
    def onExpire(self,e):
        if RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_BYE:
            t = self.rtcp_interval()
            tn = self.tp + t
            if tn <= self.tc:
                # stream close
                self.SendByePacket(e)
                return
            else:
                self.Schedule(tn,e)
        elif RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_REPORT:
            t = self.rtcp_interval()
            tn = self.tp + t
            if tn <= self.tc:
                self.SendRTCPReport(e)
                self.avg_rtcp_size = (1.0/16.0) * self.SentPacketSize(e) + (15.0/16.0) * self.avg_rtcp_size
                self.tp = self.tc
                t = self.rtcp_interval()
                self.Schedule(t + self.tc,e)
                self.initial = False
            else:
                self.Schedule(tn,e)
            self.pmembers = self.member_count

    def onReceive(self,packet,e):
        '''
            What we do depends on whether we have left the group, and are
            waiting to send a BYE (TypeOfEvent(e) == EVENT_BYE) or an RTCP
            report.  packet represents the packet that was just received.
        '''
        if PacketType(packet) == PACKET_RTCP_REPORT:
            if self.NewMember(packet) and RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_REPORT:
                self.AddMember(packet)
                self.members += 1
            self.avg_rtcp_size = (1.0/16.0) * ReceivedPacketSize(packet) + (15.0/16.0) * self.avg_rtcp_size
        elif PacketType(packet) == PACKET_RTP:
            if self.NewMember(packet) and RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_REPORT:
                self.AddMember(packet)
                self.members += 1
            if self.NewSender(packet) and RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_REPORT:
                self.AddSender(packet)
                self.senders += 1
        elif PacketType(packet) == PACKET_BYE:
            self.avg_rtcp_size = (1.0/16.0) * ReceivedPacketSize(packet) + (15.0/16.0) * self.avg_rtcp_size
            if RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_REPORT:
                if not self.NewSender(packet):
                    self.RemoveSender(packet)
                if not self.NewMember(packet):
                    self.RemoveMember(packet)

                if self.member_count < self.pmembers:
                    tn = self.tc + ( float(self.member_count) / self.pmembers ) * (self.tn - self.tc)
                    self.tp = self.tc - ( float(self.member_count) / self.pmembers ) * (self.tc - self.tp)
                    self.Reschedule(tn,e)
                    self.pmembers = self.member_count
            elif RTCP_TYPE.TypeOfEvent(e) == RTCP_TYPE.EVENT_BYE:
                self.member_count += 1

    def NewMember(self,m):
        return m.ssrc in self.member_list

    def AddMember(self,m):
        self.members_list.add( m.ssrc )

    def RemoveMember(self,m):
        self.members_list.remove(m.ssrc)

    def NewSender(self,m):
        return m.ssrc in self.sender_list

    def AddSender(self,m):
        self.sender_list.add(m.ssrc)

    def RemoveSender(self,m):
        self.sender_list.remove(m.ssrc)

    def Schedule(self,tn,e):
        self.tn = tn
        pass

    def Reschedule(self,tn,e):
        self.tn = tn
        pass

    def SendByePacket(self):
        pass
    def SendRTCPReport(self,e):
        pass


