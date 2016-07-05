
RTP_VERSION = 2

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
        self.field_byte_1   = 0
        self.field_byte_2   = 0
        self.field_ushort_3  = 0
        self.field_uint_4       = 0
        self.field_uint_5       = 0
        self.field_uints_6      = []

        self.version    = 0
        self.padding    = 0
        self.ext        = 0
        self.cc         = 0
        self.marker     = 0
        self.paytype    = 0
        self.seq        = 0
        self.timestamp  = 0
        self.ssrc       = 0
        self.csrc       = []

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
        return (self.field_byte_1 & 0xF)
    @cc.setter
    def cc(self,c):
        self.field_byte_1 = (self.field_byte_1 & 0xF0) | ( c & 0xF )

class RtcpCommonHeader:
    def __init__(self):
        self.version    = 0
        self.padding    = 0
        self.count      = 0
        self.paytype    = 0
        self.length     = 0

class RtcpReceiverItem:
    def __init__(self):
        self.ssrc       = 0     # data source being reported
        self.fraction   = 0     # fraction lost since last SR/RR
        self.lost       = 0     # cumul. no. pkts lost (signed!)
        self.last_seq   = 0     # extended last seq. no. received
        self.jitter     = 0     # 
        self.lsr        = 0     # last SR packet from this source
        self.dlsr       = 0     # delay since last SR packet

class RtcpReceiverReport:
    def __init__(self):
        self.ssrc       = 0     # receiver generating this report
        self.reports    = []    # list of RtcpReceiverItem

class RtcpSenderReport:
    def __init__(self):
        self.ssrc       = 0     # sender generating this report
        self.ntp_sec    = 0     # NTP timestamp
        self.ntp_frac   = 0
        self.rtp_ts     = 0     # RTP timestamp
        self.psent      = 0     # packets sent
        self.osent      = 0     # octets send
        self.rr         = []    # list of RtcpReceiverReport

class RtcpSdesItem:
    def __init__(self):
        self._type      = 0
        self.length     = 0
        self.data       = ''    # text,not null-terminated

class RtcpSdes:
    def __init__(self):
        self.src        = 0     # first SSRC/CSRC
        self.item       = []    # list of RtcpSDESItem

class RtcpBye:
    def __init__(self):
        self.src        = []    # list of sources

class Rtcp:
    def __init__(self):
        self.common =       RtcpCommonHeader()
        self.report =       None        # sender/receiver/sdes/byte 
