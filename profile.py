
class PAYLOAD_TYPE:
    PAYLOAD_AUDIO_CONTINUOUS    = 0
    PAYLOAD_AUDIO_PACKETIZED    = 1
    PAYLOAD_VIDEO               = 2
    PAYLOAD_TEXT                = 3
    PAYLOAD_OTHER               = 4 # looks like useless

class Profile:
    def __init__(self):
        self.mime_type          = ''        # ex: pcm evrc-8k g711.1
        self.payload_type       = PAYLOAD_TYPE.PAYLOAD_AUDIO_CONTINUOUS

        '''
            bytes_per_frame = (samples_per_frame * bits_per_sampe + 7) / 8
            frames_per_second = clock_rate * channels / samples_per_frame
            payload_bitrate = clock_rate * channels * bits_per_sampe
        '''
        self.clock_rate         = 0         # rtp clock rate
        self.samples_per_frame  = 0         # num samples of frame
        self.channels           = 1         # number of channels of audio
        self.bits_per_sampe     = 0         # in case of continuous audio data

        self.frames_per_packet_hint = 1     # number frame per rtp packet hint
        self.auto_adjust_sent_rate = False  # if allow auto change sent rate
        self.zero_pattern       = None      # silence frame

    @property
    def bytes_per_frame(self):
        return int((self.samples_per_frame * self.bits_per_sampe + 7) / 8)

    @property
    def frames_per_second(self):
        return self.clock_rate * self.channels / self.samples_per_frame

    @property
    def payload_bitrate(self):
        return self.clock_rate * self.channels * self.bits_per_sampe

    def zeroFrame(self):
        if self.zero_pattern is None:
            self.zero_pattern = bytearray(bytes_per_frame)
        return self.zero_pattern

    '''
    Input:
        frames: a list of bytes

    Output:
        return: bytes or bytearray
    '''
    def pack(self,frames):
        raise NotImplementedError()

    '''
    Input:
        packet: payload (not include rtp header) bytes or bytearray
    Output:
        frames: a list of bytes or bytearray
    '''
    def unpack(self,packet):
        raise NotImplementedError()

