
'''
    callback method: callback(packet)
'''
class Transport:
    def __init__(self):
        self._callback = None

    def send(self,packet):
        raise NotImplementedError('Transport send method not implement')

    def readable(self,callback):
        self._callback = callback
