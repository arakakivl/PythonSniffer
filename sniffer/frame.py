from json import JSONEncoder

class FrameHeader:
    def __init__(self, dest_addr, src_addr, eth_type):
        self.DestinationMacAddress = dest_addr
        self.SourceMacAddress = src_addr
        self.EthernetType = eth_type

class Frame:
    def __init__(self, frameHeader, packet):
        self.FrameHeader = frameHeader
        self.EncapsulatedPacket = packet

class FrameEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__