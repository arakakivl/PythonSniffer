class IcmpSegment:
    def __init__(self, type, code, checksum, data):
        self.Type = type
        self.Code = code
        self.Checksum = checksum
        self.Data = data

class TcpSegment:
    def __init__(self, source_port, dest_port, seq, ack, data_offset, data):
        self.SourcePort = source_port
        self.DestinationPort = dest_port
        self.SequenceNumber = seq
        self.AcknowledgmentNumber = ack
        self.DataOffset = data_offset
        self.Data = data


class UdpSegment:
    def __init__(self, source_port, dest_port, length, checksum, data):
        self.SourcePort = source_port
        self.DestinationPort = dest_port
        self.Length = length
        self.Checksum = checksum
        self.Data = data