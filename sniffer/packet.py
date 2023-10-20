class PacketHeader:
    def __init__(self, version, ihl, dscp, ecn, total_length, id, flags, fragment_offset, ttl, protocol, checksum, src_ip, dest_ip):
        self.Version = version
        self.InternetHeaderLength = ihl
        self.Dscp = dscp
        self.Ecn = ecn
        self.TotalLength = total_length
        self.Identification = id
        self.Flags = flags
        self.FragmentOffset = fragment_offset
        self.TimeToLive = ttl
        
        if protocol == 1:
            self.Protocol = "ICMP"
        elif protocol == 6:
            self.Protocol = "TCP"
        elif protocol == 17:
            self.Protocol = "UDP"
        else:
            self.Protocol = protocol

        self.HeaderChecksum = checksum
        self.SourceIP = src_ip
        self.DestinationIP = dest_ip

class Packet:
    def __init__(self, packetHeader, segment):
        self.PacketHeader = packetHeader
        self.EncapsulatedSegment = segment