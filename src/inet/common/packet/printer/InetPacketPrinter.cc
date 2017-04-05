//
// Copyright (C) 2014 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/common/INETDefs.h"

#include "inet/networklayer/common/L3Address.h"
#include "inet/networklayer/contract/INetworkHeader.h"
#include "inet/applications/pingapp/PingPayload_m.h"

#ifdef WITH_IPv4
#include "inet/networklayer/ipv4/ICMPHeader.h"
#include "inet/networklayer/ipv4/IPv4Header.h"
#endif // ifdef WITH_IPv4

#ifdef WITH_TCP_COMMON
#include "inet/transportlayer/tcp_common/TCPSegment.h"
#endif // ifdef WITH_TCP_COMMON

#ifdef WITH_UDP
#include "inet/transportlayer/udp/UdpHeader.h"
#endif // ifdef WITH_UDP

namespace inet {

class INET_API InetPacketPrinter : public cMessagePrinter
{
  protected:
    L3Address srcAddr, destAddr;

  protected:
#ifdef WITH_TCP_COMMON
    void printTCPPacket(std::ostream& os, Packet *packet, const std::shared_ptr<tcp::TcpHeader>& tcpHeader) const;
#endif // ifdef WITH_TCP_COMMON
#ifdef WITH_UDP
    void printUDPPacket(std::ostream& os, Packet *packet, const std::shared_ptr<UdpHeader>& udpHeader) const;
#endif // ifdef WITH_UDP
#ifdef WITH_IPv4
    void printICMPPacket(std::ostream& os, Packet *packet, const std::shared_ptr<ICMPHeader>& icmpHeader) const;
#endif // ifdef WITH_IPv4
    void printChunk(std::ostream& os, Packet *packet, const std::shared_ptr<Chunk>& chunk) const;

  public:
    InetPacketPrinter() {}
    virtual ~InetPacketPrinter() {}
    virtual int getScoreFor(cMessage *msg) const override;
    virtual void printMessage(std::ostream& os, cMessage *msg) const override;
};

Register_MessagePrinter(InetPacketPrinter);

int InetPacketPrinter::getScoreFor(cMessage *msg) const
{
    return (typeid(*msg) == typeid(Packet)) ? 20 : 0;
}

void InetPacketPrinter::printMessage(std::ostream& os, cMessage *msg) const
{
    srcAddr = destAddr = L3Address();

    if (Packet *pk = dynamic_cast<Packet *>(msg)) {
        auto packet = new Packet(pk->peekData());
        while (const auto& chunk = packet->popHeader(bit(-1), Chunk::PF_ALLOW_NULLPTR)) {
            if (const auto& sliceChunk = std::dynamic_pointer_cast<SliceChunk>(chunk)) {
                os << "slice of ????";  //FIXME TODO show the sliced chunk
            }
            else
                printChunk(os, packet, chunk);
        }
    }
    os << "(" << msg->getClassName() << ")" << " id=" << msg->getId() << " kind=" << msg->getKind();
}

void InetPacketPrinter::printChunk(std::ostream& os, Packet *packet, const std::shared_ptr<Chunk>& chunk) const
{
#ifdef WITH_IPv4
    if (const auto& ipv4Header = std::dynamic_pointer_cast<Ipv4Header>(chunk)) {
        if (ipv4Header->getMoreFragments() || ipv4Header->getFragmentOffset() > 0)
            os << (ipv4Header->getMoreFragments() ? "" : "last ")
               << "fragment with offset=" << ipv4Header->getFragmentOffset() << " of ";
    }
    else
#endif    // WITH_IPv4
#ifdef WITH_TCP_COMMON
    if (const auto& tcpHeader = std::dynamic_pointer_cast<tcp::TcpHeader>(chunk)) {
        printTCPPacket(os, packet, tcpHeader);
        return;
    }
    else
#endif // ifdef WITH_TCP_COMMON
#ifdef WITH_UDP
    if (const auto& udpHeader = std::dynamic_pointer_cast<UdpHeader>(chunk)) {
        printUDPPacket(os, packet, udpHeader);
        return;
    }
    else
#endif // ifdef WITH_UDP
#ifdef WITH_IPv4
    if (const auto &icmpHeader = std::dynamic_pointer_cast<ICMPHeader>(chunk)) {
        printICMPPacket(os, packet, icmpHeader);
        return;
    }
    else
#endif // ifdef WITH_IPv4
    {
        os << chunk->getChunkLength() << " " << chunk->getClassName();
    }
}

void InetPacketPrinter::printTCPPacket(std::ostream& os, Packet *packet, const std::shared_ptr<tcp::TcpHeader>& tcpHeader) const
{
#ifdef WITH_TCP_COMMON
    os << " TCP: " << srcAddr << '.' << tcpHeader->getSrcPort() << " > " << destAddr << '.' << tcpHeader->getDestPort() << ": ";
    // flags
    bool flags = false;
    if (tcpHeader->getUrgBit()) { flags = true; os << "U "; }
    if (tcpHeader->getAckBit()) { flags = true; os << "A "; }
    if (tcpHeader->getPshBit()) { flags = true; os << "P "; }
    if (tcpHeader->getRstBit()) { flags = true; os << "R "; }
    if (tcpHeader->getSynBit()) { flags = true; os << "S "; }
    if (tcpHeader->getFinBit()) { flags = true; os << "F "; }
    if (!flags) { os << ". "; }

    // data-seqno
    os << tcpHeader->getSequenceNo() << " ";

    // ack
    if (tcpHeader->getAckBit())
        os << "ack " << tcpHeader->getAckNo() << " ";

    // window
    os << "win " << tcpHeader->getWindow() << " ";

    // urgent
    if (tcpHeader->getUrgBit())
        os << "urg " << tcpHeader->getUrgentPointer() << " ";
#endif // ifdef WITH_TCP_COMMON
}

void InetPacketPrinter::printUDPPacket(std::ostream& os, Packet *packet, const std::shared_ptr<UdpHeader>& udpHeader) const
{
#ifdef WITH_UDP

    os << " UDP: " << srcAddr << '.' << udpHeader->getSourcePort() << " > " << destAddr << '.' << udpHeader->getDestinationPort()
       << ": (" << udpHeader->getTotalLengthField() << ")";
#endif // ifdef WITH_UDP
}

void InetPacketPrinter::printICMPPacket(std::ostream& os, L3Address srcAddr, L3Address destAddr, Packet *packet, ICMPHeader *icmpHeader) const
{
#ifdef WITH_IPv4
    switch (icmpHeader->getType()) {
        case ICMP_ECHO_REQUEST: {
            PingPayload *payload = check_and_cast<PingPayload *>(icmpHeader->getEncapsulatedPacket());
            os << "ping " << srcAddr << " to " << destAddr
               << " (" << icmpHeader->getByteLength() << " bytes) id=" << payload->getId() << " seq=" << payload->getSeqNo();
            break;
        }

        case ICMP_ECHO_REPLY: {
            PingPayload *payload = check_and_cast<PingPayload *>(icmpHeader->getEncapsulatedPacket());
            os << "pong " << srcAddr << " to " << destAddr
               << " (" << packet->getByteLength() << " bytes) id=" << payload->getId() << " seq=" << payload->getSeqNo();
            break;
        }

        case ICMP_DESTINATION_UNREACHABLE:
            os << "ICMP dest unreachable " << srcAddr << " to " << destAddr << " type=" << icmpHeader->getType() << " code=" << icmpHeader->getCode()
               << " origin: ";
            // printMessage(os, icmpHeader->getEncapsulatedPacket());
            break;

        default:
            os << "ICMP " << srcAddr << " to " << destAddr << " type=" << icmpHeader->getType() << " code=" << icmpHeader->getCode();
            break;
    }
#else // ifdef WITH_IPv4
    os << " ICMP: " << srcAddr << " > " << destAddr;
#endif // ifdef WITH_IPv4
}

} // namespace inet

