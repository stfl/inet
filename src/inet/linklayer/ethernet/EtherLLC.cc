/*
 * Copyright (C) 2003 Andras Varga; CTIE, Monash University, Australia
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "inet/linklayer/ethernet/EtherLLC.h"

#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/linklayer/ethernet/Ethernet.h"
#include "inet/linklayer/ethernet/EtherEncap.h"
#include "inet/linklayer/common/Ieee802Ctrl.h"
#include "inet/linklayer/common/Ieee802SapTag_m.h"
#include "inet/linklayer/common/MACAddressTag_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/lifecycle/NodeOperations.h"

namespace inet {

Define_Module(EtherLLC);

simsignal_t EtherLLC::dsapSignal = registerSignal("dsap");
simsignal_t EtherLLC::encapPkSignal = registerSignal("encapPk");
simsignal_t EtherLLC::decapPkSignal = registerSignal("decapPk");
simsignal_t EtherLLC::passedUpPkSignal = registerSignal("passedUpPk");
simsignal_t EtherLLC::droppedPkUnknownDSAPSignal = registerSignal("droppedPkUnknownDSAP");
simsignal_t EtherLLC::pauseSentSignal = registerSignal("pauseSent");

void EtherLLC::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        seqNum = 0;
        WATCH(seqNum);

        dsapsRegistered = totalFromHigherLayer = totalFromMAC = totalPassedUp = droppedUnknownDSAP = 0;

        WATCH(dsapsRegistered);
        WATCH(totalFromHigherLayer);
        WATCH(totalFromMAC);
        WATCH(totalPassedUp);
        WATCH(droppedUnknownDSAP);
    }
    else if (stage == INITSTAGE_LINK_LAYER) {
        // lifecycle
        NodeStatus *nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));
        isUp = !nodeStatus || nodeStatus->getState() == NodeStatus::UP;
        if (isUp)
            start();
    }
}

void EtherLLC::handleMessage(cMessage *msg)
{
    if (!isUp) {
        EV << "EtherLLC is down -- discarding message\n";
        delete msg;
        return;
    }

    if (msg->arrivedOn("lowerLayerIn")) {
        // frame received from lower layer
        processFrameFromMAC(check_and_cast<Packet *>(msg));
    }
    else {
        switch (msg->getKind()) {
            case IEEE802CTRL_DATA:
                // data received from higher layer
                processPacketFromHigherLayer(check_and_cast<Packet *>(msg));
                break;

            case IEEE802CTRL_REGISTER_DSAP:
                // higher layer registers itself
                handleRegisterSAP(msg);
                break;

            case IEEE802CTRL_DEREGISTER_DSAP:
                // higher layer deregisters itself
                handleDeregisterSAP(msg);
                break;

            case IEEE802CTRL_SENDPAUSE:
                // higher layer want MAC to send PAUSE frame
                handleSendPause(msg);
                break;

            default:
                throw cRuntimeError("Received message `%s' with unknown message kind %d",
                    msg->getName(), msg->getKind());
        }
    }
}

void EtherLLC::refreshDisplay() const
{
    char buf[80];
    sprintf(buf, "passed up: %ld\nsent: %ld", totalPassedUp, totalFromHigherLayer);

    if (droppedUnknownDSAP > 0) {
        sprintf(buf + strlen(buf), "\ndropped (wrong DSAP): %ld", droppedUnknownDSAP);
    }

    getDisplayString().setTagArg("t", 0, buf);
}

void EtherLLC::processPacketFromHigherLayer(Packet *packet)
{
    if (packet->getByteLength() > (MAX_ETHERNET_DATA_BYTES - ETHER_LLC_HEADER_LENGTH))
        throw cRuntimeError("packet from higher layer (%d bytes) plus LLC header exceeds maximum Ethernet payload length (%d)", (int)(packet->getByteLength()), MAX_ETHERNET_DATA_BYTES);

    totalFromHigherLayer++;
    emit(encapPkSignal, packet);

    // Creates MAC header information and encapsulates received higher layer data
    // with this information and transmits resultant frame to lower layer

    // create Ethernet frame, fill it in from Ieee802Ctrl and encapsulate msg in it
    EV << "Encapsulating higher layer packet `" << packet->getName() << "' for MAC\n";
    EV << "Sent from " << getSimulation()->getModule(packet->getSenderModuleId())->getFullPath() << " at " << packet->getSendingTime() << " and was created " << packet->getCreationTime() << "\n";

    auto ieee802SapReq = packet->getMandatoryTag<Ieee802SapReq>();

    const auto& frame = std::make_shared<EtherFrameWithLLC>();

    frame->setPayloadLength(packet->getByteLength());
    frame->setControl(0);
    frame->setSsap(ieee802SapReq->getSsap());
    frame->setDsap(ieee802SapReq->getDsap());
    frame->setDest(packet->getMandatoryTag<MacAddressReq>()->getDestAddress());    // src address is filled in by MAC
    frame->markImmutable();
    packet->pushHeader(frame);

    EtherEncap::addPaddingAndFcs(packet);

    send(packet, "lowerLayerOut");
}

void EtherLLC::processFrameFromMAC(Packet *packet)
{
    // decapsulate it and pass up to higher layer
    const auto& ethHeader = EtherEncap::decapsulate(packet);


    EtherFrameWithLLC *frame = dynamic_cast<EtherFrameWithLLC *>(ethHeader.get());
    if (frame == nullptr) {
        EV << "Incoming packet does not have an LLC ethernet header, dropped. Header is " << (ethHeader ? ethHeader->getClassName() : "nullptr") << "\n";
        delete packet;
        return;
    }
    // check SAP
    int sap = frame->getDsap();
    int port = findPortForSAP(sap);
    if (port < 0) {
        EV << "No higher layer registered for DSAP=" << sap << ", discarding frame `" << packet->getName() << "'\n";
        droppedUnknownDSAP++;
        emit(droppedPkUnknownDSAPSignal, packet);
        delete packet;
        return;
    }

    auto macaddressInd = packet->ensureTag<MacAddressInd>();
    macaddressInd->setSrcAddress(frame->getSrc());
    macaddressInd->setDestAddress(frame->getDest());
    auto ieee802SapInd = packet->ensureTag<Ieee802SapInd>();
    ieee802SapInd->setSsap(frame->getSsap());
    ieee802SapInd->setDsap(frame->getDsap());

    EV << "Decapsulating frame `" << packet->getName() << "', "
            "passing up contained packet `" << packet->getName() << "' to higher layer " << port << "\n";       //FIXME packet name printed twice

    totalFromMAC++;
    emit(decapPkSignal, packet);

    // pass up to higher layer
    totalPassedUp++;
    emit(passedUpPkSignal, packet);
    send(packet, "upperLayerOut", port);
}

int EtherLLC::findPortForSAP(int dsap)
{
    auto it = dsapToPort.find(dsap);
    return (it == dsapToPort.end()) ? -1 : it->second;
}

void EtherLLC::handleRegisterSAP(cMessage *msg)
{
    int port = msg->getArrivalGate()->getIndex();
    Ieee802RegisterDsapCommand *etherctrl = dynamic_cast<Ieee802RegisterDsapCommand *>(msg->getControlInfo());
    if (!etherctrl)
        throw cRuntimeError("packet `%s' from higher layer received without Ieee802Ctrl", msg->getName());
    int dsap = etherctrl->getDsap();

    EV << "Registering higher layer with DSAP=" << dsap << " on port=" << port << "\n";

    if (dsapToPort.find(dsap) != dsapToPort.end())
        throw cRuntimeError("DSAP=%d already registered with port=%d", dsap, dsapToPort[dsap]);

    dsapToPort[dsap] = port;
    dsapsRegistered = dsapToPort.size();
    emit(dsapSignal, 1L);
    delete msg;
}

void EtherLLC::handleDeregisterSAP(cMessage *msg)
{
    Ieee802DeregisterDsapCommand *etherctrl = dynamic_cast<Ieee802DeregisterDsapCommand *>(msg->getControlInfo());
    if (!etherctrl)
        throw cRuntimeError("packet `%s' from higher layer received without Ieee802Ctrl", msg->getName());
    int dsap = etherctrl->getDsap();

    EV << "Deregistering higher layer with DSAP=" << dsap << "\n";

    if (dsapToPort.find(dsap) == dsapToPort.end())
        throw cRuntimeError("DSAP=%d not registered with port=%d", dsap, dsapToPort[dsap]);

    // delete from table (don't care if it's not in there)
    dsapToPort.erase(dsapToPort.find(dsap));
    dsapsRegistered = dsapToPort.size();
    emit(dsapSignal, -1L);
    delete msg;
}

void EtherLLC::handleSendPause(cMessage *msg)
{
    Ieee802PauseCommand *etherctrl = dynamic_cast<Ieee802PauseCommand *>(msg->getControlInfo());
    if (!etherctrl)
        throw cRuntimeError("PAUSE command `%s' from higher layer received without Ieee802Ctrl", msg->getName());

    MACAddress dest = etherctrl->getDestinationAddress();
    int pauseUnits = etherctrl->getPauseUnits();
    EV << "Creating and sending PAUSE frame, with duration=" << pauseUnits << " units\n";

    // create Ethernet frame
    char framename[40];
    sprintf(framename, "pause-%d-%d", getId(), seqNum++);
    Packet *packet = new Packet(framename);
    const auto& frame = std::make_shared<EtherPauseFrame>();
    frame->setPauseTime(pauseUnits);
    if (dest.isUnspecified())
        dest = MACAddress::MULTICAST_PAUSE_ADDRESS;
    frame->setDest(dest);
    packet->pushHeader(frame);

    EtherEncap::addPaddingAndFcs(packet);

    send(packet, "lowerLayerOut");
    emit(pauseSentSignal, pauseUnits);

    delete msg;
}

bool EtherLLC::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if ((NodeStartOperation::Stage)stage == NodeStartOperation::STAGE_NETWORK_LAYER)
            start();
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if ((NodeShutdownOperation::Stage)stage == NodeShutdownOperation::STAGE_NETWORK_LAYER)
            stop();
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if ((NodeCrashOperation::Stage)stage == NodeCrashOperation::STAGE_CRASH)
            stop();
    }
    return true;
}

void EtherLLC::start()
{
    dsapToPort.clear();
    dsapsRegistered = dsapToPort.size();
    isUp = true;
}

void EtherLLC::stop()
{
    dsapToPort.clear();
    dsapsRegistered = dsapToPort.size();
    isUp = false;
}

} // namespace inet

