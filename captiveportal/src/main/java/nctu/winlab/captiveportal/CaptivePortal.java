/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.captiveportal;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Path;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.topology.TopologyService;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;
import java.util.HashMap;
import java.util.Set;

import java.nio.ByteBuffer;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {CaptivePortal.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class CaptivePortal {

    private ApplicationId appId;
    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    /** Configure Flow Timeout for installed flow rules; default is 20 sec.*/
    private int flowTimeout = 20;

    /** Configure Flow Priority for installed flow rules; default is 40001.*/
    private int flowPriority = 40001;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    private HashMap<PortNumber, MacAddress> tempMac;
    private HashMap<PortNumber, Ip4Address> tempIp;
    private HashMap<PortNumber, PortNumber> tempPort;
    private HashMap<MacAddress, HashMap<PortNumber, MacAddress>> macMapping =
        new HashMap<MacAddress, HashMap<PortNumber, MacAddress>>();
    private HashMap<MacAddress, HashMap<PortNumber, Ip4Address>> ipMapping =
        new HashMap<MacAddress, HashMap<PortNumber, Ip4Address>>();
    private HashMap<MacAddress, HashMap<PortNumber, PortNumber>> portMapping =
        new HashMap<MacAddress, HashMap<PortNumber, PortNumber>>();

    private String portalIp = "192.168.44.198";
    private String portalMac = "f6:42:0f:83:51:de";

    private String toPortalSwitch = "of:000078321bdf7000";

    private CaptivePortalUserInfo captivePortalUserInfo;

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            InboundPacket inPkt = context.inPacket();
            Ethernet ethPkt = inPkt.parsed();
            if (ethPkt == null) {
                return;
            }
            if (isControlPacket(ethPkt)) {
                return;
            }
            HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
            if (dstId.mac().isLldp()) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (dstId.mac().isMulticast()) {
                    return;
                }

                MacAddress sourceMac = ethPkt.getSourceMAC();
                MacAddress destinationMac = ethPkt.getDestinationMAC();
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                Ip4Address sourceIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                Ip4Address destinationIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
                byte protocol = ipv4Packet.getProtocol();

                String sourcePort = "";
                String destinationPort = "";

                DeviceId packetInSwitch = inPkt.receivedFrom().deviceId();
                PortNumber packetInSwitchPort = inPkt.receivedFrom().port();

                String sourceAccessSwitch = "";
                String sourceAccessSwitchPort = "";
                if (hostService.getHost(srcId) != null) {
                    sourceAccessSwitch = hostService.getHost(srcId).location().deviceId().toString();
                    sourceAccessSwitchPort = hostService.getHost(srcId).location().port().toString();
                }

                String destinationAccessSwitch = "";
                String destinationAccessSwitchPort = "";
                if (hostService.getHost(dstId) != null) {
                    destinationAccessSwitch = hostService.getHost(dstId).location().deviceId().toString();
                    destinationAccessSwitchPort = hostService.getHost(dstId).location().port().toString();
                }

                int intSrcPort = 0;
                int intDstPort = 0;
                if (protocol == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    intSrcPort = tcpPacket.getSourcePort();
                    intDstPort = tcpPacket.getDestinationPort();
                    sourcePort = PortNumber.portNumber(Integer.toString(intSrcPort)).toString();
                    destinationPort = PortNumber.portNumber(Integer.toString(intDstPort)).toString();
                } else if (protocol == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    intSrcPort = udpPacket.getSourcePort();
                    intDstPort = udpPacket.getDestinationPort();
                    sourcePort = PortNumber.portNumber(Integer.toString(intSrcPort)).toString();
                    destinationPort = PortNumber.portNumber(Integer.toString(intDstPort)).toString();
                }

                captivePortalUserInfo = new CaptivePortalUserInfo(
                    sourceMac.toString(), destinationMac.toString(),
                    sourceIp.toString(), destinationIp.toString(),
                    sourcePort, destinationPort,
                    protocol,
                    sourceAccessSwitch, sourceAccessSwitchPort,
                    destinationAccessSwitch, destinationAccessSwitchPort,
                    packetInSwitch.toString(), packetInSwitchPort.toString());

                // Check whether the host can pass
                String resultAction = captivePortalUserInfo.accessCheck();

                if (resultAction.equals(CaptivePortalUserInfo.CAPTIVE_PORTAL_DENIED)) {
                    return;
                } else if (resultAction.equals(CaptivePortalUserInfo.CAPTIVE_PORTAL_AUTHORIZED)) {
                    normalPkt(context);
                    return;
                } else if (resultAction.equals(CaptivePortalUserInfo.CAPTIVE_PORTAL_FROM_PORTAL)) {
                    pktFromPortal(context);
                    return;
                } else if (resultAction.equals(CaptivePortalUserInfo.CAPTIVE_PORTAL_REDIRECT_TO_PORTAL)) {
                    redirectToPortal(context);
                    return;
                }
            }
        }
    }

    /**
    * Forward packets like official ReactiveForwarding.
    *
    * @param context the packet that needs transmission
    **/
    private void normalPkt(PacketContext context) {

        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();

        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
        Host dst = hostService.getHost(dstId);

        if (dst == null) {
            flood(context);
            return;
        }

        if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
            if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                installRule(context, dst.location().port());
            }
            return;
        }

        Path path = calculatePath(context);

        if (path == null) {
            flood(context);
            return;
        }

        installRule(context, path.src().port());
    }

    /**
    * Modify source IP to make the host think the packet is from requested URL.
    **/
    private void pktFromPortal(PacketContext context) {

        log.info("packet from protal");
        InboundPacket inPkt = context.inPacket();
        Ethernet ethPkt = inPkt.parsed();

        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();

        MacAddress destinationMac = ethPkt.getDestinationMAC();
        PortNumber destinationPort = PortNumber.portNumber(Integer.toString(tcpPacket.getDestinationPort()));
        DeviceId packetInSwitch = inPkt.receivedFrom().deviceId();

        MacAddress oldSrcMac = null;
        Ip4Address oldSrcIp = null;
        PortNumber oldSrcPort = null;

        if (macMapping.get(destinationMac) != null && ipMapping.get(destinationMac) != null) {
            oldSrcMac = macMapping.get(destinationMac).get(destinationPort);
            oldSrcIp = ipMapping.get(destinationMac).get(destinationPort);
            oldSrcPort = portMapping.get(destinationMac).get(destinationPort);
        }

        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
        Host dst = hostService.getHost(dstId);

        TrafficTreatment treatment = null;

        if (dst == null) {
            treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.FLOOD).build();
        } else {
            if (inPkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
                }
            } else {
                Path path = calculatePath(context);
                if (path == null) {
                    treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.FLOOD).build();
                } else {
                    treatment = DefaultTrafficTreatment.builder().setOutput(path.src().port()).build();
                }
                // installRule(context, path.src().port());
            }
        }

        Ip4Address sourceIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
        // Don't modify source IP if it is old source IP
        if (sourceIp != null && oldSrcIp != null) {
            if (sourceIp.toString() != oldSrcIp.toString()) {
                if (oldSrcMac != null && oldSrcIp != null) {
                    ipv4Packet.setSourceAddress(oldSrcIp.toString());
                    tcpPacket.setSourcePort(Integer.valueOf(oldSrcPort.toString()));
                    tcpPacket.resetChecksum();
                    tcpPacket.serialize();
                    ipv4Packet.resetChecksum();
                    ipv4Packet.serialize();
                    log.info("packet from portal, oldSrcIP:{}, oldDstIP:{}, oldSrcPort:{},oldDstPort:{}",
                            Ip4Address.valueOf(ipv4Packet.getSourceAddress()).toString(),
                            Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).toString(),
                            Integer.toString(tcpPacket.getSourcePort()),
                            Integer.toString(tcpPacket.getDestinationPort()));
                }
            }
        }

        OutboundPacket outPkt = new DefaultOutboundPacket(packetInSwitch,
                treatment, ByteBuffer.wrap(ethPkt.serialize()));
        packetService.emit(outPkt);
    }

    /**
    * Modify destination MAC address and IP address to redirect packet to portal.
    **/
    private void redirectToPortal(PacketContext context) {

        InboundPacket inPkt = context.inPacket();
        Ethernet ethPkt = inPkt.parsed();

        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
        TCP tcpPacket = (TCP) ipv4Packet.getPayload();

        MacAddress sourceMac = ethPkt.getSourceMAC();
        MacAddress destinationMac = ethPkt.getDestinationMAC();
        Ip4Address destinationIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
        PortNumber sourcePort = PortNumber.portNumber(Integer.toString(tcpPacket.getSourcePort()));
        PortNumber destinationPort = PortNumber.portNumber(Integer.toString(tcpPacket.getDestinationPort()));
        DeviceId packetInSwitch = inPkt.receivedFrom().deviceId();
        byte ipv4Protocol = ipv4Packet.getProtocol();

        if (macMapping.get(sourceMac) == null) {
            tempMac = new HashMap<>();
            tempMac.put(sourcePort, destinationMac);
            macMapping.put(sourceMac, tempMac);
        } else {
            macMapping.get(sourceMac).put(sourcePort, destinationMac);
        }

        if (ipMapping.get(sourceMac) == null) {
            tempIp = new HashMap<>();
            tempIp.put(sourcePort, destinationIp);
            ipMapping.put(sourceMac, tempIp);
        } else {
            ipMapping.get(sourceMac).put(sourcePort, destinationIp);
        }

        if (portMapping.get(sourceMac) == null) {
            tempPort = new HashMap<>();
            tempPort.put(sourcePort, destinationPort);
            portMapping.put(sourceMac, tempPort);
        } else {
            portMapping.get(sourceMac).put(sourcePort, destinationPort);
        }

        ethPkt.setDestinationMACAddress(portalMac);
        ipv4Packet.setDestinationAddress(portalIp);
        if (destinationPort.toLong() == 80) {
            tcpPacket.setDestinationPort(5000);
        } else if (destinationPort.toLong() == 443) {
            tcpPacket.setDestinationPort(5001);
        }
        tcpPacket.resetChecksum();
        tcpPacket.serialize();
        ipv4Packet.resetChecksum();
        ipv4Packet.serialize();

        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC()); // Portal MAC
        Host dst = hostService.getHost(dstId);
        TrafficTreatment treatment = null;

        if (dst == null) {
            log.info("dst is null when redirect to portal, so FLOOD the packet");
            treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.FLOOD).build();
        } else {
            if (inPkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
                }
            } else {
                Path path = calculatePath(context);
                if (path == null) {
                    treatment = DefaultTrafficTreatment.builder().setOutput(PortNumber.FLOOD).build();
                } else {
                    treatment = DefaultTrafficTreatment.builder().setOutput(path.src().port()).build();
                }
                // installRule(context, path.src().port());
            }
        }

        OutboundPacket outPkt = new DefaultOutboundPacket(packetInSwitch,
                treatment, ByteBuffer.wrap(ethPkt.serialize()));
        log.info("Redirect to portal, oldSrcIP:{}, oldDstIP:{}, oldSrcPort:{}, oldDstPort:{}",
                Ip4Address.valueOf(ipv4Packet.getSourceAddress()).toString(),
                Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).toString(),
                tcpPacket.getSourcePort(),
                tcpPacket.getDestinationPort());
        packetService.emit(outPkt);
    }

    private Path calculatePath(PacketContext context) {
        InboundPacket inPkt = context.inPacket();
        Ethernet ethPkt = inPkt.parsed();

        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
        Host dst = hostService.getHost(dstId);
        // log.info(inPkt.receivedFrom().deviceId().toString());
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), inPkt.receivedFrom().deviceId(),
                dst.location().deviceId());
        if (paths.isEmpty()) {
            log.info("Path is empty when calculate Path");
            return null;
        }

        Path path = pickForwardPathIfPossible(paths, inPkt.receivedFrom().port());
        if (path == null) {
            log.warn("Don't know where to go from here {} for {} -> {}", inPkt.receivedFrom(), ethPkt.getSourceMAC(),
                    ethPkt.getDestinationMAC());
            return null;
        } else {
            return path;
        }
    }
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path lastPath = null;
        for (Path path : paths) {
            lastPath = path;
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return lastPath;
    }

    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(), context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    /*
    * if the TCP/UDP port is for DNS/HTTPS/HTTP then return true.
    */
    private boolean isSpecificLayer4Port(Integer portNum) {

        if (portNum == 53 || portNum == 443 || portNum == 80) {
            return true;
        }
        return false;
    }

    private boolean isMyLocalAreaNetwork(Ip4Prefix addr) {
        if (addr.toString().equals("192.168.44.0/24")) {
            return true;
        }
        return false;
    }

    private void installRule(PacketContext context, PortNumber portNumber) {
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // Forward ARP packets directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        selectorBuilder.matchInPort(context.inPacket().receivedFrom().port());

        if (inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
            byte ipv4Protocol = ipv4Packet.getProtocol();
            Ip4Prefix matchIp4SrcPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);
            Ip4Prefix matchIp4DstPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                    Ip4Prefix.MAX_MASK_LENGTH);
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4);
            if (isMyLocalAreaNetwork(Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), 24))) {
                selectorBuilder.matchIPSrc(matchIp4SrcPrefix);
            }
            if (isMyLocalAreaNetwork(Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), 24))) {
                selectorBuilder.matchIPDst(matchIp4DstPrefix);
            }

            if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol);
                if (isSpecificLayer4Port(tcpPacket.getSourcePort())) {
                    selectorBuilder.matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()));
                }
                if (isSpecificLayer4Port(tcpPacket.getDestinationPort())) {
                    selectorBuilder.matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
            }
            if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol);
                if (isSpecificLayer4Port(udpPacket.getSourcePort())) {
                    selectorBuilder.matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()));
                }
                if (isSpecificLayer4Port(udpPacket.getDestinationPort())) {
                    selectorBuilder.matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
            }
            if (ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol);
            }
        }

        TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
        treatmentBuilder.setOutput(portNumber);

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build()).withTreatment(treatmentBuilder.build())
                .withPriority(flowPriority).withFlag(ForwardingObjective.Flag.VERSATILE).fromApp(appId)
                .makeTemporary(flowTimeout).add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

        packetOut(context, portNumber);
    }

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.captiveportal");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
        log.info("Captive Portal App Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(processor);
        withdrawIntercepts();
        log.info("Captive Portal App Stopped");
    }

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }
}
