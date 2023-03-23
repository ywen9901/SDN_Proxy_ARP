/*
 * Copyright 2022-present Open Networking Foundation
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
package nctu.winlab.proxyArp;

import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.swing.plaf.basic.BasicScrollPaneUI.HSBChangeListener;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, service = { SomeInterface.class }, property = {
        "someProperty=Some Default String Value",
})
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    private String tableMissMsg = "TABLE MISS. Send request to edge ports";
    private String recvReplyMsg = "RECV REPLY. Requested MAC = {}";
    private String tableHitMsg = "TABLE HIT. Requested MAC = {}";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    private ApplicationId appId;
    private ProxyArpProcessor processor;

    private HashMap<Ip4Address, MacAddress> IP_MAC_MAPPING = new HashMap<Ip4Address, MacAddress>();
    private HashMap<Ip4Address, ConnectPoint> IP_CP_MAPPING = new HashMap<Ip4Address, ConnectPoint>();

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");

        processor = new ProxyArpProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(3));

        packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                PacketPriority.REACTIVE, appId);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(processor);
        packetService.cancelPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
                PacketPriority.REACTIVE, appId);
        processor = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            Ethernet pkt = context.inPacket().parsed();
            ARP arpPkt = (ARP) pkt.getPayload();

            short arpOpCode = arpPkt.getOpCode();
            MacAddress srcMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());
            Ip4Address srcIP = Ip4Address.valueOf(arpPkt.getSenderProtocolAddress());
            Ip4Address dstIP = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());

            if (!IP_CP_MAPPING.containsKey(srcIP)) {
                ConnectPoint cp = new ConnectPoint(context.inPacket().receivedFrom().deviceId(),
                        context.inPacket().receivedFrom().port());
                IP_CP_MAPPING.put(srcIP, cp);
            }

            if (arpOpCode == ARP.OP_REQUEST) {
                if (IP_MAC_MAPPING.containsKey(dstIP)) {
                    MacAddress dstMac = IP_MAC_MAPPING.get(dstIP);
                    log.info(tableHitMsg, dstMac);

                    ConnectPoint srcCP = IP_CP_MAPPING.get(srcIP);
                    Ethernet replyPkt = ARP.buildArpReply(dstIP, dstMac, pkt);

                    OutboundPacket arpReply = createOutboundPkt(srcCP.deviceId(), srcCP.port(), replyPkt);
                    packetService.emit(arpReply);
                } else {
                    log.info(tableMissMsg);

                    List<ConnectPoint> edgePoints = Lists.newArrayList(edgePortService.getEdgePoints());
                    for (ConnectPoint point : edgePoints) {
                        if(point != IP_CP_MAPPING.get(srcIP)) {
                            OutboundPacket arpRequest = createOutboundPkt(point.deviceId(), point.port(), pkt);
                            packetService.emit(arpRequest);
                        }
                    }
                }
            } else if (arpOpCode == ARP.OP_REPLY) {
                IP_MAC_MAPPING.put(srcIP, srcMac);
                IP_MAC_MAPPING.put(dstIP, MacAddress.valueOf(arpPkt.getTargetHardwareAddress()));

                log.info(recvReplyMsg, IP_MAC_MAPPING.get(srcIP));

                ConnectPoint dstCP = IP_CP_MAPPING.get(dstIP);
                OutboundPacket arpReply = createOutboundPkt(dstCP.deviceId(), dstCP.port(), pkt);

                packetService.emit(arpReply);
            }
        }
    }

    private OutboundPacket createOutboundPkt(DeviceId device, PortNumber port, Ethernet rawPkt) {
        OutboundPacket outPacket = new DefaultOutboundPacket(
                device,
                DefaultTrafficTreatment.builder().setOutput(port).build(),
                ByteBuffer.wrap(rawPkt.serialize()));
        return outPacket;
    }
}