package edu.nyu.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.sps.InterfaceShortestPathSwitching;
import edu.nyu.cs.sdn.apps.sps.ShortestPathSwitching;

import edu.nyu.cs.sdn.apps.util.ArpServer;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;
import edu.nyu.cs.sdn.apps.util.Host;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    // private IL3Routing l3RoutingApp;
	private InterfaceShortestPathSwitching l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(InterfaceShortestPathSwitching.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}

	public ArrayList<OFMatchField> getARPRules(int virtualHost) {
		ArrayList<OFMatchField> fieldList = new ArrayList<OFMatchField>();

		fieldList.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_ARP));
		fieldList.add(new OFMatchField(OFOXMFieldType.ARP_TPA, virtualHost));
	
		return fieldList;
	}

	public ArrayList<OFMatchField> getIPRules(int virtualHost) {
		ArrayList<OFMatchField> fieldList = new ArrayList<OFMatchField>();

		fieldList.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
		fieldList.add(new OFMatchField(OFOXMFieldType.IPV4_DST, virtualHost));
	
		return fieldList;
	}

	public void installSwitchRule(IOFSwitch sw, ArrayList<OFMatchField> ofmFields) {
		OFMatch ofm = new OFMatch();
		ArrayList<OFAction> actions = new ArrayList <OFAction>();
		ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();

		ofm.setMatchFields(ofmFields);

		OFActionOutput ofActionOutput = new OFActionOutput();
		ofActionOutput.setPort(OFPort.OFPP_CONTROLLER);
		actions.add(ofActionOutput);
		
		OFInstructionApplyActions actionsToApply = new OFInstructionApplyActions(actions);
		instructions.add(actionsToApply);

		SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY, ofm, instructions);
	}

	public void installSwitchRules(IOFSwitch sw, int virtualHost) {
		ArrayList<OFMatchField> ARPFields = getARPRules(virtualHost);
		ArrayList<OFMatchField> IPFields = getIPRules(virtualHost);

		installSwitchRule(sw, ARPFields);
		installSwitchRule(sw, IPFields);
	}

	public void installOtherRules(IOFSwitch sw) {
		OFInstructionGotoTable gotoTable = new OFInstructionGotoTable();
		gotoTable.setTableId(ShortestPathSwitching.table);

		ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(gotoTable);
		
		SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY - 1), new OFMatch(), instructions);
	}

	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */

		for (int host : this.instances.keySet()) {
			// for both ARP and IPv4
			installSwitchRules(sw, host);
		}

		installOtherRules(sw);

		/*********************************************************************/
	}
	
	/*
		Sends an ARP reply for ARP requests for virtual IPs
	*/
	public void handleARPReply(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw) {

		ARP arpPkt = (ARP) ethPkt.getPayload();
		int vIP = IPv4.toIPv4Address(arpPkt.getTargetProtocolAddress());

		if (arpPkt.getOpCode() != ARP.OP_REQUEST) {
			return;
		}

		if (!isIPVirtual(vIP)) {
			return;
		}

		byte[] vMAC = instances.get(vIP).getVirtualMAC();

		Ethernet ethReplyPacket = new Ethernet();
		ARP arpReply = new ARP();
		
		// Set ARP reply packet fields

		arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpReply.setSenderHardwareAddress(vMAC);
		arpReply.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
		arpReply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);

		arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
		arpReply.setSenderProtocolAddress(vIP);
		arpReply.setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());
		arpReply.setProtocolAddressLength((byte) 0x4);

		arpReply.setOpCode(ARP.OP_REPLY);

		ethReplyPacket.setEtherType(Ethernet.TYPE_ARP);
		ethReplyPacket.setDestinationMACAddress(ethPkt.getSourceMACAddress());
		ethReplyPacket.setSourceMACAddress(vMAC);

		// add ARP payload
		ethReplyPacket.setPayload(arpReply);

		SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ethReplyPacket);
		
	}

	public void respondWithTCP_RST(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw, TCP tcpPkt) {
		IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();

		// build TCP packet

		tcpPkt.setFlags((short) 0x04); // TCP RESET FLAG
		tcpPkt.setSequence(tcpPkt.getAcknowledge());
		tcpPkt.setWindowSize((short) 0);
		tcpPkt.setSourcePort(tcpPkt.getDestinationPort());
		tcpPkt.setDestinationPort(tcpPkt.getSourcePort());
		tcpPkt.setChecksum((short) 0);
		tcpPkt.serialize();

		ipv4Pkt.setDestinationAddress(ipv4Pkt.getSourceAddress());
		ipv4Pkt.setSourceAddress(ipv4Pkt.getDestinationAddress());
		ipv4Pkt.setPayload(tcpPkt);

		ipv4Pkt.setChecksum((short) 0);
		ipv4Pkt.serialize();
		
		// Add ipv4 packet to ethernet response frame

		ethPkt.setPayload(ipv4Pkt);
		ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress()); 
		ethPkt.setSourceMACAddress(ethPkt.getDestinationMACAddress());  
		
		SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ethPkt);
	}

	public void installConnectionRules(IOFSwitch sw, ArrayList<OFMatchField> IPFields, ArrayList<OFAction> actions) {
		OFMatch ofm = new OFMatch();
		ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();

		ofm.setMatchFields(IPFields);
		OFInstructionApplyActions actionsToApply = new OFInstructionApplyActions(actions);

		OFInstructionGotoTable instrGoToTable = new OFInstructionGotoTable();
		instrGoToTable.setTableId(ShortestPathSwitching.table);
			
		instructions.add(actionsToApply);
		instructions.add(instrGoToTable);

		SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1), ofm, instructions, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);
	}

	public ArrayList<OFMatchField> getPacketFieldList(IPv4 ipv4Pkt){
		ArrayList<OFMatchField> IPFields = new ArrayList<OFMatchField>();

		IPFields.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
		IPFields.add(new OFMatchField(OFOXMFieldType.IPV4_SRC, ipv4Pkt.getSourceAddress()));
		IPFields.add(new OFMatchField(OFOXMFieldType.IPV4_DST, ipv4Pkt.getDestinationAddress()));
		IPFields.add(new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP));

		return IPFields;
	}

	public void setHostFieldsAndActions(IOFSwitch sw, IPv4 ipv4Pkt, TCP tcpPkt, int vIP){
		ArrayList<OFMatchField> fields = getPacketFieldList(ipv4Pkt);
		ArrayList<OFAction> actions = new ArrayList <OFAction>();
		ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();
		int hostIP = instances.get(vIP).getNextHostIP();

		fields.add(new OFMatchField(OFOXMFieldType.TCP_DST, tcpPkt.getDestinationPort()));
		fields.add(new OFMatchField(OFOXMFieldType.TCP_SRC, tcpPkt.getSourcePort()));

		actions.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIP));
		actions.add(new OFActionSetField(OFOXMFieldType.ETH_DST, getHostMACAddress(hostIP)));

		installConnectionRules(sw, fields, actions);
	}

	public void setClientFieldsAndActions(IOFSwitch sw, IPv4 ipv4Pkt, TCP tcpPkt, int vIP){
		ArrayList<OFMatchField> fields = getPacketFieldList(ipv4Pkt);
		ArrayList<OFAction> actions = new ArrayList <OFAction>();
		ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();	
		
		fields.add(new OFMatchField(OFOXMFieldType.TCP_DST, tcpPkt.getDestinationPort()));
		fields.add(new OFMatchField(OFOXMFieldType.TCP_SRC, tcpPkt.getSourcePort()));

		actions.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, vIP));
		actions.add(new OFActionSetField(OFOXMFieldType.ETH_SRC, instances.get(vIP).getVirtualMAC()));

		installConnectionRules(sw, fields, actions);
	}

	public void handleIPV4(Ethernet ethPkt, OFPacketIn pktIn, IOFSwitch sw) {

		IPv4 ipv4Pkt= (IPv4) ethPkt.getPayload();
		
		if (ipv4Pkt.getProtocol() != IPv4.PROTOCOL_TCP){
			return;
		}

		TCP tcpPkt = (TCP) ipv4Pkt.getPayload();
		int vIP = ipv4Pkt.getDestinationAddress();

		if (tcpPkt.getFlags() != TCP_FLAG_SYN) {
			respondWithTCP_RST(ethPkt, pktIn, sw, tcpPkt);
			return;
		}

		if (!isIPVirtual(vIP)) {
			return;
		}
		
		// install connection specific roles in virtual hosts and clients
		setHostFieldsAndActions(sw, ipv4Pkt, tcpPkt, vIP);
		setClientFieldsAndActions(sw, ipv4Pkt, tcpPkt, vIP);
	}

	private boolean isIPVirtual(int ip){
		return instances.containsKey(ip);
	}

	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other packets                             */
		switch (ethPkt.getEtherType()) {
			case Ethernet.TYPE_ARP: 
				handleARPReply(ethPkt, pktIn, sw);
				break;
			case Ethernet.TYPE_IPv4: 
				handleIPV4(ethPkt, pktIn, sw); 
				break;
			default: break;
		}
		/*********************************************************************/
		
		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
