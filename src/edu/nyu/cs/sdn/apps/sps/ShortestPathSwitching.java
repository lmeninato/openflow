package edu.nyu.cs.sdn.apps.sps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.PriorityQueue;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.Host;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.Link;

import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionType;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener,
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching {
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();

	// Interface to the logging system
	private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

	// Interface to Floodlight core for interacting with connected switches
	private IFloodlightProviderService floodlightProv;

	// Interface to link discovery service
	private ILinkDiscoveryService linkDiscProv;

	// Interface to device manager service
	private IDeviceService deviceProv;

	// Switch table in which rules should be installed
	static public byte table;

	// Map of hosts to devices
	private Map<IDevice, Host> knownHosts;

	// Store shortest paths from a switch to all other switches
	public HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> allShortestPaths;

	/**
	 * Loads dependencies and initializes data structures.
	 */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String, String> config = context.getConfigParams(this);
		this.table = Byte.parseByte(config.get("table"));

		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
		this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
		this.deviceProv = context.getServiceImpl(IDeviceService.class);

		this.knownHosts = new ConcurrentHashMap<IDevice, Host>();

		/*********************************************************************/
		/* TODO: Initialize other class variables, if necessary */

		this.allShortestPaths = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();

		/*********************************************************************/
	}

	public class SwitchPair implements Comparable<SwitchPair> {

		IOFSwitch s;
		Integer cost;

		SwitchPair(IOFSwitch s, Integer cost) {
			this.s = s;
			this.cost = cost;
		}

		@Override
		public int compareTo(SwitchPair o) {
			return this.cost - o.cost;
		}
	}

	/*
	 * Initialize data structures for Dijkstra's
	 */
	private void initializeSwitchDistances(Collection<IOFSwitch> switches,
			IOFSwitch sw,
			HashMap<IOFSwitch, Integer> distances,
			HashMap<IOFSwitch, IOFSwitch> parents,
			PriorityQueue<SwitchPair> pq) {
		for (IOFSwitch s : switches) {
			distances.put(s, Integer.MAX_VALUE);
			pq.add(new SwitchPair(s, Integer.MAX_VALUE));
			parents.put(s, null);
		}

		distances.put(sw, 0);
		pq.add(new SwitchPair(sw, 0));

		for (Link link : getLinks()) {
			IOFSwitch source = getSwitches().get(link.getSrc());
			IOFSwitch dest = getSwitches().get(link.getDst());

			if (source == sw) {
				distances.put(dest, 1);
				pq.add(new SwitchPair(dest, 1));
				parents.put(dest, source);
			}
		}
	}

	/**
	 *
	 * Compute Dijkstras on every node in the network topology
	 * 
	 * Link costs are assumed to be 1
	 * 
	 * sets allShortestPaths to hashmap where {switch -> {switch1 -> parent1,
	 * switch2 -> parent2, ...}}
	 * So to look up the shortest path from A to B, we keep looking up the shortest
	 * paths object until the parent is B.
	 */
	public void computeAllShortestPaths() {

		Collection<IOFSwitch> switches = getSwitches().values();
		HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> shortestPaths = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();

		for (IOFSwitch sw : switches) {

			PriorityQueue<SwitchPair> pq = new PriorityQueue<SwitchPair>();
			HashMap<IOFSwitch, IOFSwitch> parents = new HashMap<IOFSwitch, IOFSwitch>();
			HashMap<IOFSwitch, Integer> distances = new HashMap<IOFSwitch, Integer>();

			initializeSwitchDistances(switches, sw, distances, parents, pq);

			Set<IOFSwitch> seen = new HashSet<IOFSwitch>();
			Integer dist;
			IOFSwitch curr;

			while (!pq.isEmpty()) {
				curr = pq.poll().s;
				seen.add(curr);
				for (Link link : getLinks()) {
					IOFSwitch source = getSwitches().get(link.getSrc());
					IOFSwitch neighbor = getSwitches().get(link.getDst());

					if (source == curr && !seen.contains(neighbor)) {
						dist = distances.get(curr) + 1;
						if (dist < distances.get(neighbor)) {
							distances.put(neighbor, dist);
							pq.add(new SwitchPair(neighbor, dist));
							parents.put(neighbor, curr);
						}
					}
				}
			}

			shortestPaths.put(sw, parents);
		}

		this.allShortestPaths = shortestPaths;
	}

	public OFMatch initializeOFMatch(Host host) {
		OFMatch ofm = new OFMatch();
		ArrayList<OFMatchField> fields = new ArrayList<OFMatchField>();

		// add ethernet type
		fields.add(new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4));
		// add mac address
		fields.add(new OFMatchField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(host.getMACAddress())));

		ofm.setMatchFields(fields);

		return ofm;
	}

	public ArrayList<OFInstruction> getInstructionList(Host host, IOFSwitch sw) {
		IOFSwitch hostSwitch = host.getSwitch();
		OFActionOutput ofa = new OFActionOutput();

		if (sw.getId() != hostSwitch.getId()) {

			IOFSwitch nextSwitch = this.allShortestPaths.get(hostSwitch).get(sw);

			for (Link link : getLinks()) {
				if (sw.getId() == link.getSrc()) {
					if (nextSwitch.getId() == link.getDst()) {
						ofa.setPort(link.getSrcPort());
					}
				}
			}

		} else {
			ofa.setPort(host.getPort());
		}

		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		ArrayList<OFInstruction> instructions = new ArrayList<OFInstruction>();

		actions.add(ofa);
		OFInstructionApplyActions actionsToApply = new OFInstructionApplyActions(actions);
		instructions.add(actionsToApply);

		return instructions;
	}

	public void setTables(Host host) {

		// only consider hosts that are connected to the network topology
		if (!host.isAttachedToSwitch()) {
			return;
		}

		OFMatch ofm = initializeOFMatch(host);
		for (IOFSwitch sw : getSwitches().values()) {
			ArrayList<OFInstruction> instructions = getInstructionList(host, sw);
			SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY, ofm, instructions);
		}
	}

	public void setAllTables() {
		for (Host host : getHosts()) {
			setTables(host);
		}
	}

	public void deleteTablesForHost(Host host) {
		OFMatch ofm = initializeOFMatch(host);

		for (IOFSwitch sw : getSwitches().values()) {
			SwitchCommands.removeRules(sw, this.table, ofm);
		}
	}

	public void deleteAllTables() {
		for (Host host : getHosts()) {
			deleteTablesForHost(host);
		}

	}

	public void rebuildAllTables() {
		deleteAllTables();
		computeAllShortestPaths();
		setAllTables();
	}

	/**
	 * Subscribes to events and performs other startup tasks.
	 */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
	}

	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable() {
		return this.table;
	}

	/**
	 * Get a list of all known hosts in the network.
	 */
	private Collection<Host> getHosts() {
		return this.knownHosts.values();
	}

	/**
	 * Get a map of all active switches in the network. Switch DPID is used as
	 * the key.
	 */
	private Map<Long, IOFSwitch> getSwitches() {
		return floodlightProv.getAllSwitchMap();
	}

	/**
	 * Get a list of all active links in the network.
	 */
	private Collection<Link> getLinks() {
		return linkDiscProv.getLinks().keySet();
	}

	/**
	 * Event handler called when a host joins the network.
	 * 
	 * @param device information about the host
	 */
	@Override
	public void deviceAdded(IDevice device) {
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null) {
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);

			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host */
			computeAllShortestPaths();
			setTables(host);
			/*****************************************************************/
		}
	}

	/**
	 * Event handler called when a host is no longer attached to a switch.
	 * 
	 * @param device information about the host
	 */
	@Override
	public void deviceRemoved(IDevice device) {
		Host host = this.knownHosts.get(device);
		if (null == host) {
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}

		log.info(String.format("Host %s is no longer attached to a switch",
				host.getName()));

		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host */
		deleteTablesForHost(host);
		/*********************************************************************/
	}

	/**
	 * Event handler called when a host moves within the network.
	 * 
	 * @param device information about the host
	 */
	@Override
	public void deviceMoved(IDevice device) {
		Host host = this.knownHosts.get(device);
		if (null == host) {
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}

		if (!host.isAttachedToSwitch()) {
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));

		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host */
		deleteTablesForHost(host);
		setTables(host);
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch joins the network.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchAdded(long switchId) {
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));

		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts */
		rebuildAllTables();
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) {
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));

		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts */
		rebuildAllTables();
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * 
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
		for (LDUpdate update : updateList) {
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst()) {
				log.info(String.format("Link s%s:%d -> host updated",
						update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else {
				log.info(String.format("Link s%s:%d -> %s:%d updated",
						update.getSrc(), update.getSrcPort(),
						update.getDst(), update.getDstPort()));
			}
		}

		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts */
		computeAllShortestPaths();
		setAllTables();
		/*********************************************************************/
	}

	/**
	 * Event handler called when link goes up or down.
	 * 
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) {
		this.linkDiscoveryUpdate(Arrays.asList(update));
	}

	/**
	 * Event handler called when the IP address of a host changes.
	 * 
	 * @param device information about the host
	 */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) {
		this.deviceAdded(device);
	}

	/**
	 * Event handler called when the VLAN of a host changes.
	 * 
	 * @param device information about the host
	 */
	@Override
	public void deviceVlanChanged(IDevice device) {
		/* Nothing we need to do, since we're not using VLANs */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) {
		/* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * 
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) {
		/* Nothing we need to do */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * 
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) {
		/* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * 
	 * @return name for this module
	 */
	@Override
	public String getName() {
		return this.MODULE_NAME;
	}

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) {
		return false;
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) {
		return false;
	}

	/**
	 * Tell the module system which services we provide.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> services = new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services;
	}

	/**
	 * Tell the module system which services we implement.
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> services = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		// We are the class that implements the service
		services.put(InterfaceShortestPathSwitching.class, this);
		return services;
	}

	/**
	 * Tell the module system which modules we depend on.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> modules = new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
		return modules;
	}
}
