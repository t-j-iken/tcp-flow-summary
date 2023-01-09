import java.io.IOException;
import java.io.EOFException;
import java.net.Inet4Address;
import com.sun.jna.Platform;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.Packets;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import java.lang.InterruptedException;
import java.lang.NullPointerException;
import java.util.concurrent.TimeoutException;
import java.util.Objects;
import java.lang.Object;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import java.util.Date;
import java.sql.Timestamp;
import java.lang.ArrayIndexOutOfBoundsException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;



public class App 
{

// create two lists
static ArrayList<Flow> actFlowList = new ArrayList<Flow>();
static ArrayList<Flow> inactFlowList = new ArrayList<Flow>();

//create FLow class for flow objects
public static class Flow {
	private String srcIP;
	private String srcPort;
	private String destIP;
	private String destPort;
	private int id;
	private long endTime;
	private int count;
	private int packetSize;
	private long startTime;
	private double bandwidth;
	
	private Boolean isComplete = false;
	private Boolean isSyn = false;
	
	//originally -> public void TcpPacketFlow
	public void Flow(String ssrcIP, String ssrcPort, String sDestIP, String sDestPort, int sid, int scount, int spacketSize, long sstartTime, double sbandwidth, Boolean sisComplete, Boolean isSyn, long sendTime){
			srcIP = ssrcIP;
			srcPort = ssrcPort;
			destIP = sDestIP;
			destPort = sDestPort;
			id = sid;
			count = scount;
			packetSize = spacketSize;
			startTime = sstartTime;
			bandwidth = sbandwidth;
			isComplete = false;
			isSyn = false;
			endTime = sendTime;
	}

	public String getSrcIP() {
		return srcIP;
	}
	public String getSrcPort() {
                return srcPort;
        }
	public String getDestIP() {
                return destIP;
        }
	public String getDestPort() {
                return destPort;
        }
	public int  getID() {
                return id;
        }
	public int getCount() {
                return count;
        }
	public int getPacketSize() {
                return packetSize;
        }
	public void setPacketSize(int newSize) {
                this.packetSize = newSize;
        }
	public long getStartTime() {
                return startTime;
        }
	public void setStartTime(long newStartTime) {
                this.startTime = newStartTime;
        }
	public double getBandwidth() {
                return bandwidth;
        }
	public void setBandwidth(double newBandwidth) {
                this.bandwidth = newBandwidth;
        }
	public Boolean getComplete() {
                return isComplete;
        }
	public void setComplete(Boolean newComplete) {
                this.isComplete = newComplete;
        }


	@Override
	public String toString() {
			 return ("(" + srcIP + ", " + srcPort + ", " + destIP + ", " + destPort + ")");
	}
	

	@Override
	public boolean equals(Object anotherFlow) {
		if(anotherFlow instanceof Flow) {
			Flow flow = (Flow) anotherFlow;
			return (srcIP.equals(flow.srcIP) && srcPort.equals(flow.srcPort)
					&& destIP.equals(flow.destIP) && destPort.equals(flow.destPort));
		} else {
			return false;
		}
	}
}

	//Main method, code begins
    public static void main( String[] args ) throws PcapNativeException, NotOpenException
    {

	String file;
	int debug = 0;
	
	if(args.length == 0) {
	  file = "input.pcap";	
	} else {
	  file = args[0];
	}

	//string for debugging
    System.out.println( "---Starting Packet Analysis---" );
	final PcapHandle handle;
	try{
		handle = Pcaps.openOffline(file);
	} catch (Exception e){
		System.out.println("Opening pcap file failed");
		e.printStackTrace();
		return;
	}

	
	final int[] udp = {0,0};
	final int[] icmp = {0,0};
	final int[] other = {0,0};
	final int[] maxID = {0};
	final int[] regPackets = {0};

	//hashmap used to store and uniquely identify flows
	final Map<Flow, Integer> keyList = new HashMap<Flow, Integer>();
	ArrayList<Flow> idStorage = new ArrayList<Flow>();
	
	//***********************************************************************************************************//
	//MAIN FUNCTION FOR PACKET PROCESSING

	 PacketListener listener = new PacketListener() {
		  public void gotPacket(Packet packet) {
			
			try {
				//if packet is TCP
				if(packet.get(TcpPacket.class) != null) {
					//System.out.print(actFlowList.size() + " ");

					//get addresses and variables
					IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
					String srcIP = ipV4Packet.getHeader().getSrcAddr().toString();
					String destIP = ipV4Packet.getHeader().getDstAddr().toString();
					//get port
					TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
					String srcPort = tcpHeader.getSrcPort().toString();
					String destPort = tcpHeader.getDstPort().toString();
					//get time
					Timestamp time = handle.getTimestamp();

					//create temp packet flow for comparing
					Flow temp = new Flow();
					temp.srcIP = srcIP; 
					temp.destIP = destIP; 
					temp.srcPort = srcPort; 
					temp.destPort = destPort;
				        temp.startTime = handle.getTimestamp().getTime();
					temp.isComplete = false;
				
					int id = 0;

					if(keyList.containsKey(temp)) {
						id = keyList.get(temp);
					} else {
						id = maxID[0];
						maxID[0]++;
					}

					temp.id = id;

					int finFlag = 0;
					int synFlag = 0;
					int regFlag = 0;

					//*******************************************************************
					int idFlag = 0;
	
					if(idStorage.contains(temp)) {
						int index = idStorage.indexOf(temp);
						temp.id = index;
					}
					else {
						idStorage.add(temp);
					}

					//test!!!
					//System.out.println(temp.getSrcIP() + "" + temp.getDestIP());
					
					//if TCP header has FIN
					if(tcpHeader.getFin()) {
						// checks null is syn was found
						if(actFlowList.contains(temp)) {
							//take care of back to back fin bits
							int index = actFlowList.indexOf(temp);
						
							actFlowList.get(index).count++;
							actFlowList.get(index).packetSize += packet.length();
							actFlowList.get(index).isComplete = true;
							actFlowList.get(index).endTime = time.getTime();

							double timeDiff = (actFlowList.get(index).endTime - actFlowList.get(index).startTime) / 1000.0; //get time difference
							double bytes = actFlowList.get(index).packetSize * 0.008; //adding the / 125000
							actFlowList.get(index).bandwidth = (float)(bytes / timeDiff);

							//its finished so move to inactive flow
							inactFlowList.add(actFlowList.get(index));
							actFlowList.remove(index);
								
								
							//if found set flag to 1 to skip next step
									
						} 
						else {			
							temp.count++;
							//System.out.println(temp.count);
                            temp.packetSize += packet.length();
                            temp.endTime = time.getTime();
                            double timeDiff = (temp.endTime - temp.startTime) / 1000.0;
                            double bytes = temp.packetSize * 0.008;
                            temp.bandwidth = (float)(bytes / timeDiff);
                            //add to inactive flow list
                            inactFlowList.add(temp);
						}

						//reset flag
						finFlag = 0;
					
					//if TCP header has SYN
					}  if(tcpHeader.getSyn()) {

							if(actFlowList.contains(temp)) {
								//if found, move into closed list, start new flow
								//inactFlowList.add(actFlowList.remove(actFlowList.indexOf(temp)));
								int index = actFlowList.indexOf(temp);
								actFlowList.get(index).count++;
								actFlowList.get(index).packetSize += packet.length();
								actFlowList.get(index).isComplete = false;
								inactFlowList.add(actFlowList.get(index));
								actFlowList.remove(index);
								//**********
								//temp.count++;
								//temp.packetSize += packet.length();
								//temp.startTime  = time.getTime();
								//temp.isComplete = false; //added this maybe ill need to fucking delete
								//inactFlowList.add(actFlowList.remove(actFlowList.indexOf(temp)));
								//actFlowList.add(temp);
							}
							else {
							temp.count++;
                            temp.packetSize += packet.length();
							temp.startTime = time.getTime();
							temp.isSyn = true; //syn set to true
                            actFlowList.add(temp);
							}
						
					} else 
						{
				
						if(actFlowList.contains(temp)) {
								//if found
								int index = actFlowList.indexOf(temp); //originally was to add to actFlowList, gonna try inact
								actFlowList.get(index).count++;  //was original count += 1;
								actFlowList.get(index).packetSize += packet.length();
						} else {
							temp.count++;
                            temp.packetSize += packet.length();
                            actFlowList.add(temp);
							
						}
						
						
					}
				//if packet is UDP
				 } else if(packet.get(UdpPacket.class) != null) {
					udp[0] += 1;
					udp[1] += packet.length();
				//get other packet info	
				 } else {
					try {
						IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
						if(ipV4Packet.getHeader().getProtocol().name().equals("ICMP")) {
							icmp[0] += 1;
							icmp[1] += packet.length();
						} else {
							other[0] += 1;
							other[1] += packet.length();
						}

					} catch (NullPointerException e) {
						other[0] += 1;
						other[1] += packet.length();
					}
				 }

			 } catch (NullPointerException e) {
					 return;
		       			}

								
		 	 }
		};

		// looping 
		try {
			int maxP = -1;
			handle.loop(maxP, listener);
		} catch (InterruptedException e ) {
			return;
		
		}

		//DEBUG IP FOR FLOW OBJECT
		String debugcode = "192.168.2.220";
		String debugcode1 = "34.107.221.82";
		String debugcode2 = "34.216.198.143";
		String debugcode3 = "72.21.91.29";
		//merge lists
		for(int l = 0; l < actFlowList.size(); l++) {
			inactFlowList.add(actFlowList.get(l));
		}

		System.out.println("");		
		System.out.println("TCP Flow Summary Table");
		//print results 
	if(debug == 0) {

		for(int i = 0; i < idStorage.size(); i++) {
			Flow temp = idStorage.get(i);
			int com = 0;
			int incom = 0;
			int totalBytes = 0;
			
			for(int j = 0; j < inactFlowList.size(); j++) {
				Flow temp2 = inactFlowList.get(j);
				//System.out.println(temp2.count);
				if(temp2.id == temp.id) {
					if(temp2.isComplete == true) {
						com += temp2.count;
					}
					
					else {  //(temp2.isComplete == false) {
						incom += temp2.count;
						
					}

					totalBytes += temp2.packetSize;
				}
			}
			if(temp.bandwidth == 0.0) {
			System.out.println(temp.srcIP + ", " + temp.srcPort + ", " + temp.destIP + ", " + temp.destPort + ", " + com + ", " + incom);
			} else {
			System.out.println(temp.srcIP + ", " + temp.srcPort + ", " + temp.destIP + ", " + temp.destPort + ", " + com + ", " + incom + ", " + totalBytes + ", " + temp.bandwidth);
			}	
		}
	} else {
			//do nothing
	}
		//print additional protocols.
		System.out.println();
		System.out.println("Additional Protocols Table");
		System.out.println("UDP, " + udp[0] + ", " + udp[1]);
		System.out.println("ICMP, " + icmp[0] + ", " + icmp[1]);
		System.out.println("Other, " + other[0] + ", " + other[1]);

    	handle.close();
    }
}	    