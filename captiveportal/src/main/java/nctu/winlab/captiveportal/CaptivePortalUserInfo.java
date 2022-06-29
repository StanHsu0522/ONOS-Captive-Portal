package nctu.winlab.captiveportal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.onlab.packet.IPv4;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

/**
 * class of CaptivePortal user authentication information.
 */
public class CaptivePortalUserInfo {

    private final Logger log = LoggerFactory.getLogger(getClass());

    // Host transmitting the packet is authenticated
    public static final String CAPTIVE_PORTAL_AUTHORIZED = "Pass";
    // The packet cannot be transmitted in this network
    public static final String CAPTIVE_PORTAL_DENIED = "Drop";
    // Packets for authentication from portal
    public static final String CAPTIVE_PORTAL_REDIRECT_TO_PORTAL = "RedirectToPortal";
    // Redirect the packet to portal for authentication
    public static final String CAPTIVE_PORTAL_FROM_PORTAL = "PktFromPortal";

    private String portalMac = "f6:42:0f:83:51:de";
    private String gatewayMac = "ea:e9:78:fb:fd:00";

    private String sourceMac;
    private String destinationMac;
    private String sourceIp;
    private String destinationIp;
    private String sourcePort = "";
    private String destinationPort = "";
    private byte protocol;

    private String sourceAccessSwitch;
    private String sourceAccessSwitchPort;
    private String destinationAccessSwitch;
    private String destinationAccessSwitchPort;

    private String packetInSwitch;
    private String packetInSwitchPort;

    private String result = "Drop"; // Default action = Drop

    public CaptivePortalUserInfo(
        String sourceMac, String destinationMac,
        String sourceIp, String destinationIp,
        String sourcePort, String destinationPort,
        byte protocol,
        String sourceAccessSwitch, String sourceAccessSwitchPort,
        String destinationAccessSwitch, String destinationAccessSwitchPort,
        String packetInSwitch, String packetInSwitchPort) {

        this.sourceMac = sourceMac;
        this.destinationMac = destinationMac;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.protocol = protocol;

        if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
        }

        this.sourceAccessSwitch = sourceAccessSwitch;
        this.sourceAccessSwitchPort = sourceAccessSwitchPort;
        this.destinationAccessSwitch = destinationAccessSwitch;
        this.destinationAccessSwitchPort = destinationAccessSwitchPort;
        this.packetInSwitch = packetInSwitch;
        this.packetInSwitchPort = packetInSwitchPort;

        Process process;
        try {
            String authenticationUrl = "http://localhost:8181/RadiusAuthentication/UserCredential/insertIpMapping";
            String insertUserIp2MacMappingCurlCmd =
            "curl -X POST " + authenticationUrl + " -u onos:rocks -d ip="
            + sourceIp + "&mac=" + sourceMac;
            process = Runtime.getRuntime().exec(insertUserIp2MacMappingCurlCmd);
            int returnVal = 0;
            try {
                returnVal = process.waitFor();
            } catch (InterruptedException e) {
                log.info("interrupted exception for exec curl");
            }
            insertUserIp2MacMappingCurlCmd = "";
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            insertUserIp2MacMappingCurlCmd = bufferedReader.readLine();
            if (insertUserIp2MacMappingCurlCmd == null) {
                log.info("insertUserIp2MacMappingCurlCmd is null in Auth. constructor!!");
            }
        } catch (IOException e) {
            log.info("in Authentication getUser IOException");
        }
    }

    /**
    * Check whether the packet can pass or it needs redirection.
    *
    * @return A string of Pass/Drop/PktFromPortal/RedirectToPortal
    *         Pass: Host transmitting the packet is authenticated
    *         Drop: The packet cannot be transmitted in this network
    *         PktFromPortal: Packets for authentication from portal
    *         RedirectToPortal: Redirect the packet to portal for authentication
    **/
    public String accessCheck() {

        // Ignore DHCP packets
        if (protocol == IPv4.PROTOCOL_UDP) {
            if ((sourcePort.equals("67") && destinationPort.equals("68")) ||
            (sourcePort.equals("68") && destinationPort.equals("67"))) {
                return CAPTIVE_PORTAL_DENIED;
            }
        }
        // Pass DNS packets
        if (protocol == IPv4.PROTOCOL_UDP || protocol == IPv4.PROTOCOL_TCP) {
            if ((sourcePort.equals("53") || destinationPort.equals("53"))) {
                return CAPTIVE_PORTAL_AUTHORIZED;
            }
        }
        // Pass ICMP packets
        if (protocol == IPv4.PROTOCOL_ICMP) {
            return CAPTIVE_PORTAL_AUTHORIZED;
        } else if (sourceMac.equalsIgnoreCase(portalMac)) {
            // Packets from port 80/443/5000/5001 of portal need some modification
            // Pass packets from other ports of portal
            if (sourcePort.equals("80") || sourcePort.equals("443") ||
            sourcePort.equals("5001") || sourcePort.equals("5000")) {
                return CAPTIVE_PORTAL_FROM_PORTAL;
            } else {
                return CAPTIVE_PORTAL_AUTHORIZED;
            }
        }

        // Check whether the host is authenticated or not
        boolean hostEnable = false;
        Process process;
        try {
            String checkUserCredentialCmd =
            "curl -X POST http://localhost:8181/RadiusAuthentication/UserCredential/getUser -u onos:rocks -d ip="
            + sourceIp;
            process = Runtime.getRuntime().exec(checkUserCredentialCmd);
            int returnVal = 0;
            try {
                returnVal = process.waitFor();
            } catch (InterruptedException e) {
                log.info("interrupted exception for exec checkUserCredentialCmd");
            }
            String userCredential = "";
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            userCredential = bufferedReader.readLine();
            if (userCredential != null) {
                if (userCredential.equals("true")) {
                    // log.info("getUser success!!");
                    hostEnable = true;
                } else {
                    // log.info("getUser failed!!");
                    hostEnable = false;
                }
            }
        } catch (IOException e) {
            log.info("in Authentication getUser IOException");
        }

        if (protocol == IPv4.PROTOCOL_TCP) {
            // Pass any packets that its destination is portal or from gateway
            if (destinationMac.equalsIgnoreCase(portalMac)) {
                return CAPTIVE_PORTAL_AUTHORIZED;
            } else if (sourceMac.equalsIgnoreCase(gatewayMac)) {
                result = CAPTIVE_PORTAL_AUTHORIZED;
            } else if (!sourceMac.equalsIgnoreCase(gatewayMac) && hostEnable) {
                log.info("user authenticated!!!!!!!!!!!!!!!!!!!! & going to internet");
                result = CAPTIVE_PORTAL_AUTHORIZED;
            } else if (!sourceMac.equalsIgnoreCase(portalMac) && !destinationMac.equalsIgnoreCase(portalMac)) {
                // If the packet is from unauthenticated host and destination is not portal,
                // redirect it to portal
                if (destinationPort.equals("80") || destinationPort.equals("443") ||
                destinationPort.equals("5001") || destinationPort.equals("5000")) {
                    return CAPTIVE_PORTAL_REDIRECT_TO_PORTAL;
                }
            }
        }
        log.info("accessCheck finally return the result: " + result + "sourcePort: "
        + sourcePort + "destinationPort" + destinationPort);
        return result;
    }
}