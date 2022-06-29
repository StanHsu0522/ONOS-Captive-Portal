package nctu.winlab.authentication;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.FormParam;

import javax.ws.rs.core.Response;
import java.util.HashMap;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("UserCredential")
public class AuthWebResource extends AbstractWebResource {
    private static HashMap<String, String> ipToMac = new HashMap<String, String>();
    private static HashMap<String, Boolean> userMap = new HashMap<String, Boolean>();
    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    public Response hello() {
        ObjectNode node = mapper().createObjectNode().put("HI", "you GET it !");
        return ok(node).build();
    }

    /**
     * Verify the user credential by sending RADIUS packet to RADIUS server.
     *
     * @return "Access-Accept": this user credential is confirmed by RADIUS server
     *         "Access-Reject": this user credential is rejected by RADIUS server
     *
     * @param user user ID
     * @param pass user Password
     */
    @POST
    @Consumes("application/x-www-form-urlencoded")
    public String userCredentialCheck(@FormParam("user") String user, @FormParam("pass") String pass) {
        Authenticator newUser = new Authenticator();
        String result = newUser.startAuthenticationProcess(newUser.createRequest(user, pass));
        return result;
    }

    /**
     * Insert a authorized user MAC record.
     *
     * If this function is being called, it stands for this user
     * has been authorized, so we record this user's MAC
     *
     * @return 0: this user IP is in our IP to MAC mapping record, and record
     *            authorized user's MAC
     *        -1: this user IP isn't in our IP to MAC mapping record
     *
     * @param newIp user IP
     */
    @POST
    @Path("/insertNewUser")
    @Consumes("application/x-www-form-urlencoded")
    public int insertNewUser(@FormParam("ip") String newIp) {
        if (ipToMac.get(newIp) != null) {
            userMap.put(ipToMac.get(newIp), true);
            return 0;
        }
        return -1;
    }

    /**
     * Check whether this user is a authorized or not.
     *
     * @return true: the user is authorized
     *         false: the user is not authorized
     *
     * @param newIp user IP
     */
    @POST
    @Path("/getUser")
    @Consumes("application/x-www-form-urlencoded")
    public boolean getUser(@FormParam("ip") String newIp) {
        if (ipToMac.get(newIp) != null) {
            if (userMap.get(ipToMac.get(newIp)) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Insert a user IP to MAC mapping.
     *
     * When a user connect to our net and this function would be called
     * to insert this user's IP to MAC mapping
     *
     * @return 0: this user IP is in our IP to MAC mapping record, and record
     *            authorized user's MAC
     *        -1: this user IP isn't in our IP to MAC mapping record
     *
     * @param newIp user IP
     * @param newMac user MAC
     */
    @POST
    @Path("/insertIpMapping")
    @Consumes("application/x-www-form-urlencoded")
    public String insertIpMapping(@FormParam("ip") String newIp, @FormParam("mac") String newMac) {
        ipToMac.put(newIp, newMac);
        return "done";
    }
    @GET
    @Path("/deleteAllUser")
    @Consumes("application/x-www-form-urlencoded")
    public String deleteUser() {
        if (!userMap.isEmpty()) {
            userMap.clear();
            log.info("clean user!!");
        }
        return "clean user done";
    }
}