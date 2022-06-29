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
package nctu.winlab.authentication;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusClient;

import java.util.Dictionary;
import java.util.Properties;
import java.io.IOException;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {Authenticator.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class Authenticator {

    private ApplicationId appId;
    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    private RadiusClient radiusClient;

    private String radiusClientIp = "172.17.0.2"; // Radius server is in the container
    private String radiusSharedSecret = "winlab_radius_share_secret";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    public Authenticator() {
        log.info("RADIUS client created! ");
        radiusClient = new RadiusClient(radiusClientIp, radiusSharedSecret);
    }

    public String startAuthenticationProcess(AccessRequest accessRequest) {
        log.info("Authenticator start to send RADIUS packet to RADIUS server, accessRequest: " + accessRequest);
        RadiusPacket response = null;
        try {
            if (radiusClient == null) {
                log.info("RadiusClient is null.");
            } else {
                response = radiusClient.authenticate(accessRequest);
            }
        } catch (IOException e) {
            log.info("Exception from IO.");
            e.printStackTrace();
        } catch (RadiusException e) {
            log.info("Exception from RADIUS.");
            e.printStackTrace();
        }
        log.info("After sending RADIUS packet to RADIUS server, accessRequest: " + accessRequest);
        if (response == null) {
            log.info("RADIUS response is null.");
            return null;
        } else {
            log.info("Response: " + response.getPacketTypeName() + "\n");
        }
        radiusClient.close();

        return response.getPacketTypeName();
    }

    public AccessRequest createRequest(String userId, String userPassword) {
        AccessRequest accessRequest = new AccessRequest(userId, userPassword);
        log.info("Access Request created!!");
        accessRequest.setAuthProtocol("pap");
        accessRequest.addAttribute("NAS-Identifier", "My localhost NAS~~");
        accessRequest.addAttribute("NAS-IP-Address", "127.0.1.1");
        accessRequest.addAttribute("Service-Type", "Login-User");
        return accessRequest;
    }

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.authentication");
        log.info("nctu.winlab.authentication Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("nctu.winlab.authentication Stopped");
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
