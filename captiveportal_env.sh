onos-netcfg localhost ~/ONOS-Captive-Portal/onos-dhcp.json
onos localhost app activate dhcp proxyarp
onos-app localhost install! ~/ONOS-Captive-Portal/authentication/target/authentication-1.0-SNAPSHOT.oar
onos-app localhost install! ~/ONOS-Captive-Portal/captiveportal/target/captiveportal-1.0-SNAPSHOT.oar
ping -c 5 192.168.44.198
