# D-link authentication project - Captive Portal
## Environment
ONOS: 2.2.2
Bazel: 1.1.0
Java: 11.0.8
Ubuntu: 18.04
## Testing steps
* Controller 
    - Data plane IP: `192.168.44.128`
    - Control plane IP: `192.168.20.57`
1. Start RADIUS server in the container
```bash=
user$ docker run -it --rm --privileged winlab/freeradius
(docker)$ freeradius -X
```
2. Start ONOS
```bash=
cd ~/Dlink-onos-2.2.2/authentication && mci -DskipTests
cd ~/Dlink-onos-2.2.2/captiveportal && mci -DskipTests

ok clean
onos-netcfg localhost ~/Dlink-onos-2.2.2/onos-dhcp.json
onos localhost app activate dhcp proxyarp
onos-app localhost install! ~/Dlink-onos-2.2.2/captiveportal/target/captiveportal-1.0-SNAPSHOT.oar
onos-app localhost install! ~/Dlink-onos-2.2.2/authentication/target/authentication-1.0-SNAPSHOT.oar
ping 192.168.44.198 # ping portal web server in order to let onos get its location
```
* Portal web server

```bash=
python3 ~/Dlink-onos-2.2.2/LoginPage/login_http.py
python3 ~/Dlink-onos-2.2.2/LoginPage/login_https.py
```
* Host

Open your browser and surf any website