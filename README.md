# brewmonitor
Python based brewometer BLE listening program.
It was designed to run on a RaspberryPi however any Linux box capable of running the BlueZ stack can be utilized
as the host.

This program listens for BLE beacon transmissions from a `brewometer` and publishes the information to:
 - MQTT topic
 
# TODO
 - Implement an MQTT consumer
 - Implement data submission to an HTTP service
 
# References 
Brewometer - www.brewometer.net
 
