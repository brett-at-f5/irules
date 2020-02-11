#**
#** Name   : log_udp_nat_hsl_irule
#** Author : brett-at-f5
#** Description: Log UDP NAT connections to HSL Publisher.
#**

when SERVER_CONNECTED {
  set hsl [HSL::open -publisher /Common/hsl_log_5400_pub]
  # Log NAT connection
  HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],event=SERVER_CONNECTED,ip_protocol=[IP::protocol],cs_source_ip=[IP::client_addr],cs_source_port=[UDP::client_port],cs_dest_ip=[clientside {IP::local_addr}],cs_dest_port=[clientside {UDP::local_port}],ss_source_ip=[IP::local_addr],ss_source_port=[UDP::local_port],ss_dest_ip=[LB::server addr],ss_dest_port=[LB::server port]"
}
