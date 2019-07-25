#**
#** Name   : log_l4_udp_nat_hsl_irule
#** Author : brett-at-f5
#** Description: Log L4 UDP NAT connections to HSL Publisher.
#**

when SERVER_CONNECTED {
  set hsl [HSL::open -publisher /Common/elk_log_pub]
  # Log NAT connection
  HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],event=SERVER_CONNECTED,ip_protocol=[IP::protocol],cs_source_ip=[IP::client_addr],cs_source_port=[UDP::client_port],cs_dest_ip=[IP::server_addr],cs_dest_port=[UDP::server_port],ss_source_ip=[IP::local_addr],ss_source_port=[UDP::local_port],ss_dest_ip=[LB::server addr],ss_dest_port=[LB::server port]"
}
