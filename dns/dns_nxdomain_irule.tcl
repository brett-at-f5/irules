#**
#** Name: dns_nxdomain_irule
#** Author: brett-at-f5
#** Version: 1.0
#** Description: This iRule will check if the DNS Question Name and Question Type matches the Data Group value and send a NXDOMAIN response
#**

when RULE_INIT {
  # Data Group to match against
  set static::dns_fqdn_qtype_map_dg "dns_fqdn_qtype_map_dg"
}


when DNS_REQUEST {
  # Debug DNS Request
  #log local0. "timestamp=[clock clicks -milliseconds],vs=\"[virtual]\",ptype=\"[DNS::ptype]\",origin=\"[DNS::origin]\",opcode=\"[DNS::header opcode]\",id=[DNS::header id],qname=\"[DNS::question name]\",class=\"[DNS::question class]\",dns_type=\"[DNS::question type]\",cs_source_ip=[IP::client_addr],cs_dest_ip=[clientside {IP::local_addr}]"

  # If the FQDN in the data group matches the Question Name and the Question Type is a match send NXDOMAIN
  if { [class match [DNS::question name] equals $static::dns_fqdn_qtype_map_dg] } {
    if { [class lookup [DNS::question name] $static::dns_fqdn_qtype_map_dg] equals [DNS::question type] } {
      # Respond with NXDOMAIN
      DNS::answer clear
      DNS::header rcode NXDOMAIN
      DNS::header ra "1"
      DNS::return
    }
  }
}
