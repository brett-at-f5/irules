#**
#** Name: log_dns_hsl_irule
#** Author: brett-at-f5
#** Description: Logs DNS Request and Responses to HSL publisher
#**

when DNS_REQUEST {
  set hsl [HSL::open -publisher /Common/elk_log_pub]

  # Log DNS Request details
  HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],ptype=[DNS::ptype],origin=[DNS::origin],opcode=[DNS::header opcode],id=[DNS::header id],name=[DNS::question name],class=[DNS::question class],dns_type=[DNS::question type],source_ip=[IP::client_addr]"
}

when DNS_RESPONSE {
  set hsl [HSL::open -publisher /Common/elk_log_pub]

  if { [DNS::ptype] eq "ANSWER" } {
    foreach rr [DNS::answer] {
      # Log DNS Response via HSL
      HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],ptype=[DNS::ptype],origin=[DNS::origin],rcode=[DNS::header rcode],id=[DNS::header id],name=[DNS::name $rr],class=[DNS::class $rr],dns_type=[DNS::type $rr],ttl=[DNS::ttl $rr],rdata=[DNS::rdata $rr],source_ip=[IP::client_addr],dest_ip=[LB::server addr]"
    }
  }

  if { [DNS::ptype] eq "NXDOMAIN" } {
    # Log DNS Response via HSL
    HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],ptype=[DNS::ptype],origin=[DNS::origin],rcode=[DNS::header rcode],id=[DNS::header id],name=[DNS::question name],class=[DNS::question class],dns_type=[DNS::question type],source_ip=[IP::client_addr],dest_ip=[LB::server addr]"
  }
}
