#**
#** Name: log_dns_irule
#** Author: brett-at-f5
#** Description: Logs DNS Request and Responses to /var/log/ltm
#**

when RULE_INIT {
  # Debug logging control.
  # 0 = no logging, 1 = debug logging (Test/Dev Only).
  set static::log_dns_dbg 1
}

proc log_dns_dbg { log_message } {
  if { $static::log_dns_dbg } {
    log local0.info $log_message
  }
}

when DNS_REQUEST priority 50 {
  # Log DNS Request
  call log_dns_dbg "[virtual],timestamp=[clock clicks -milliseconds],ptype=[DNS::ptype],origin=[DNS::origin],opcode=[DNS::header opcode],id=[DNS::header id],name=[DNS::question name],class=[DNS::question class],dns_type=[DNS::question type],source_ip=[IP::client_addr],dest_ip=[IP::local_addr],server_ip=[LB::server addr]"
}

when DNS_RESPONSE {
  if { [DNS::ptype] eq "ANSWER" } {
    foreach rr [DNS::answer] {
      # Log DNS Response
      call log_dns_dbg "[virtual],timestamp=[clock clicks -milliseconds],ptype=[DNS::ptype],origin=[DNS::origin],rcode=[DNS::header rcode],id=[DNS::header id],name=[DNS::name $rr],class=[DNS::class $rr],dns_type=[DNS::type $rr],ttl=[DNS::ttl $rr],rdata=[DNS::rdata $rr],source_ip=[IP::client_addr],dest_ip=[IP::local_addr],server_ip=[LB::server addr]"
    }
  } else {
    # Log DNS Response
    call log_dns_dbg "[virtual],timestamp=[clock clicks -milliseconds],ptype=[DNS::ptype],origin=[DNS::origin],rcode=[DNS::header rcode],id=[DNS::header id],name=[DNS::question name],class=[DNS::question class],dns_type=[DNS::question type],ttl=,rdata=,source_ip=[IP::client_addr],dest_ip=[IP::local_addr],server_ip=[LB::server addr]"
  }
}
