#**
#** Name: log_dns_irule
#** Author: brett-at-f5
#** Description: Logs DNS Request and Responses to /var/log/ltm
#**

when RULE_INIT {
  # Debug logging control.
  # 0 = no logging, 1 = debug logging (Test/Dev Only).
  set static::log_dns_dbg 0
}

proc logger { log_message } {
  if { $static::log_dns_dbg } {
    log local0.info $log_message
  }
}

when DNS_REQUEST {
  set dns_request_msg "ptype=[DNS::ptype],id=[DNS::header id],name=[DNS::question name],class=[DNS::question class],dns_type=[DNS::question type],"
  append dns_request_msg "source_ip=[IP::client_addr],timestamp=[clock seconds]"

  # Log DNS Request details
  call logger $dns_request_msg
}

when DNS_RESPONSE {
  if { [DNS::ptype] eq "ANSWER" } {
    foreach rr [DNS::answer] {
      set dns_response_msg "ptype=[DNS::ptype],id=[DNS::header id],name=[DNS::name $rr],class=[DNS::class $rr],dns_type=[DNS::type $rr],ttl=[DNS::ttl $rr],"
      append dns_response_msg "rdata=[DNS::rdata $rr],source_ip=[IP::client_addr],server_ip=[LB::server addr],timestamp=[clock seconds]"

      # Log DNS Response via HSL
      call logger $dns_response_msg
    }
  }

  if { [DNS::ptype] eq "NXDOMAIN" } {
    set dns_response_msg "ptype=[DNS::ptype],id=[DNS::header id],name=[DNS::question name],class=[DNS::question class],dns_type=[DNS::question type],"
    append dns_response_msg "source_ip=[IP::client_addr],server_ip=[LB::server addr],timestamp=[clock seconds]"

    # Log DNS Response details
    call logger $dns_response_msg
  }
}
