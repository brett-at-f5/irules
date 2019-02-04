#**
#** Name: dns_zone_steering_irule
#** Author: brett-at-f5
#** Description: This iRule will select a DNS server pool based on the Zone Name. The pool name is stored in data group.
#**

when RULE_INIT {
  # DNS Zone to DNS Pool mapping
  set static::dns_zone_pool_mapping_dg "dns_zone_pool_mapping_dg"

  # Debug logging control
  # 0 = logging off, 1 = informational logging, 2 = debug logging
  set static::debug_dns_steering 0
}

when CLIENT_ACCEPTED {
  # Save the name of the default pool
  set default_pool [LB::server pool]
}

when DNS_REQUEST {
  # If the Zone Name in the data group matches the Question Name, send the request to the Pool specified in data group
  if { [class match [DNS::question name] ends_with $static::dns_zone_pool_mapping_dg] } {
    set dns_pool [class match -value [DNS::question name] ends_with $static::dns_zone_pool_mapping_dg]
    if { $static::debug_dns_steering >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: [DNS::question type], Query ID: [DNS::header id],Pool: $dns_pool" }
    pool $dns_pool
  } else {
    if { $static::debug_dns_steering >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: [DNS::question type], Query ID: [DNS::header id], Pool: $default_pool" }
  }
}

when DNS_RESPONSE {
  if { $static::debug_dns_steering >= 2 } { log local0. "Client IP: [IP::client_addr], Answer: [DNS::answer], RCODE: [DNS::header rcode], Query ID: [DNS::header id], DNS Server: [LB::server addr]" }
}

##** Example Data Group
##**

# ltm data-group internal dns_zone_pool_mapping_dg {
#  records {
#    1.1.10.in-addr.arpa {
#      data f5.demo_dns_pool
#    }
#    f5.demo {
#      data f5.demo_dns_pool
#    }
#  }
#  type string
#}
