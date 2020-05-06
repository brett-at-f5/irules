#**
#** Name   : xp_whitelist_irule
#** Author : brett-at-f5
#** Description: Used in conjunction with an Explicit Proxy configuration (https://github.com/brett-at-f5/tmsh/blob/master/simple_explicit_proxy.tmsh) as Source IP and FQDN Whitelist
#** Version: 1.0
#**

when RULE_INIT {
  ## Debug logging control
  # 0 = no logging, 1 = debug logging (Test/Dev Only).
  set static::xp_dbg 1

  ## Data group containing Source IPs that are allowed regardless of FQDN
  set static::xp_source_ip_allow_dg "xp_source_ip_allow_dg"
  
  ## Data group containing FQDNs that are allowed regardless of Source IP
  set static::xp_fqdn_allow_dg "xp_fqdn_allow_dg"
}

proc log_this { log_message } {
  if { $static::xp_dbg } {
    log local0. "timestamp=[clock clicks -milliseconds],vs=[virtual],$log_message"
  }
}

when CLIENT_ACCEPTED {
  set log_prefix "[IP::client_addr]:[TCP::client_port] --> [IP::local_addr]:[TCP::local_port]"

  # Allow based on Source IP
  if { ([class match [IP::client_addr] equals $static::xp_source_ip_allow_dg] ) } {
    event HTTP_PROXY_REQUEST disable
    call log_this "$log_prefix,decision=allow"
    return
  }
}

when HTTP_PROXY_REQUEST {
  # Strip the port number from the Hostname
  set host [string tolower [lindex [split [HTTP::host] ":"] 0]]
  append log_prefix ",host=$host"

  # Allow based on FQDN
  if { [class match $host ends_with $static::xp_fqdn_allow_dg] } {
    call log_this "$log_prefix,decision=allow"
  } else {
    call log_this "$log_prefix,decision=reject"
    event disable all
    reject
  }
}
