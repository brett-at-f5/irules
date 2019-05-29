#**
#** Name: dns_conditional_forwarding_irule
#** Author: brett-at-f5
#** Description:
#**  - This iRule will select a DNS server pool based on the Zone Name and forward the query.
#**  - It also supports sending NULL DNS or NXDOMAIN response for a Zone or FQDN.
#**  - The Pool Name is stored in data group specified in the RULE_INIT variable.
#**  - If the Pool Members are actively monitored and marked down, a NXDOMAIN response will be sent to the client.
#**

when RULE_INIT {
  # DNS Zone to DNS Pool map Data Group
  set static::dns_zone_pool_map_dg "dns_zone_pool_map_dg"

  # TTL value for NULL response
  set static::null_ttl 30
}

when CLIENT_ACCEPTED {
  # Save the name of the Pool attached to the Virtual Server
  set default_pool [LB::server pool]
}

proc nxdomain {
  DNS::answer clear
  DNS::header rcode NXDOMAIN
  DNS::header ra "1"
  DNS::return
}

when DNS_REQUEST priority 200 {
  # If the Zone Name in the data group matches the Question Name, send the request to the Pool Name specified in data group
  if { [class match [DNS::question name] ends_with $static::dns_zone_pool_map_dg] } {
    # Disable DNS Express (DNSX) - If the Zone Name is also in DNSX, this will override DNSX response
    DNS::disable dnsx
    # Get the Pool Name value from the data group
    set dns_pool [string trim [class match -value [DNS::question name] ends_with $static::dns_zone_pool_map_dg]]

    switch $dns_pool {
      "0.0.0.0" {
        # Send a NULL response
        if { ([DNS::question type] eq "A") } {
          DNS::header rcode NOERROR
          DNS::header ra "1"
          DNS::answer insert "[DNS::question name]. $static::null_ttl [DNS::question class] [DNS::question type] 0.0.0.0"
          DNS::return
        }
      }
      "NXDOMAIN" {
        # Send NXDOMAIN response
        call nxdomain
      }
      "" {
        # Do nothing - Unconditional Forward (Load Balance) to the Pool attached to the Virtual Server
      }
      default {
        # Use the Pool Name value from the data group. If the Pool doesn't exist, respond with NXDOMAIN.
        if { [catch {pool $dns_pool}] } {
          log local0.err "ERROR: $dns_pool doesn't exist for [DNS::question name]."
          call nxdomain
        } else {
          # If all Pool Members are down - Conditional Forwarder is not available, respond with NXDOMAIN.
          if { [active_members $dns_pool] < 1 } {
            log local0.err "ERROR: All $dns_pool members are down for [DNS::question name]."
            call nxdomain
          } else {
            pool $dns_pool
          }
        }
      }
    }
  } 
}
