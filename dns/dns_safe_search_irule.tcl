#**
#** Name: dns_safe_search_irule
#** Author: brett-at-f5
#** Description: This iRule will enable Google SafeSearch, Bing Family Filter and Strict Restricted YouTube. Each solution uses a CNAME.
#**

when RULE_INIT {
  # SafeSearch Bypass List (IPv4)
  set static::dns_safe_search_bypass_dg "dns_safe_search_bypass_dg"

  # SafeSearch CNAME Record mapping
  set static::dns_safe_search_cname_dg "dns_safe_search_cname_dg"

  # DNS Resolver
  set static::dns_resolver "/Common/dns_udp_vs"

  # TTL value for CNAME Record
  set static::dns_ttl 30

when DNS_REQUEST priority 100 {
  # If the Client IP is not in the Bypass List, filter enable SafeSearch.
  if { !([class match [IP::client_addr] equals $static::dns_safe_search_bypass_dg]) } {
    # If the FQDN in the data group matches the Question Name, send a DNS Response with the SafeSeach CNAME in data group
    if { (([class match [DNS::question name] equals $static::dns_safe_search_cname_dg]) and ([DNS::question type] eq "A")) } {
 
      set cname [class match -value [DNS::question name] equals $static::dns_safe_search_cname_dg]
      set ipv4  [lindex [RESOLV::lookup @$static::dns_resolver $cname] 0]

      # Send the SafeSeach DNS Response
      DNS::header rcode NOERROR
      DNS::answer insert "[DNS::question name]. $static::dns_ttl [DNS::question class] CNAME $cname"
      DNS::answer insert "$cname. $static::dns_ttl [DNS::question class] A $ipv4"
      DNS::header ra "1"
      DNS::return
    }
  }
}

##** dns_safe_search_bypass_dg Example

ltm data-group internal dns_safe_search_bypass_dg {
    records {
        10.10.10.31/32 { }
        10.10.99.31/32 { }
    }
    type ip
}

##** dns_safe_search_cname_dg Example

ltm data-group internal dns_safe_search_cname_dg {
    records {
        m.youtube.com {
            data restrict.youtube.com
        }
        www.bing.com {
            data strict.bing.com
        }
        www.google.com {
            data forcesafesearch.google.com
        }
        www.google.com.au {
            data forcesafesearch.google.com
        }
        www.youtube-nocookie.com {
            data restrict.youtube.com
        }
        www.youtube.com {
            data restrict.youtube.com
        }
        youtube.googleapis.com {
            data restrict.youtube.com
        }
        youtubei.googleapis.com {
            data restrict.youtube.com
        }
    }
    type string
}
