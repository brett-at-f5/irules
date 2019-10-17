#**
#** Name: log_dns_category_hsl_irule
#** Author: brett-at-f5
#** Version: 1.0
#** Description: Logs DNS Request and Responses to HSL publisher with URL and IPI Category
#**

when DNS_REQUEST priority 100 {
  set hsl [HSL::open -publisher /Common/elk_log_5402_pub]

  set category ""

  # If the Question Type is A or AAAA, then log the URL Category 
  if { ([DNS::question type] eq "A" || [DNS::question type] eq "AAAA") } {
    # Determine the URL Category for the Question Name.
    set category [lindex [CATEGORY::lookup http://[DNS::question name]] 0]
    set category [getfield $category "/" 3]
    set category [string map {"_" " "} $category]
  }

  # Log DNS Request details
  HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=\"[virtual]\",ptype=\"[DNS::ptype]\",origin=\"[DNS::origin]\",opcode=\"[DNS::header opcode]\",id=[DNS::header id],name=\"[DNS::question name]\",class=\"[DNS::question class]\",dns_type=\"[DNS::question type]\",category=\"$category\",cs_source_ip=[IP::client_addr],cs_dest_ip=[clientside {IP::local_addr}]"
}

when DNS_RESPONSE {
  set hsl [HSL::open -publisher /Common/elk_log_5402_pub]

  set category ""
  set ss_source_ip ""
  set ss_dest_ip ""

  if { [DNS::ptype] eq "ANSWER" } {
    foreach rr [DNS::answer] {
      if { [DNS::origin] eq "SERVER" } {
        set ss_source_ip [serverside {IP::local_addr}]
        set ss_dest_ip [LB::server addr]
      }

      if { [DNS::type $rr] eq "A" } {
        set category [IP::reputation [DNS::rdata $rr]]
      }

      # Log DNS Response via HSL
      HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=\"[virtual]\",ptype=\"[DNS::ptype]\",origin=\"[DNS::origin]\",rcode=\"[DNS::header rcode]\",id=[DNS::header id],name=\"[DNS::name $rr]\",class=\"[DNS::class $rr]\",dns_type=\"[DNS::type $rr]\",ttl=[DNS::ttl $rr],rdata=\"[DNS::rdata $rr]\",category=\"$category\",cs_source_ip=[IP::client_addr],cs_dest_ip=[clientside {IP::local_addr}],ss_source_ip=$ss_source_ip,ss_dest_ip=$ss_dest_ip"
    }
  } else {
    if { [DNS::origin] eq "SERVER" } {
      set ss_source_ip [serverside {IP::local_addr}]
      set ss_dest_ip [LB::server addr]
    }
    # Log DNS Response via HSL
    HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=\"[virtual]\",ptype=\"[DNS::ptype]\",origin=\"[DNS::origin]\",rcode=\"[DNS::header rcode]\",id=[DNS::header id],name=\"[DNS::question name]\",class=\"[DNS::question class]\",dns_type=\"[DNS::question type]\",cs_source_ip=[IP::client_addr],cs_dest_ip=[clientside {IP::local_addr}],ss_source_ip=$ss_source_ip,ss_dest_ip=$ss_dest_ip"
  }
}
