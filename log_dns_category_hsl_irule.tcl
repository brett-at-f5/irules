#**
#** Name: log_dns_category_hsl_irule
#** Author: brett-at-f5
#** Description: Logs DNS Request and Responses to HSL publisher including URL Category and IPI Category
#**

when DNS_REQUEST priority 100 {
  set category ""

  set hsl [HSL::open -publisher /Common/elk_log_pub]
  # If the Question Type matches, filter the request.
  if { ([DNS::question type] eq "A" || [DNS::question type] eq "AAAA") } {
    # Determine the URL Category for the Question Name.
    set category [lindex [CATEGORY::lookup http://[DNS::question name]] 0]
    set category [getfield $category "/" 3]
  }

  # Log DNS Request details
  HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],ptype=[DNS::ptype],origin=[DNS::origin],opcode=[DNS::header opcode],id=[DNS::header id],name=[DNS::question name],category=$category,class=[DNS::question class],dns_type=[DNS::question type],cs_source_ip=[IP::client_addr],cs_source_port=[UDP::client_port],cs_dest_ip=[IP::local_addr],cs_dest_port=[UDP::local_port]"
}

when DNS_RESPONSE {
  set categories ""
  set hsl [HSL::open -publisher /Common/elk_log_pub]

  if { [DNS::ptype] eq "ANSWER" } {
    foreach rr [DNS::answer] {
      # Log DNS Response via HSL
      if { [DNS::type $rr] eq "A" } {
            set category [lindex [IP::reputation [DNS::rdata $rr]] 0]
      }

      if { ([LB::server addr] eq "") } {
        set ss_dest_ip ""
        set ss_dest_port ""
      } else {
      	set ss_dest_ip [LB::server addr]
      	set ss_dest_port [LB::server port]
      }
      # Log DNS Response via HSL
      HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],ptype=[DNS::ptype],origin=[DNS::origin],rcode=[DNS::header rcode],id=[DNS::header id],name=[DNS::name $rr],category=$category,class=[DNS::class $rr],dns_type=[DNS::type $rr],ttl=[DNS::ttl $rr],rdata=[DNS::rdata $rr],ss_dest_ip=$ss_dest_ip,ss_dest_port=$ss_dest_port"
    }
  } else {
    # Log DNS Response via HSL
    HSL::send $hsl "timestamp=[clock clicks -milliseconds],vs=[virtual],ptype=[DNS::ptype],origin=[DNS::origin],rcode=[DNS::header rcode],id=[DNS::header id],name=[DNS::question name],category=,class=[DNS::question class],dns_type=[DNS::question type],ttl=,rdata=,ss_dest_ip=[LB::server addr],ss_dest_port=[LB::server port]"
  }
}