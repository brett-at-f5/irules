#**
#** Name: dns_security_filter_irule
#** Author: brett-at-f5
#** Description: https://devcentral.f5.com/articles/dns-interception-protecting-the-client
#**

#
# This iRule is applied to a DNS resolver (DNS Profile required) or a catch all (0.0.0.0/0:53) DNS virtual server where the BIG-IP is a default GW.
#
# Configurable Parameters for DNS_REQUEST filtering:
# 1. DNS Request Filtering On or Off - Enable or Disable all DNS_REQUEST filtering.
# 2. URL Categories e.g. Adult_Content, Hacking. If the DNS Question (FQDN - e.g. playboy.com) matches a category in the data group (default: dns_request_url_categories_dg), 
# NXDOMAIN will be returned in the response. To obtain a list of possible URL Categories and their descriptions, run: tmsh list sys url-db url-category { description }
# 3. DNS Question Type e.g. A, AAAA, ANY etc. Only the Question Types configured in the data group (default: dns_request_question_type_dg) will be filtered.
# 4. FQDN/TLD Whitelist e.g. f5.com or .gov. Any FQDN/Domain in the whitelist data group will bypass DNS_REQUEST filtering regardless of the Question Type or URL Category.
#
# Configurable Parameters for DNS_RESPONSE filtering:
# 1. DNS Response Filtering On or Off - Enable or Disable all DNS_RESPONSE filtering.
# 2. IP/Subnet Whitelist e.g 192.168.0.0/16 or 1.1.1.1. Any IP or IP Subnet in the whitelist data group will bypass DNS_RESPONSE filtering.
# 3. IPI Threat Categories e.g. Spam Sources, Phishing. If the DNS RDATA (A & AAAA only) matches a category in the data group, NXDOMAIN will be returned in the response.
#
# Global Parameters
# 1. Logging Control - Off, Level 1 (NXDOMAIN and Whitelist Matching) and Level 2 (All DNS Requests & Responses)
 
when RULE_INIT {
	# DNS Request filtering - URL DB control.
	# 0 = DNS Request filter off, 1 = DNS Request filter on.
	set static::dns_request_filter 1
	# URL categories data group. Any categories (Bot_Networks, etc) in this DG will be blocked based on the DNS question name.
	set static::dns_request_url_categories_dg "dns_request_url_categories_dg"
	# DNS request questions type data group. Question types (A,AAAA,etc) in the DNS request that match the DG will be sent for URL category filtering.
	set static::dns_request_question_type_dg "dns_request_question_type_dg"
	# FQDN whitelist data group. Any FQDN/Domain in this DG will bypass DNS request URL category filtering.
	set static::dns_request_fqdn_whitelist_dg "dns_request_fqdn_whitelist_dg"
 
	# DNS Response filtering - IP intelligence (reputation) control.
	# 0 = DNS Response filter off, 1 = DNS Response filter on.
	set static::dns_response_filter 1
	# IP address whitelist data group. Any IP or IP Subnet in this DG will bypass DNS response filtering regardless of the IP intelligence (reputation) value.
	# If a AAAA record is contained in the Resource Record (RR), it is also returned in the DNS response.
	set static::dns_response_ip4_whitelist_dg "dns_response_ip_whitelist_dg"
	# IP intelligence categories data group. If the DNS RDATA (A & AAAA only) matches a category in the data group, NXDOMAIN will be returned in the response.
	set static::dns_response_ipi_categories_dg "dns_response_ipi_categories_dg"
 
	# Debug logging control.
	# 0 = logging off, 1 = informational logging, 2 = debug logging
	set static::debug_dns 2
}
 
when DNS_REQUEST {
	if { $static::debug_dns >= 2 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: [DNS::question type]" }
 
	# If DNS Request filtering is enabled, filter the request.
	if { $static::dns_request_filter } {
		# If the Question Name (eg. f5.com) is in the Whitelist, bypass URL filtering.
		if { ![class match [DNS::question name] ends_with $static::dns_request_fqdn_whitelist_dg] } {
			# If the Question Type matches, filter the request.
			if { [class match [DNS::question type] equals $static::dns_request_question_type_dg] } {
				# Determine the URL Category for the Question Name.
				set url_category [lindex [CATEGORY::lookup http://[DNS::question name]] 0]
				# If the URL Category is matched, return NXDOMAIN to the client.
				if { [class match $url_category ends_with $static::dns_request_url_categories_dg] } {
					# URL Category matched - Log.
					if { $static::debug_dns >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: [DNS::question type], URL Category: $url_category - Respond with NXDOMAIN" }
					# Return NXDOMAIN to the client.
					DNS::answer clear
					DNS::header opcode QUERY
					DNS::header rcode NXDOMAIN
					DNS::return
				}
			}
		} else {
			# FQDN/TLD Whitelist matched - Log.
			if { $static::debug_dns >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: [DNS::question type], FQDN/TLD Whitelist: Match Found - Bypass Request Filtering" }
		}
	}
}
 
when DNS_RESPONSE {
	# If Response Filter is enabled, filter the response.
	if { $static::dns_response_filter } {
 
		set threat_categories ""
 
		if { [DNS::ptype] eq "ANSWER" } {
			# Loop through each Resource Record(s).
			foreach rr [DNS::answer] {
				switch [DNS::type $rr] {
					"A" {
						# If the IP is not in the whitelist, filter the response.
						if { ![class match [DNS::rdata $rr] equals $static::dns_response_ip4_whitelist_dg] } {
							set threat_categories [IP::reputation [DNS::rdata $rr]]
							# If a Threat Category is returned and matches, filter the request.
							if { [class match $threat_categories contains $static::dns_response_ipi_categories_dg] } {
								# Threat Category matched - Log.
								if { $static::debug_dns >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: A, Threat Category: $threat_categories - Respond with NXDOMAIN" }
								# Return NXDOMAIN to the client.
								DNS::answer clear
								DNS::header opcode QUERY
								DNS::header rcode NXDOMAIN
							}
 
						} else {
							# IP Whitelist matched - Log.
							if { $static::debug_dns >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: [DNS::question type], IP Whitelist: Match Found - Bypass Response Filtering" }
						}
					}	
 
					"AAAA" {
						# As IP::reputation doesn't support IPv6, use the Threat Category response from the A record. i.e. If the A record is bad assume the AAAA record is also bad.
						if { [class match $threat_categories contains $static::dns_response_ipi_categories_dg] } {
							# Threat Category matched - Log.
							if { $static::debug_dns >= 1 } { log local0. "Client IP: [IP::client_addr], Question: [DNS::question name], Type: AAAA, Threat Category: $threat_categories - Respond with NXDOMAIN" }
							# Return NXDOMAIN to the client.
							DNS::answer clear
							DNS::header opcode QUERY
							DNS::header rcode NXDOMAIN
						}	
					}
				}
			}
		}
	}
	# Log the DNS response
	if { $static::debug_dns >= 2 } { log local0. "Client IP: [IP::client_addr], Answer: [DNS::answer], RCODE: [DNS::header rcode]" }
}
 
#Data Groups:
create ltm data-group internal dns_request_url_categories_dg type string
modify ltm data-group internal dns_request_url_categories_dg records add {"Adult_Content"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Advanced_Malware_Command_and_Control"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Advanced_Malware_Payloads"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Bot_Networks"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Compromised_Websites"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Elevated_Exposure"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Emerging_Exploits"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Files_Containing_Passwords"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Hacking"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Keyloggers"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Malicious_Embedded_Link"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Malicious_Embedded_iFrame"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Malicious_Web_Sites"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Militancy_and_Extremist"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Mobile_Malware"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Newly_Registered_Websites"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Nudity"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Peer-to-Peer_File_Sharing"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Phishing_and_Other_Frauds"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Proxy_Avoidance"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Sex"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Spyware"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Tasteless"}
modify ltm data-group internal dns_request_url_categories_dg records add {"Web_and_Email_Spam"}
 
create ltm data-group internal dns_request_question_type_dg type string
modify ltm data-group internal dns_request_question_type_dg records add {"A"}
modify ltm data-group internal dns_request_question_type_dg records add {"AAAA"}
modify ltm data-group internal dns_request_question_type_dg records add {"ANY"}
modify ltm data-group internal dns_request_question_type_dg records add {"CNAME"}
modify ltm data-group internal dns_request_question_type_dg records add {"MX"}
 
create ltm data-group internal dns_request_fqdn_whitelist_dg type string
modify ltm data-group internal dns_request_fqdn_whitelist_dg records add {"f5.com"}
 
create ltm data-group internal dns_response_ip_whitelist_dg type ip
modify ltm data-group internal dns_response_ip_whitelist_dg records add {"10.0.0.0/8"}
modify ltm data-group internal dns_response_ip_whitelist_dg records add {"172.16.0.0/12"}
modify ltm data-group internal dns_response_ip_whitelist_dg records add {"192.168.0.0/16"}
 
create ltm data-group internal dns_response_ipi_categories_dg type string
modify ltm data-group internal dns_response_ipi_categories_dg records add {"BotNets"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Networks"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Denial of Service"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Illegal"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Infected Sources"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Phishing"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Proxy"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Scanners"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Spam Sources"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Web Attacks"}
modify ltm data-group internal dns_response_ipi_categories_dg records add {"Windows Exploits"}
