#**
#** Name: extract_upn_apm_event_irule
#** Author: brett-at-f5
#** Description: This iRule will Extract the User Principal Name (UPN) from a x.509 client certificate extension.
#**

when ACCESS_POLICY_AGENT_EVENT {
  if { [ACCESS::policy agent_id] eq "extract_upn" } {
    if { [ACCESS::session data get session.ssl.cert.x509extension] contains "othername:UPN<" } {
      ACCESS::session data set session.logon.last.upn [findstr [ACCESS::session data get session.ssl.cert.x509extension] "othername:UPN<" 14 ">"]
    }
  }
}
