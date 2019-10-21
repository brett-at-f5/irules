# Author: Brett Smith @f5

when RULE_INIT {
    # Debug logging control.
    # 0 = debug logging off, 1 = debug logging on.
    set static::ldap_modify_debug 1
}

when ACCESS_POLICY_AGENT_EVENT {
    if { [ACCESS::policy agent_id] eq "ldap_modify" } {
        # Get the APM session data
        set dn [ACCESS::session data get session.ad.last.attr.dn]
        set dnpwd [ACCESS::session data get -secure session.ldap.modify.password]
        set ldap_attribute [ACCESS::session data get session.ldap.modify.attribute]
        set ldap_value [ACCESS::session data get session.ldap.modify.value]

        # Basic Error Handling - Don't execute Node.JS if LDAP attribute name or value is null     
        if { (([string trim $ldap_attribute] eq "") or ([string trim $ldap_value] eq "")) } {
            ACCESS::session data set session.ldap.modify.result 255
        } else {
            # Initialise the iRulesLX extension 
            set rpc_handle [ILX::init "ldap_modify_apm_plugin_v2" "ldap_modify_apm_extension"]        
            #set rpc_handle [ILX::init ldap_modify_apm_extension]
            if { $static::ldap_modify_debug == 1 }{ log local0. "rpc_handle: $rpc_handle" }

            # Modify the RPC call to pass the user DN and Password for Node.JS to bind as....
            # Pass the LDAP Attribute and Value to Node.JS and save the iRulesLX response
            set rpc_response [ILX::call $rpc_handle ldap_modify $dn $dnpwd $ldap_attribute $ldap_value ]

            if { $static::ldap_modify_debug == 1 }{ log local0. "rpc_response: $rpc_response" }
            ACCESS::session data set session.ldap.modify.result $rpc_response
        }
    }
}
