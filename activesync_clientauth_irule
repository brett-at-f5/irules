#
# APM Microsoft ActiveSync iRule
# supports client cert based auth for ActiveSync
# v1.0
#
# Author: James Deucker
# Copyright (c) 2014 F5 Networks
#
# Based on the v11.2 and v11.6 system APM activesync iRules
# Based on Brett Smith's Client Cert Activesync guide
#

# these static vars come from the system supplied _sys_APM_activesync iRule initialisation
# if an upgrade does not contain the iRule or is renamed then uncomment this event
#when RULE_INIT priority 900 {
#    set static::actsync_401_http_body   "<html><title>Authentication Failured</title><body>Error: Authentication Failure</body></html>"
#    set static::actsync_503_http_body   "<html><title>Service is not available</title><body>Error: Service is not available</body></html>"
#    set static::ACCESS_LOG_PREFIX       "01490000:7:"
#}

# If using this on a single VS with OWA/other services you need to add the ssl_renegotiate iRule attached
# SSL renegotiate HTTP_REQUEST must happen before the apm_activesync iRule

when HTTP_REQUEST priority 200 {
    set http_path [string tolower [HTTP::path]]
    set f_clientless_mode 0

    if { $http_path == "/microsoft-server-activesync" } {
        # process the activesync URI
        # continue the iRule
    } elseif { $http_path == "/autodiscover/autodiscover.xml" } {
        # process the autodiscover URI
        set f_auto_discover 1
        return
    } else {
        # skip this event
        return
    }

    # form the user key from a hash of the user agent and source IP
    # this is used to uniquely identify the user
    # it it turns out to be insufficient I recommend mix in the client certificate serial
    binary scan [md5 "[HTTP::header User-Agent][IP::client_addr]"] H* user_key

    # assume we're not inserting the clientless mode header
    set f_insert_clientless_mode 0
    # fetch the cookie list for this user key
    set apm_cookie_list [ ACCESS::user getsid $user_key ]

    # if we have apm cookies for this user key
    if { [ llength $apm_cookie_list ] != 0 } {
        # fetch their cookies from the APM session
        set apm_cookie [ ACCESS::user getkey [ lindex $apm_cookie_list 0 ] ]
        # if their session has a valid cookie
        if { $apm_cookie != "" } {
           # remove any existing MRHSession cookie from the request
           if { [ HTTP::cookie MRHSession ] != "" } {
               HTTP::cookie remove MRHSession
           }
           # insert a fresh MRHSession cookie from the APM session
           HTTP::cookie insert name MRHSession value $apm_cookie
        } else {
            # flag that we need to inser the clientless mode headers    
           set f_insert_clientless_mode 1
        }
    } else {
        # flag that we need to inser the clientless mode headers    
        set f_insert_clientless_mode 1
    }
    if { $f_insert_clientless_mode == 1 } {
        # insert the clientless-mode header
        HTTP::header insert "clientless-mode" 1
    }
    unset f_insert_clientless_mode
}

when ACCESS_SESSION_STARTED priority 400 {
    # if we have a key from the HTTP_REQUEST then this is a session we process
    if { [ info exists user_key ] } {
        # set their uuid to be their user key (user agent + src ip)
        ACCESS::session data set "session.user.uuid" $user_key
        # tell APM this is an exchange session
        ACCESS::session data set "session.user.microsoft-exchange-client" 1
        # tell APM this is an activesync session
        ACCESS::session data set "session.user.activesync" 1
        if { [ info exists f_auto_discover ] && $f_auto_discover == 1 } {
            # reset the autodiscover flag for the next request
            set f_auto_discover 0
            # tell APM this is an autodiscovery
            ACCESS::session data set "session.user.microsoft-autodiscover" 1
        }
    }
}

when ACCESS_POLICY_COMPLETED priority 400 {
    # if we have a key from the HTTP_REQUEST then this is a session we process
    if { [ info exists user_key ] } {
        switch [ACCESS::policy result] {
            "allow" {
                # the APM policy lets this session through
            }
            "deny" {
                # the APM policy denied this session
                ACCESS::respond 401 content $static::actsync_401_http_body Connection close
                ACCESS::session remove
            }
            default {
                # the APM policy couldn't process this session
                ACCESS::respond 503 content $static::actsync_503_http_body Connection close
                ACCESS::session remove
            }
        }
        unset user_key
    }
}
