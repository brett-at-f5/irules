// Author: Brett Smith @f5
// index.js for ldap_modify_apm_events_lx
  
// Debug logging control.
// 0 = debug off, 1 = debug level 1, 2 = debug level 2
var debug = 2;
  
// Includes
var f5 = require('f5-nodejs');
var ldap = require('ldapjs');

// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer();  
  
// Start listening for ILX::call and ILX::notify events. 
ilx.listen();

// Unbind LDAP Connection
function ldap_unbind(client){
    client.unbind(function(err) {
        if (err) {
            if (debug >= 1) { console.log('Error Unbinding.'); }
        } else {
            if (debug >= 1) { console.log('Unbind Successful.'); }
        }
    });
}

// LDAP Modify method, requires DN, LDAP Attribute Name and Value
ilx.addMethod('ldap_modify', function(ldap_data, response) {
    
    // LDAP Server Settings
    var bind_url = 'ldaps://10.1.30.101:636';
    var bind_dn = ldap_data.params()[0];
    var bind_pw = ldap_data.params()[1];

    // DN, LDAP Attribute Name and Value from iRule
    var ldap_dn = ldap_data.params()[0];
    var ldap_attribute = ldap_data.params()[2];
    var ldap_value = ldap_data.params()[3];
    
    if (debug >= 2) { console.log('dn: ' + ldap_dn + ',attr: ' + ldap_attribute + ',val: ' + ldap_value); }
    
    var ldap_modification = {};
    ldap_modification[ldap_attribute] = ldap_value;

    var ldap_change = new ldap.Change({
        operation: 'replace',
        modification: ldap_modification
    });

    if (debug >= 1) { console.log('Creating LDAP Client.'); }
    
    // Create LDAP Client
    var ldap_client = ldap.createClient({
        url: bind_url,
        tlsOptions: { 'rejectUnauthorized': false } // Ignore Invalid Certificate - Self Signed etc..
    });

    // Bind to the LDAP Server
    ldap_client.bind(bind_dn, bind_pw, function(err) {
        if (err) {
            if (debug >= 1) { console.log('Error Binding to: ' + bind_url); }
            response.reply('1'); // Bind Failed
            return;
        } else {
            if (debug >= 1) { console.log('LDAP Bind Successful.'); }
            
            // LDAP Modify
            ldap_client.modify(ldap_dn, ldap_change, function(err) {
                if (err) {
                    if (debug >= 1) { console.log('LDAP Modify Failed.'); }
                    ldap_unbind(ldap_client);
                    response.reply('2'); // Modify Failed
                } else {
                    if (debug >= 1) { console.log('LDAP Modify Successful.'); }
                    ldap_unbind(ldap_client);
                    response.reply('0'); // No Error
                }
            });
        }
    });
});
