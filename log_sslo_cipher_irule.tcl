#**
#** Name   : log_sslo_cipher_irule
#** Author : Brett Smith, <brett-at-f5>
#** Description: Log Client and Server Cipher Version and Name on transparent SSL/TLS forward proxy Virtual Servers
#**

when CLIENT_ACCEPTED {
  set sni_exists 0
}

when CLIENTSSL_CLIENTHELLO {
  # Is this a TLS connection? 99% of clients support SNI. SNI should be sent in the Client Hello if true.
  # Will not work for SSLv3 clients, but they should be denied anyway
  set sni_exists [SSL::extensions exists -type 0]
}

when HTTP_REQUEST {
  # If TLS connection, save the Client Cipher Version and Name.
  if { $sni_exists } {
    set ssl_string "Client SSL: [SSL::cipher version] [SSL::cipher name]"
  }
}

when HTTP_RESPONSE {
  # Log the TCP connection
  set log_string "TCP: [IP::client_addr]:[TCP::client_port] ([IP::local_addr]:[TCP::local_port]) --> [IP::server_addr]:[TCP::server_port], "

  # If TLS connection, log the Client and Server Cipher Version and Name
  if { $sni_exists } {
    append log_string "$ssl_string, "
    append log_string "Server SSL: [SSL::cipher version] [SSL::cipher name]"
  # If not TLS, i.e. HTTP, set as Null
  } else {
    append log_string "Client SSL: Null, "
    append log_string "Server SSL: Null"
  }
  log local0. $log_string
}
