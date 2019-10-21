when ACCESS_POLICY_AGENT_EVENT {
  if { [ACCESS::policy agent_id] eq "verify_ga_otp" } {

    set ga_code_attempt [ACCESS::session data get session.logon.last.otp] 
    set ga_key [ACCESS::session data get session.custom.ga.secret]
    set ga_result 1

    # check that a valid key was retrieved, then proceed
    if { [string length $ga_key] == 16 } {

      # begin - Base32 decode to binary

      # Base32 alphabet (see RFC 4648)
      array set static::b32_alphabet {
       A 0  B 1  C 2  D 3
       E 4  F 5  G 6  H 7
       I 8  J 9  K 10 L 11
       M 12 N 13 O 14 P 15
       Q 16 R 17 S 18 T 19
       U 20 V 21 W 22 X 23
       Y 24 Z 25 2 26 3 27
       4 28 5 29 6 30 7 31
      }

      set ga_key [string toupper $ga_key]
      set l [string length $ga_key]
      set n 0
      set j 0
      set ga_key_bin ""

      for { set i 0 } { $i < $l } { incr i } {
        set n [expr {$n << 5}]
        set n [expr {$n + $static::b32_alphabet([string index $ga_key $i])}]
        set j [incr j 5]

        if { $j >= 8 } {
          set j [incr j -8]
          append ga_key_bin [format %c [expr {($n & (0xFF << $j)) >> $j}]]
        }
      }

      # end - Base32 decode to binary

      # begin - HMAC-SHA1 calculation of Google Auth token

      set time [binary format W* [expr {[clock seconds] / 30}]]
      set ipad ""
      set opad ""

      for { set j 0 } { $j < [string length $ga_key_bin] } { incr j } {
        binary scan $ga_key_bin @${j}H2 k
        set o [expr 0x${k} ^ 0x5C]
        set i [expr 0x${k} ^ 0x36]
        append ipad [format %c $i]
        append opad [format %c $o]
      }

      while { $j < 64 } {
        append ipad 6
        append opad \\
        incr j
      }

      binary scan [sha1 $opad[sha1 ${ipad}${time}]] H* token

      # end - HMAC-SHA1 calculation of Google Auth hex token

      # begin - extract code from Google Auth hex token

      set offset [expr {([scan [string index $token end] %x] & 0x0F) << 1}]
      set ga_code [expr (0x[string range $token $offset [expr {$offset + 7}]] & 0x7FFFFFFF) % 1000000]
      set ga_code [format %06d $ga_code]

      # end - extract code from Google Auth hex token

      #log local0.alert "[ACCESS::policy agent_id], GA Attempt: $ga_code_attempt, GA Code: $ga_code"

      if { $ga_code_attempt eq $ga_code } {
        # code verification successful
        set ga_result 0
      } 
    } 

    # set code verification result in session variable
    ACCESS::session data set session.custom.ga.result $ga_result
  }
}
