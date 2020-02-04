when ACCESS_POLICY_AGENT_EVENT {
  if { [ACCESS::policy agent_id] eq "create_ga_secret" } {
    set secret [b64encode [md5 [expr rand()]]]
    set secret [string range $secret 0 9]

    array set b32_alphabet_inv {
       0 A  1 B  2 C  3 D
       4 E  5 F  6 G  7 H
       8 I  9 J 10 K 11 L
      12 M 13 N 14 O 15 P
      16 Q 17 R 18 S 19 T
      20 U 21 V 22 W 23 X
      24 Y 25 Z 26 2 27 3
      28 4 29 5 30 6 31 7
    }

    set secret_b32 ""
    set l [string length $secret]
    set n 0
    set j 0

    # encode loop is outlined in RFC 4648 (http://tools.ietf.org/html/rfc4648#page-8)
    for { set i 0 } { $i < $l } { incr i } {
      set n [expr {$n << 8}]
      set n [expr {$n + [scan [string index $secret $i] %c]}]
      set j [incr j 8]

      while { $j >= 5 } {
        set j [incr j -5]
        append secret_b32 $b32_alphabet_inv([expr {($n & (0x1F << $j)) >> $j}])
      }
    }

    # pad final input group with zeros to form an integral number of 5-bit groups, then encode
    if { $j > 0 } { append secret_b32 $b32_alphabet_inv([expr {$n << (5 - $j) & 0x1F}]) }

    # if the final quantum is not an integral multiple of 40, append "=" padding
    set pad [expr {8 - [string length $secret_b32] % 8}]
    if { ($pad > 0) && ($pad < 8) } { append secret_b32 [string repeat = $pad] }

    log local0. "GA Secret: $secret_b32"
    ACCESS::session data set session.custom.ga.secret $secret_b32
  }
}
