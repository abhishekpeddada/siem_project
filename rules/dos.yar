rule SynFloodDoS
{
  meta:
    author = "flask-siem"
    description = "Multiple TRAFFIC_DENY events for SYN_FLOOD"
    threshold = "10"
    window_seconds = "10"
    group_by_regex = "src_ip=([0-9]{1,3}(\\.[0-9]{1,3}){3})"

  strings:
    $a = "TRAFFIC_DENY" ascii
    $b = "SYN_FLOOD" ascii
    $c = /src_ip=[0-9]{1,3}(\.[0-9]{1,3}){3}/

  condition:
    $a and $b and $c
}
