rule BruteForceFailedLogins
{
  meta:
    author = "flask-siem"
    description = "Detect repeated auth failures from same IP"
    threshold = "5"
    window_seconds = "60"
    group_by_regex = "src_ip=([0-9]{1,3}(\\.[0-9]{1,3}){3})"

  strings:
    $a = "AUTH_FAIL" ascii
    $b = /user=[A-Za-z0-9_]+/
    $c = /src_ip=[0-9]{1,3}(\.[0-9]{1,3}){3}/

  condition:
    ($a and $c) or ($b and $c)
}
