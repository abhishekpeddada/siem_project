rule PhishingEmailClick
{
  meta:
    author = "flask-siem"
    description = "Detect suspicious email sender or click"
    threshold = "1"
    window_seconds = "3600"
    group_by_regex = "from=\\\"([^\\\"]+)\\\""

  strings:
    $a = "EMAIL_RECEIVED" ascii
    $b = "secure-microsoft-login.com" ascii
    $c = "EMAIL_CLICK" ascii
    $d = /from="[^"]+"/

  condition:
    (($a and $b and $d) or $c)
}
