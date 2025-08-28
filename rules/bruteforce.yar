rule bruteforce_for_an_account
{
 meta:
      subject = "bruteforce for an account"
      description = "It identifies successful login brute force activity for an account i.e., multiple login failures followed by a successful login for the same user account. Brute force (password-guessing) attempts either on publicly identified login pages or moving to other systems on the network."
      tactic = "Credential Access"
      technique = "Brute Force"
      subtechnique = "T1110.001, T1110.003, T1110.004"
      tool = ""
      datasource = "User Account"
      category = ""
      product = ""
      logsource = "Access Point, EDR, Firewall, Email, NGFW, Iaas, Database, SSO, Network Security Monitor(NSM), Web Server, Switch, WLANController, Operating System, Windows Events, Virtulization, Email Gateway"
      actor = ""
      malware = ""
      vulnerability = ""
      custom = "Identity"
      confidence = "Medium"
      severity = "Medium"
      falsePositives = "None"
      externalSubject = "0"
      externalMITRE = "0"
      version = "2"
      threshold = "5"
      window_seconds = "3600"
      // 🛠️ FIXED: Escaped the backslashes with a double backslash
      group_by_regex = "\"UserId\":\"([a-zA-Z0-9\\._%+-]+@[a-zA-Z0-9\\.-]+\\.[a-zA-Z]{2,})\""


 strings:
        $s1 = "\"Operation\":\"UserLoginFailed\""
        $s2 = /"UserId":"([a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"/

 condition:
    $s1 and $s2
}
