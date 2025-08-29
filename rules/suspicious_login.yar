rule MDO_SuspiciousAutomationLogin
{
    meta:
        subject = "Suspicious Automation Login"
        description = "Detects successful logins using automation frameworks like Python requests or other scripting tools."
        tactic = "Defense Evasion, Persistence"
        severity = "medium"
        confidence = "High"
        threshold = "1"
        window_seconds = "3600"
        group_by_regex = "\"UserId\":\"([a-zA-Z0-9\\._%+-]+@[a-zA-Z0-9\\.-]+\\.[a-zA-Z]{2,})\""
    
    strings:
        // Detect the operation
        $s1 = "\"Operation\":\"UserLoggedIn\""

        // Detect automation user agents
        $s2 = "python-requests"
        $s3 = "curl/"
        $s4 = "Go-http-client"
        $s5 = "Java"
        $s6 = "axios"
        $s7 = "node-fetch"
    
    condition:
        $s1 and 1 of ($s*)
}
