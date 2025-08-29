rule O365_AdminMailAccess
{
    meta:
        subject = "O365 Admin Email Access"
        description = "Detects when a privileged user accesses a user's mailbox via a specific operation."
        tactic = "Collection"
        technique = "Email Collection"
        severity = "medium"
        confidence = "Medium"
        threshold = "1"
        window_seconds = "3600"
        group_by_regex = "\"UserId\":\"([a-zA-Z0-9\\._%+-]+@[a-zA-Z0-9\\.-]+\\.[a-zA-Z]{2,})\""

    strings:
        // Detect the specific operation name
        $s1 = "\"Operation\":\"AdminMailAccess\""
        // Dynamically capture the user who performed the action
        $s2 = /"UserId":"([a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"/
    
    condition:
        all of ($s*)
}
