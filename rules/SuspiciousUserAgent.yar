rule SuspiciousUserAgent
{
  meta:
    author = "Cybersecurity Analyst"
    description = "Detects suspicious user agents indicative of scripting tools like Python or Node.js."
    severity = "medium"
    threshold = "1"
    window_seconds = "3600"

  strings:
    // Common Python libraries
    $python1 = "python-requests"
    $python2 = "Python-urllib"
    
    // Node.js HTTP clients
    $node1 = "axios"
    $node2 = "node-fetch"
    
    // Other scripting tools and generic patterns
    $curl = "curl/"
    $wget = "Wget/"
    $go = "Go-http-client"

  condition:
    1 of ($python*) or 1 of ($node*) or 1 of ($curl, $wget, $go)
}
