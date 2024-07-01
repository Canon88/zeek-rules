## Module designed for detecting suspicious DNS traffic that could indicate DNS tunneling.
module SuspiciousDNSTraffic;

# Extending the DNS::Info record to include fields indicating if the subdomain or payload is suspicious.
redef record DNS::Info += {
    ## Indicates if the domain is suspicious based on a list of manually created domains.
    is_oversize_domain: bool &log &default=F;
};

# Event handler for DNS requests
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-10 {
    if ( ! c?$dns )
        return;
    
    # Return early if detection is disabled
    if ( ! subdomain_overload_enable )
        return;

    # Ignore DNS requests that do not contain a domain, top-level domain, or subdomain
    if ( (! c$dns?$domain) || (! c$dns?$tld) || (! c$dns?$subdomain) )
        return;

    # Return early if the domain is trusted or local
    if (c$dns$is_trusted_domain || c$dns$is_local_domain)
        return;

    # Filter out private DNS traffic if enabled
    if ( ignore_private_dns && Site::is_private_addr(c$id$resp_h) )
        return;

    # Filter out queries of types that should be ignored
    if ( c$dns$qtype_name in ignore_qtypes )
        return;

    # Ignore trusted queries
    if ( query in ignore_querys )
        return;

    # Ignore trusted subdomains
    if ( c$dns$subdomain in ignore_subdomains )
        return;

    # Ignore trusted domains
    if ( c$dns$domain in ignore_domains )
        return;

    # Ignore trusted top-level domains
    if ( (c$dns$tld in ignore_tlds) || (ignore_tlds_regex in c$dns$tld) )
        return;

    # Mark the subdomain as suspicious if its length exceeds the threshold
    if ( |c$dns$subdomain| > oversize_subdomain )
        ## Set the flag to true if the subdomain length exceeds the threshold
        c$dns$is_oversize_domain = T;
}