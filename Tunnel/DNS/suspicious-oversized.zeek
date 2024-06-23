## Module designed for detecting suspicious DNS traffic that could indicate DNS tunneling.
module SuspiciousDNSTraffic;

# Extending the DNS::Info record to include fields indicating if the subdomain or payload is suspicious.
redef record DNS::Info += {
	## Indicates if the domain is suspicious based on a list of manually created domains.
	is_oversize_domain: bool &log &default=F;
};

# Configuration options for DNS traffic analysis.
export {
	# Option to enable or disable the detection feature.
	option oversize_enable: bool = T;

	# Option to enable or disable the filtering of private DNS traffic.
	option filter_private_dns: bool = F;

	# Set of DNS query types to be ignored in the detection of suspicious activities.
	option oversize_ignore_qtypes: set[string] = { };

	# Set of trusted DNS queries to be ignored.
	option oversize_ignore_querys: set[string] = { };

	# Set of trusted subdomains to be ignored.
	option oversize_ignore_subdomains: set[string] = { };

	# Maximum length for domain name prefixes to be considered suspicious.
	option oversize_subdomain: int = 50;

	# File path to additional detection rules.
	redef Config::config_files += { "/usr/local/zeek/share/zeek/site/rules/Tunnel/DNS/suspicious-oversized.dat" };
}

# Event handler for DNS requests
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-10 {
	# Return early if detection is disabled
	if ( ! oversize_enable )
		return;

	if ( ! c$dns?$subdomain )
		return;

    # Return early if the domain is trusted or local
    if (c$dns$is_trusted_domain || c$dns$is_local_domain)
        return;

	# Filter out private DNS traffic if enabled
	if ( filter_private_dns && Site::is_private_addr(c$id$resp_h) )
		return;

	# Filter out queries of types that should be ignored
	if ( c$dns$qtype_name in oversize_ignore_qtypes )
		return;

	# Ignore trusted queries
	if ( query in oversize_ignore_querys )
		return;

	# Ignore trusted subdomains
	if ( c$dns$subdomain in oversize_ignore_subdomains )
		return;

	# Mark the subdomain as suspicious if its length exceeds the threshold
	if ( |c$dns$subdomain| > oversize_subdomain )
		c$dns$is_oversize_domain = T;
}