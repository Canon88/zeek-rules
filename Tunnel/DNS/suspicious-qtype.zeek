## Module designed for detecting suspicious DNS traffic that could indicate DNS tunneling.
module SuspiciousDNSTraffic;

# Configuration options for DNS traffic analysis.
export {
    # Enable or disable the detection feature.
    option enable: bool = T;

    # Set of DNS query types to be monitored for suspicious activities.
    option qtype_names: set[string] = { "MX", "NULL", "TXT", "CNAME" };

    # Set of second-level domains that are excluded from monitoring.
    option second_level_domains: set[string] = {};

    # File path to additional detection rules.
    redef Config::config_files += { "/usr/local/zeek/share/zeek/site/rules/Tunnel/DNS/suspicious-qtype.dat" };
}

# Time window for analyzing DNS traffic for suspicious patterns.
const threshold_window = 5sec &redef;

# Maximum length for domain name prefixes to be considered suspicious.
const max_Length = 30 &redef;

# Extending the Notice type to include suspicious DNS traffic.
redef enum Notice::Type += {
    Suspicious_DNS_Traffic  # New category for DNS-related alerts
};

# Extending the Notice::Info record for additional details on suspicious DNS activity.
redef record Notice::Info += {
    total_bytes:            count           &log    &optional;  # Total bytes of DNS queries and responses
    related_uid:            set[string]     &log    &optional;  # Set of unique identifiers for related connections
    related_qtype:          set[string]     &log    &optional;  # Set of DNS query types considered suspicious
    related_prefix:         set[string]     &log    &optional;  # Set of domain name prefixes from the DNS queries
    second_level_domain:    string          &log    &optional;  # Second-level domain identified in the DNS queries
};

# Event handler for DNS requests.
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Return early if detection is disabled.
    if ( ! enable )
        return;

    # Filter out queries not in the specified types or to local domains.
    if ( (c$dns$qtype_name ! in qtype_names) || (Site::is_local_name(query)) )
        return;
    
    # Split the query into components to extract second-level domain and prefix.
    local query_vec = split_string(query, /[\.]/);
    # Ensure there's a subdomain and a second-level domain.
    if ( |query_vec| < 3 )
        return;

    local sld = query_vec[|query_vec|-2] + "." + query_vec[|query_vec|-1];
    local prefix = join_string_vec(query_vec[0, |query_vec| - 2], ".");

    # Skip monitoring for domains in the exclusion list.
    if (sld in second_level_domains)
        return;
    
    # Prepare data for statistical analysis.
    local val_str: string = fmt("%s####%s####%s####%s####%s####%s####%s", c$uid, c$id$orig_h, c$id$resp_h, prefix, sld, c$orig$size, c$dns$qtype_name);
    # Register the query for further observation.
    SumStats::observe("suspicious_dns_qtype_event", [$str=sld], [$str=val_str]);
}

# Initialization event for DNS request analysis.
event zeek_init() {
    # Define a reducer for tracking unique DNS queries.
    local reducer_unique = SumStats::Reducer($stream="suspicious_dns_qtype_event", $apply=set(SumStats::UNIQUE));
    
    # Configure statistical analysis for DNS requests.
    SumStats::create([
        $name="suspicious_dns_qtype_event.unique", 
        $epoch=threshold_window,  # Analysis time window
        $reducers=set(reducer_unique),

        # Function called at the end of each analysis window.
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
            local hit_count = 0;  # Count of suspicious prefixes
            local total_bytes = 0;  # Total bytes observed in queries
            local related_uids: set[string];  # Collecting connection IDs
            local related_qtypes: set[string];  # Collecting suspicious query types
            local related_prefixes: set[string];  # Collecting domain prefixes

            # Parse each unique value for detailed analysis.
            for (value in result["suspicious_dns_qtype_event"]$unique_vals) {
                local value_vector: vector of string = split_string(value$str, /####/);
                if (|value_vector[3]| > max_Length)
                    hit_count += 1;
                
                total_bytes += to_count(value_vector[5]);
                add related_uids[value_vector[0]];
                add related_qtypes[value_vector[6]];
                add related_prefixes[value_vector[3]];

                # Push IoC data to the Intel framework.
                local ioc_meta: Intel::MetaData = [$source="Zeek", $desc="from Suspicious DNS Traffic alert", $expire=300 sec];
                local ioc_indicator = value_vector[3] + "." + key$str;
                local ioc_type = Intel::DOMAIN;
                local item: Intel::Item = [
                    $indicator=ioc_indicator,
                    $indicator_type=ioc_type,
                    $meta=ioc_meta
                ];
                Intel::insert(item);
            }
            
            # Generate a notice if suspicious patterns are found.
            if (|related_uids| > 0) {
                NOTICE([
                    $note=Suspicious_DNS_Traffic,
                    $sub=fmt("Possible DNS Tunneling Detected for SLD %s", key$str),
                    $n=|related_uids|,
                    $second_level_domain=key$str,
                    $total_bytes=total_bytes,
                    $related_uid=related_uids,
                    $related_qtype=related_qtypes,
                    $related_prefix=related_prefixes,
                    $msg=fmt("[+] Detected %d suspicious DNS requests over %s. Second-level domain: '%s', using %d query types, %d domain prefixes exceeding %d bytes in length.",
                              |related_uids|, threshold_window, key$str, |related_qtypes|, hit_count, max_Length)
                ]);
            }
        }
    ]);
}
