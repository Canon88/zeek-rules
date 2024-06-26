module SuspiciousDNSTraffic;

# Extend the DNS::Info record to include custom fields
redef record DNS::Info += {
    payload_prev_avg: count &log &optional; # Previous average payload size
    payload_prev_sd: count &log &optional;  # Previous standard deviation of payload size

    payload_len: count &log &optional;      # Length of the DNS payload
    
    avg_threshold: double &log &optional;   # Threshold based on average payload size
    sd_threshold: double &log &optional;    # Threshold based on standard deviation of payload size

    # Indicates if the payload size is suspicious
    is_oversize_payload: bool &log &default=F; # Flag indicating if the payload size is suspicious
    alert_reason: set[string] &log &optional;  # Reasons for alert if payload is suspicious
};

# Global variable for baseline interval
const baseline_interval: interval = 300sec &redef; # Baseline interval for SumStats collection

export {
    # Define a record type to store the average and standard deviation
    type Stats: record {
        prev_avg: count; # Previous average payload size
        prev_sd: count;  # Previous standard deviation of payload size
    };

    # Define a table to store the data
    option data: table[string] of Stats;
}

# Event handler for DNS messages
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=-10 {
    # Return early if detection is disabled
    if (! payload_overload_enable)
        return;
    
    # Return early if the DNS query is not present or if the connection is from the originator
    if ( ! c?$dns || ! c$dns?$query || is_orig)
        return;

    # Ignore DNS over UDP
    local proto = get_port_transport_proto(c$id$orig_p);
    if ("tcp" == cat(proto))
        return;

    # Return early if the domain is local
    if (c$dns$is_local_domain)
        return;

    # Filter out private DNS traffic if enabled
    if (ignore_private_dns && Site::is_private_addr(c$id$resp_h))
        return;

    # Filter out queries of types that should be ignored
    if (c$dns$qtype_name in ignore_qtypes)
        return;

    # Ignore trusted queries
    if (c$dns$query in ignore_querys)
        return;
    
    #  Ignore trusted subdomains
    if ( (c$dns?$subdomain) && (c$dns$subdomain in ignore_subdomains) )
        return;

    # Ignore trusted domains
    if ( (c$dns?$domain) && (c$dns$domain in ignore_domains) )
        return;

    # Ignore trusted top-level domains
    if ( (c$dns?$tld) && ( (c$dns$tld in ignore_tlds) || (ignore_tlds_regex in c$dns$tld) ) )
        return;
    
    # Store the payload size in the DNS::Info record
    c$dns$payload_len = len;

    # Observe the payload size for SumStats calculations
    SumStats::observe("dns_payload_len", SumStats::Key($str=c$dns$qtype_name), SumStats::Observation($num=len));

    if (c$dns$qtype_name in data) {
        local avg = data[c$dns$qtype_name]$prev_avg;
        local sd = data[c$dns$qtype_name]$prev_sd;

        local max_avg_threshold = avg * multiplier_threshold;
        local min_avg_threshold = avg / multiplier_threshold;
        local max_sd_threshold = avg + sd * deviation_threshold;
        local min_sd_threshold = avg - sd * deviation_threshold;

        # Compare the current payload size with the calculated average and standard deviation
        if ( avg != 0.0 ) {
            local alert_reason: set[string] = set();
            if ( len > max_avg_threshold ) {
                c$dns$is_oversize_payload = T;
                c$dns$avg_threshold = max_avg_threshold;
                add alert_reason["payload_len > avg_threshold"];
            } else if ( len < min_avg_threshold ) {
                c$dns$is_oversize_payload = T;
                c$dns$avg_threshold = min_avg_threshold;
                add alert_reason["payload_len < avg_threshold"];
            }

            if ( len > max_sd_threshold ) {
                c$dns$is_oversize_payload = T;
                c$dns$sd_threshold = max_sd_threshold;
                add alert_reason["payload_len > sd_threshold"];
            } else if ( len < min_sd_threshold ) {
                c$dns$is_oversize_payload = T;
                c$dns$sd_threshold = min_sd_threshold;
                add alert_reason["payload_len < sd_threshold"];
            }

            if ( |alert_reason| > 0 ) {
                c$dns$alert_reason = alert_reason;
            }
        }

        # c$dns$payload_prev_avg = avg;
        # c$dns$payload_prev_sd = sd;
    }
}

# Initialize the event handler for analyzing DNS requests
event zeek_init() {
    # Define a reducer to calculate the standard deviation of DNS payload sizes
    local r_std_dev = SumStats::Reducer($stream="dns_payload_len", $apply=set(SumStats::STD_DEV));

    # Create a SumStats object to collect data every baseline_interval (e.g. 5 minutes)
    SumStats::create([
        $name = "dns_payload_len.std_dev",
        $epoch = baseline_interval,
        $reducers = set(r_std_dev),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = { 
            local current_avg = double_to_count(result["dns_payload_len"]$average);
            local current_std_dev = double_to_count(result["dns_payload_len"]$std_dev);

            # Initialize the table with the given data
            data[key$str] = [$prev_avg = current_avg, $prev_sd = current_std_dev];

            # Update the data table with the new values
            Config::set_value("SuspiciousDNSTraffic::data", data);
        }
    ]);
}
