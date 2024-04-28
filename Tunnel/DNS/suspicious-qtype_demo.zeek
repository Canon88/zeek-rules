# Extending the Notice type to include a new category for suspicious DNS queries with specific query types (qtype)
redef enum Notice::Type += {
    Suspicious_DNS_Traffic  # New Notice type for suspicious DNS traffic
};

# Redefine the Notice::Info record to include additional fields for tracking specific details
redef record Notice::Info += {
    total_bytes:			count			&log	&optional;  # Total bytes of the DNS request
    related_uid:			set[string] 	&log	&optional;  # UIDs related to the DNS request
    related_qtype: 		    set[string] 	&log	&optional;  # Query types related to the DNS request
    related_prefix: 		set[string] 	&log	&optional;  # Prefixes related to the DNS request
    second_level_domain:	string			&log	&optional;  # Second-level domain of the DNS request
};

# Configuration constant for the time window
const threshold_windows = 5sec &redef;
const max_Length = 30 &redef;  # Maximum length for the domain name
const qtype_name: set[string] = { "MX", "NULL", "TXT", "CNAME" };  # Set of query types to monitor

# Event handler for DNS requests
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( (c$dns$qtype_name ! in qtype_name) || (Site::is_local_name(query)) )
        return;
    
    local query_vec = split_string(query, /[\.]/);
    if ( |query_vec| <= 2 )
        return;

    local sld_vec = query_vec[|query_vec|-2, |query_vec|];
    local prefix_vec = query_vec[0, |query_vec| - 3];
    
    # Second-Level Domain
    local sld = join_string_vec(sld_vec, ".");
    local prefix = join_string_vec(prefix_vec, ".");
    
    # SumStats::observe
    local val_str: string = fmt("%s####%s####%s####%s####%s####%s####%s", c$uid, c$id$orig_h, c$id$resp_h, prefix, sld, c$orig$size, c$dns$qtype_name);
    SumStats::observe("dns_qtype_null_event", [$str=sld], [$str=val_str]);
}

# Initialization event for setting up the statistical summary
event zeek_init() {
    local r1 = SumStats::Reducer($stream="dns_qtype_null_event", $apply=set(SumStats::UNIQUE));
    
    # Set up the statistical analysis parameters
    SumStats::create([
        $name="dns_qtype_null_event.unique", 
        $epoch=threshold_windows,
        $reducers=set(r1),

        # If you need to use a threshold, use the following code.
        # $threshold=Threshold,
        # $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
        #     return result["dns_qtype_null_event"]$num + 0.0;
        # },
        # $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {

        # }

        # Detected 30 suspicious DNS requests in the past 5 seconds, 5 suspicious domain lengths, total bytes transferred 1024.
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
            local hit_count = 0;
            local total_bytes = 0;
            local related_uid: set[string];
            local related_qtype: set[string];
            local related_prefix: set[string];

            # c$uid, c$id$orig_h, c$id$resp_h, prefix, sld, c$orig$size, c$dns$qtype_name
            for (value in result["dns_qtype_null_event"]$unique_vals) {
                local value_vector: vector of string = split_string(value$str, /####/);
                if (|value_vector[3]| >= max_Length) 
                    hit_count += 1;
                
                total_bytes += to_count(value_vector[5]);
                add related_uid[value_vector[0]];
                add related_qtype[value_vector[6]];
                add related_prefix[value_vector[3]];
            }
            
            # Issue a notice if suspicious behavior is observed
            NOTICE([
                $note=Suspicious_DNS_Traffic,
                # Detected 30 suspicious DNS requests in the past 5 seconds, 5 suspicious domain lengths, total bytes transferred 1024.
                $sub=cat("Suspicious DNS traffic"),
                
                $n=|related_uid|,
                $second_level_domain=key$str,
                $total_bytes=total_bytes,
                $related_uid=related_uid,
                $related_qtype=related_qtype,
                $related_prefix=related_prefix,
                $msg=fmt("[+] Detected %d suspicious DNS requests in the last %s (Second Level-Domain: %s) using %d query types, among which %d domain prefixes exceed a length of %d bytes.", |related_uid|, threshold_windows, key$str, |related_qtype|, hit_count, max_Length)
            ]);
        }
    ]);
}