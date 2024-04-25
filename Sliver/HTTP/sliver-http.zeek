## This module is designed to detect Sliver HTTP traffic based on specific criteria.
module SliverHttpTraffic;

## Define module-level configuration options.
export {
    ## Option to turn on/off detection.
    option enable: bool = T;
    
    ## Whitelist of IPs that the script should consider.
    option allow_sensor: set[string] = {};
    
    ## Define encoder IDs for cross-referencing.
    option encoder_ids: set[int] = {};
    
    ## Define expected cookie length for validation purposes.
    option cookie_len: int = 32;
    
    ## Path to additional configuration for detection.
    redef Config::config_files += { "/usr/local/zeek/share/zeek/site/rules/Sliver/HTTP/config.dat" };
}

## Extend the built-in notice type to cater to Sliver HTTP traffic alerts.
redef enum Notice::Type += { Sliver_HTTP_Beacon_Traffic };

## Augment the default notice info to capture more specific details about detected Sliver traffic.
redef record Notice::Info += {
    host:   string &log &optional;      # Capture the domain name of the server involved
    uris:   set[string] &log &optional; # Store suspicious URIs accessed
    cookie: string &log &optional;      # Retain the suspicious cookie for analysis
};

## Table to manage state of HTTP connections, mainly using cookies as identifiers.
global http_connection_state: table[string] of string &create_expire=3600sec;

## Decode nonce value to identify the encoder used in traffic encoding.
function decode_nonce(nonce: string): int {
    local nonce_value = to_int(gsub(nonce, /[^[:digit:]]/, ""));
    return nonce_value % 101;
}

## Analyze the HTTP query and decide if it looks suspicious based on method and URI parameters.
function is_suspicious_query(method: string, uri: string): bool {
    local url = decompose_uri(uri);  # Decompose the URI to access its parameters
    local encoder_id: int;

    if (! url?$params) return F;

    # If the method is POST and there are two parameters
    if ((method == "POST") && (|url$params| == 2)) {
        local key_length: table[count] of string;

        for (k, v in url$params) {
            if (|k| > 2) return F;
            key_length[|k|] = v;  # Store parameter length as key
        }

        if ((2 ! in key_length) || (1 ! in key_length)) return F;

        encoder_id = decode_nonce(key_length[1]);
        return encoder_id in encoder_ids;
    }

    # If the method is GET and there is only one parameter
    if ((method == "GET") && (|url$params| == 1)) {
        for (k, v in url$params) {
            if (|k| > 1) return F;

            encoder_id = decode_nonce(v);
            return encoder_id in encoder_ids;
        }
    }

    return F;
}

## Determine if a cookie string looks suspicious based on its length.
function is_suspicious_cookie(cookie: string, suspicious_cookie_len: int): bool {
    local cookies = split_string(split_string(cookie, /;/)[0], /=/);
    return (|cookies| == 2 && |cookies[1]| == suspicious_cookie_len);
}

## Examine completed HTTP messages for suspicious patterns that resemble Sliver beacon traffic.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    # Return early if detection is disabled or sensor IP is not allowed.
    if (! enable || c$http$sensor_ip ! in allow_sensor) return;

    # Only consider server responses
    if (is_orig || ! c?$http || ! c$http?$status_code || ! c$http?$method || ! c$http?$uri) return;
    
    # For POST requests, validate status code and cookie presence
    if (c$http$method == "POST") {
        if (c$http$status_code != 200 || ! c$http?$set_cookie) return;
        if (! is_suspicious_cookie(c$http$set_cookie, cookie_len)) return;
        if (! is_suspicious_query(c$http$method, c$http$uri)) return;

        # Store the cookie for this specific connection for future reference
        http_connection_state[c$http$uid] = split_string(c$http$set_cookie, /;/)[0];
    }

    # For GET requests, check status code and validate the cookie against stored state
    if (c$http$method == "GET") {
        if (c$http$status_code != 204 || ! c$http?$cookie) return;
        if ((c$http$uid ! in http_connection_state) || (c$http$cookie != http_connection_state[c$http$uid])) return;

        # Formulate a unique string for this connection for statistical analysis
        local key_str = fmt("%s#####%s#####%s#####%s#####%s", c$http$uid, c$id$orig_h, c$http$host, c$id$resp_p, c$http$cookie);
        local observe_str = c$http$uri;
        
        # Send this observation for statistical tracking
        SumStats::observe("sliver_http_beacon_traffic_event", [$str=key_str], [$str=observe_str]);
    }
}

## Initialize the statistical mechanisms to further analyze detected patterns.
event zeek_init() {
    # Create a statistical reducer to count unique patterns
    local r1 = SumStats::Reducer($stream = "sliver_http_beacon_traffic_event", $apply = set(SumStats::UNIQUE));
    
    # Set up the statistical analyzer with specific parameters
    SumStats::create([
        $name = "sliver_http_beacon_traffic_event.unique",
        $epoch = 10sec,
        $reducers = set(r1),
        $threshold = 4.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["sliver_http_beacon_traffic_event"]$num + 0.0;
        },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            # If there are 4 instances of the same pattern
            if (result["sliver_http_beacon_traffic_event"]$unique == 4) {
                local key_str_vector: vector of string = split_string(key$str, /#####/);
                local suspicious_uri: set[string];

                for (value in result["sliver_http_beacon_traffic_event"]$unique_vals) {
                    if (! is_suspicious_query("GET", value$str)) return;
                    add suspicious_uri[value$str];
                }

                # Push IoC data to the Intel framework.
                local meta: Intel::MetaData = [$source="Zeek", $desc="from Sliver HTTP beacon Traffic alert", $expire=300sec];
                local ioc = key_str_vector[1];
                local ioc_type = Intel::ADDR;
                local ioc_item: Intel::Item = [
                    $indicator=ioc,
                    $indicator_type=ioc_type,
                    $meta=meta
                ];
                Intel::insert(ioc_item);
                
                local c2_ioc = key_str_vector[2];
                local indicator = split_string(c2_ioc, /:/);

                if ( |indicator| > 1) {
                    c2_ioc = indicator[0];
                }

                local c2_type = Intel::ADDR;
                if ( ! is_valid_ip(c2_ioc) ) {
                    c2_type = Intel::DOMAIN;
                }

                local c2_item: Intel::Item = [
                    $indicator=c2_ioc,
                    $indicator_type=c2_type,
                    $meta=meta
                ];
                Intel::insert(c2_item);

                # Raise a notice for this suspicious activity
                NOTICE([
                    $note=Sliver_HTTP_Beacon_Traffic,
                    $uid=key_str_vector[0],
                    $src=to_addr(key_str_vector[1]),
                    $host=c2_ioc,
                    $p=to_port(key_str_vector[3]),
                    $cookie=key_str_vector[4],
                    $uris=suspicious_uri,
                    $msg=fmt("[+] Sliver HTTP beacon traffic detected, %s -> %s:%s", key_str_vector[1], c2_ioc, key_str_vector[3]),
                    $sub=cat("Sliver HTTP beacon Traffic")
                ]);
            }
        }
    ]);
}

