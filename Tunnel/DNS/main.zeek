## Module designed for detecting suspicious DNS traffic that could indicate DNS tunneling.
module SuspiciousDNSTraffic;

export {
    ################ Payload Overload Detection Configuration ################
    # Setting this option to `T` (true) turns on the detection logic.
    option payload_overload_enable: bool = T;

    # Set the deviation threshold for identifying suspicious DNS payloads
    option deviation_threshold: double = 3.0; # Customize this threshold as needed

    # Set the multiplier threshold for identifying suspicious DNS payloads
    option multiplier_threshold: double = 2.0; # Customize this threshold as needed
    ################ Payload Overload Detection Configuration ################


    ################ Subdomain Overload Detection Configuration ################
    # Setting this option to `T` (true) turns on the detection logic.
    option subdomain_overload_enable: bool = T;

    # Subdomain length threshold, Maximum length for domain name prefixes to be considered suspicious.
    option oversize_subdomain: int = 50;
    ################ Subdomain Overload Detection Configuration ################


    ################ Common Configurations ################
    # Option to enable or disable the filtering of private DNS traffic
    option ignore_private_dns: bool = F;

    # Set of DNS query types to be ignored in the detection of suspicious activities
    option ignore_qtypes: set[string] = { };

    # Set of trusted DNS queries to be ignored
    option ignore_querys: set[string] = { };

    # Set of trusted subdomains to be ignored
    option ignore_subdomains: set[string] = { };

    # Set of trusted domains to be ignored
    option ignore_domains: set[string] = { };

    # Set of trusted top-level domains to be ignored
    option ignore_tlds: set[string] = { };
    
    # Set of regular expressions for top-level domains to be ignored
    option ignore_tlds_regex: pattern = /^[0-9]{1,2}$/;

    # File path to additional detection rules
    redef Config::config_files += { "/usr/local/zeek/share/zeek/site/rules/Tunnel/DNS/config.dat" };
    ################ Common Configurations ################
}