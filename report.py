import sys
import json
import texttable

# MAIN
# Prints an ASCII text report summarizing the results
# Get args from command line
if len(sys.argv) != 3:
    print("Usage: python3 report.py input_file.json output_file.txt")
    sys.exit(1)
input_file = sys.argv[1]
output_file = sys.argv[2]


try:
    output_f = open(output_file, "w")


    with open(input_file) as input_f:
        input_json = json.load(input_f)

        full_table = texttable.Texttable()
        full_table.set_deco(texttable.Texttable.HEADER)
        full_table.set_cols_align(["l", "l"])
        
        rtt_table = texttable.Texttable()
        rtt_table.set_deco(texttable.Texttable.HEADER)
        rtt_table.set_cols_align(["l", "l"])

        rootca_table = texttable.Texttable()
        rootca_table.set_deco(texttable.Texttable.HEADER)
        rootca_table.set_cols_align(["l", "l"])

        server_table = texttable.Texttable()
        server_table.set_deco(texttable.Texttable.HEADER)
        server_table.set_cols_align(["l", "l"])

        percent_table = texttable.Texttable()
        percent_table.set_deco(texttable.Texttable.HEADER)
        percent_table.set_cols_align(["l", "l"])

        domain2rtt = {}
        rootca2freq = {}
        server2freq = {}
        num_http = 0
        num_redirect = 0
        num_hsts = 0
        num_ipv6 = 0
        num_SSL = [0, 0]
        num_TLS = [0, 0, 0, 0] # 1.0, 1.1, 1.2, 1.3

        for domain in input_json:

            # Add a header row for the section
            full_table.add_row([f"=== {domain} ===", ""])

            # Add the data for the section
            for key, value in input_json[domain].items():
                full_table.add_row([key, str(value)])

                if key == "rtt_range":
                    domain2rtt[domain] = value
                elif key == "root_ca":
                    if value != None:
                        if value in rootca2freq:
                            rootca2freq[value] += 1
                        else:
                            rootca2freq[value] = 1
                elif key == "http_server" and value != None:
                    if value in server2freq:
                        server2freq[value] += 1
                    else:
                        server2freq[value] = 1
                elif key == "tls_versions":
                    for tls_ver in value:
                        if tls_ver == "TLSv1.0":
                            num_TLS[0] += 1
                        elif tls_ver == "TLSv1.1":
                            num_TLS[1] += 1
                        elif tls_ver == "TLSv1.2":
                            num_TLS[2] += 1
                        elif tls_ver == "TLSv1.3":
                            num_TLS[3] += 1

                elif key == "insecure_http":
                    if value:
                        num_http += 1
                elif key == "redirect_to_https":
                    if value:
                        num_redirect += 1
                elif key == "hsts":
                    if value:
                        num_hsts += 1
                elif key == "ipv6_addresses":
                    if value != []:
                        num_ipv6 += 1

    # All info
    full_table.header(["Domain", "All Info"])
    output_f.write(full_table.draw())
    output_f.write('\r\n\r\n')

    # Table for RTT range for all domains
    rtt_table.header(["Domain", "RTT Range"])
    sorted_domain2rtt = dict(sorted(domain2rtt.items(), key=lambda x: x[1])) 
    # Add sorted data to the table
    for key, value in sorted_domain2rtt.items():
        rtt_table.add_row([key, str(value)])

    output_f.write(rtt_table.draw())
    output_f.write('\r\n\r\n')

    # Table for the number of occurrences for each observed root certificate authority, sorted from most popular to least.
    rootca_table.header(["Root CA", "Frequency"])
    sorted_rootca2freq = dict(sorted(rootca2freq.items(), key=lambda x: x[1], reverse=True))
    for key, value in sorted_rootca2freq.items():
        rootca_table.add_row([key, str(value)])
    output_f.write(rootca_table.draw())
    output_f.write('\r\n\r\n')

    # Table for the number of occurrences of each web server, ordered from most popular to least.
    server_table.header(["Root CA", "Frequency"])
    sorted_server2freq = dict(sorted(server2freq.items(), key=lambda x: x[1], reverse=True))
    for key, value in sorted_server2freq.items():
        server_table.add_row([key, str(value)])
    output_f.write(server_table.draw())
    output_f.write('\r\n\r\n')

    num_domains = len(input_json)
    percent_table.header(["Feature", "Percentage"])
    percent_table.add_row(["SSLv2", num_SSL[0] / num_domains])
    percent_table.add_row(["SSLv3", num_SSL[1] / num_domains])
    percent_table.add_row(["TLSv1.0", num_TLS[0] / num_domains])
    percent_table.add_row(["TLSv1.1", num_TLS[1] / num_domains])
    percent_table.add_row(["TLSv1.2", num_TLS[2] / num_domains])
    percent_table.add_row(["TLSv1.3", num_TLS[3] / num_domains])
    percent_table.add_row(["plain http", num_http / num_domains])
    percent_table.add_row(["https redirect", num_redirect / num_domains])
    percent_table.add_row(["hsts", num_hsts / num_domains])
    percent_table.add_row(["ipv6", num_ipv6 / num_domains])

    output_f.write(percent_table.draw())
    output_f.write('\r\n\r\n')

    output_f.close()

except:
    pass
