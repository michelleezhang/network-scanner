import sys
import json
import time
import subprocess
import socket
import requests
import maxminddb

class Scanner():
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.scan_results = {}
        self.missing_code = "NaH"
        self.public_resolvers = ['1.0.0.1', '1.1.1.1', '134.195.4.2', '149.112.112.112', '159.89.120.99', 
                                 '185.228.168.9', '185.228.169.9', '195.46.39.39', '195.46.39.40', 
                                 '205.171.2.65', '205.171.3.65', '208.67.220.220', '208.67.222.222', 
                                 '216.146.35.35', '216.146.36.36', '64.6.64.6', '64.6.65.6', '74.82.42.42',
                                 '76.223.122.150', '76.76.10.0', '76.76.19.19', '76.76.2.0', '77.88.8.1',
                                 '77.88.8.8', '8.20.247.20', '8.26.56.26', '8.8.4.4', '8.8.8.8', '84.200.69.80',
                                 '84.200.70.40', '89.233.43.71', '9.9.9.9', '91.239.100.100', '94.140.14.14', '94.140.15.15']
    
    def scan(self):
        # Returns: JSON2 dictionary, written to output_file
        # Keys: domains that were scanned, values: dictionaries with scan results

        with open(self.input_file, 'r') as f:
            domain_names = f.read().splitlines()

        # Create a scan result dictionary for each given domain
        for domain in domain_names:
            scan_result = {}

            scan_result["scan_time"] = time.time() 

            ipv4_addresses = self.get_ipvx_addresses(domain, 'A')
            scan_result["ipv4_addresses"] = ipv4_addresses

            scan_result["ipv6_addresses"] = self.get_ipvx_addresses(domain, 'AAAA') 

            scan_result["http_server"] = self.get_http_server(domain)

            insecure_http = self.get_insecure_http(domain)
            scan_result["insecure_http"] = insecure_http

            if insecure_http:
                redirect_https, redirect_url = self.get_https_redirect(domain)
                scan_result["redirect_to_https"] = redirect_https

                if redirect_https:
                    scan_result["hsts"] = self.get_hsts(redirect_url)
                else:
                    scan_result["hsts"] = self.get_hsts(domain)
                
                scan_result["tls_versions"] = self.get_tls_versions(domain)

                scan_result["root_ca"] = self.get_root_ca(domain)
            else:
                scan_result["redirect_to_https"] = False

                scan_result["hsts"] = False

                scan_result["tls_versions"] = []

                scan_result["root_ca"] = None

            scan_result["rdns_names"] = self.get_rdns_names(ipv4_addresses)

            scan_result["rtt_range"] = self.get_rtt_range(ipv4_addresses)

            scan_result["geo_locations"] = self.get_geo_locations(ipv4_addresses)

            # If any of these keys maps to the missing code, then a command line tool was missing, so skip the scan
            scan_result = {key: value for key, value in scan_result.items() if value != self.missing_code}

            self.scan_results[domain] = scan_result
       
        # Write scan results to output file
        with open(self.output_file , "w") as f: 
            json.dump(self.scan_results, f, sort_keys=True, indent=4)
    
    def get_ipvx_addresses(self, domain, version):
        # Returns: List of IPvX addresses listed as DNS “A” (for IPv4) or "AAAA" (for IPv6) records for the domain.
        
        ipvx_addresses = []
        record_type = "-type=" + version
        for resolver in self.public_resolvers:
            try:
                ns_output = subprocess.check_output(["nslookup", record_type, domain, resolver], timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
                # Parse output
                result_lines = ns_output.split('\n')
                address_lines = [line for line in result_lines if 'Address:' in line][1:]
                for address_line in address_lines:
                    ipvx_address = address_line.split(' ')[-1]
                    if ipvx_address not in ipvx_addresses:
                        ipvx_addresses.append(ipvx_address)
            except Exception as e:
                if hasattr(e, 'errno') and e.errno == 2: # Missing command line tool will throw "No such file or directory" (Erno 2)
                    return self.missing_code
        return ipvx_addresses
    
    def get_http_server(self, domain):
        # Returns: Web server software reported in the Server header4 of the HTTP response
        # None if this does not exist.
        
        try:
            # Make an HTTP GET request to the domain
            response = requests.head(f"http://{domain}", timeout=5)
            # Check if we have a server header
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                return server_header
            
            # Sometimes the server info is missing if we just use head, so check again with full get request if needed 
            response = requests.get(f"http://{domain}", timeout=5)
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                return server_header
            
            return None
        except:
            return None
    
    def get_insecure_http(self, domain):
        # Returns: JSON boolean indicating whether the website listens for unencrypted HTTP requests on port 80. 
       
        try:
            ip_address = socket.gethostbyname(domain)
            port = 80

            # Create a socket and attempt to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Set a timeout for the connection attempt
            result = sock.connect_ex((ip_address, port))
            sock.close()

            if result == 0:
                # Port 80 is open, so HTTP is likely listening
                return True 
            else:
                # Port 80 is closed or not accessible
                return False
        except:
            return False # Domain not resolved or error in socket connection
        

    def get_https_redirect(self, domain):
        # Returns: JSON boolean indicating whether unencrypted HTTP requests on port 80 are redirected to HTTPS requests on port 443. 
        # Give up after 10 redirects

        try:
            url = f"http://{domain}"

            redirect_count = 0
            while redirect_count < 10:
                response = requests.get(url, timeout=5)
                if 299 < response.status_code < 310 and 'Location' in response.headers:
                    if response.headers['Location'].startswith('https://'):
                        return True, response.headers['Location'] # HTTP to HTTPS redirection detected
                    else:
                        redirect_count += 1
                        url = response.headers['Location']
                elif response.status_code == 503:
                    return True, url
                else:
                    break

            return False, url
        except:
            return False, url


    def get_hsts(self, domain):
        # Returns: JSON boolean indicating whether the website has enabled HTTP Strict Transport Security
        # Check for the appropriate HTTP response header on the final page that you are redirected to

        try:
            # Make an HTTPS request to the domain
            response = requests.get(f"https://{domain}", timeout=5)

            # Check if the 'Strict-Transport-Security' header is present in the response
            if 'Strict-Transport-Security' in response.headers:
                return True  # HSTS is enabled
            else:
                return False # HSTS is not enabled

        except:
            return False # Error in the request or HSTS not enabled

    def get_tls_versions(self, domain):
        # Returns: List of all versions of Transport Layer Security (TLS/SSL) supported by the server (strings, in no particular order)
        
        tls_versions = []
        try:
            nmap_output = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain], timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
            
            if "TLSv1.0" in nmap_output:
                tls_versions.append("TLSv1.0")
            if "TLSv1.1" in nmap_output:
                tls_versions.append("TLSv1.1")
            if "TLSv1.2" in nmap_output:
                tls_versions.append("TLSv1.2")
        except Exception as e:
            if hasattr(e, 'errno') and e.errno == 2: # Missing command line tool will throw "No such file or directory" (Erno 2)
                    return self.missing_code

        try:
            ssl_output = subprocess.check_output(["openssl", "s_client", "-tls1_3", "-connect", domain + ":443"], timeout=5, stderr=subprocess.STDOUT, input="").decode("utf-8")
            if "TLSv1.3" in ssl_output:
                tls_versions.append("TLSv1.3")
        except Exception as e:
            if hasattr(e, 'errno') and e.errno == 2: # Missing command line tool will throw "No such file or directory" (Erno 2)
                    return self.missing_code

        return tls_versions
    
    
    def get_root_ca(self, domain):
        # Returns: the root certificate authority (CA) at the base of the chain of trust for validating this server’s public key. 
        # None if no root CA found

        try:
            ssl_output = subprocess.check_output(["openssl", "s_client", "-tls1_3", "-connect", domain + ":443"], timeout=5, stderr=subprocess.STDOUT, input="").decode("utf-8")
            
            # Find the index of "Certificate chain" and "Server certificate"
            chain_index = ssl_output.find("Certificate chain")
            cert_index = ssl_output.find("Server certificate")
            
            if chain_index != -1 and cert_index != -1:
                # Extract the certificate chain between "Certificate chain" and "Server certificate"
                certificate_chain = ssl_output[chain_index:cert_index]
                # Find and extract the root CA's name (assuming 'O =' is present in the certificate chain)
                # Root CA is at the BOTTOM (highest number) line
                lines = certificate_chain.strip().split('\n')
                root_line = lines[-2]

                root_ca = root_line.split("O = ")[1].split(',', 1)[0]
                if len(root_ca) == 0:
                    return None
                else:
                    return root_ca
        except Exception as e:
            if hasattr(e, 'errno') and e.errno == 2: # Missing command line tool will throw "No such file or directory" (Erno 2)
                    return self.missing_code
            return None
    

    def get_rdns_names(self, ipv4_addresses):
        # Returns: List of the reverse DNS names for the IPv4 addresses from ipv4

        rdns_names = []
        for ipv4_address in ipv4_addresses:
            try:
                ns_output = subprocess.check_output(["nslookup", "-type=PTR", ipv4_address], timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
                result_lines = ns_output.split('\n')
                names_lines = [line for line in result_lines if 'name = ' in line]
                for name_line in names_lines:
                    rdns_name = name_line.split("name = ", 1)[1][:-1] # remove . at end
                    if rdns_name not in rdns_names:
                        rdns_names.append(rdns_name)
            except Exception as e:
                if hasattr(e, 'errno') and e.errno == 2: # Missing command line tool will throw "No such file or directory" (Erno 2)
                        return self.missing_code
        return rdns_names

    def get_rtt_range(self, ipv4_addresses):
        # Returns: List [min, max] with the shortest and longest round trip time (milliseconds) you observe when contacting all the IPv4 addresses
        # None if unreachable

        rtt_list = []
        for ipv4_address in ipv4_addresses:
            try:
                time_output = subprocess.check_output(['sh', '-c', f"time echo -e '\x1dclose\x0d' | telnet {ipv4_address} 443"], timeout=5, stderr=subprocess.STDOUT).decode('utf-8')
                result_lines = time_output.split('\n')
                for line in result_lines:
                    if line.startswith('real'):
                        real_value = line.split()[1]
                        dot_ind = real_value.find('.') # split at '.' so it's already in ms
                        s_ind = real_value.find('s')
                        if dot_ind != -1 and s_ind != -1:
                            real_value = real_value[dot_ind + 1:s_ind]
                            rtt_list.append(real_value)
            except Exception as e:
                if hasattr(e, 'errno') and e.errno == 2: # Missing command line tool will throw "No such file or directory" (Erno 2)
                    return self.missing_code
                
        if len(rtt_list) > 0:
            return [int(min(rtt_list)), int(max(rtt_list))]
        else:
            return None

    def get_geo_locations(self, ipv4_addresses):
        # Returns: List of real-world locations (city, province, country) for all the IPv4 addresses 
        
        reader = maxminddb.open_database('GeoLite2-City.mmdb')
        
        locations = []
        for ipv4_address in ipv4_addresses:
            try:
                response = reader.get(ipv4_address)
                try:
                    city = response['city']['names']['en']
                    province = response['subdivisions'][0]['names']['en']
                    country = response['country']['names']['en']

                    location = city + ', ' + province + ', ' + country
                    if location not in locations:
                        locations.append(location)
                except:
                    pass
            except:
                pass

        reader.close()
        return locations

# MAIN
# Get args from command line
if len(sys.argv) != 3:
    print("Usage: python3 scan.py input_file.txt output_file.json")
    sys.exit(1)
input_file = sys.argv[1]
output_file = sys.argv[2]

my_scanner = Scanner(input_file, output_file)
my_scanner.scan()
