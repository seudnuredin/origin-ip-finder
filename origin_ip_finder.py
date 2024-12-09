import argparse
import requests
import json
import subprocess
from urllib.parse import urlparse
import os

dns_history_ips = set()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Find origin IPs for a given domain using SecurityTrails and other tools.")
    parser.add_argument("-u","--url", required=True, help="URL to analyze. Must start with http(s)://")
    parser.add_argument("-k","--api-key", required=True, help="SecurityTrails API key")
    parser.add_argument("-o","--output", required=False, help="filename to output as")
    return parser.parse_args()

def validate_url(url):
    if not (url.startswith("http://") or url.startswith("https://")):
        print("Error: The URL must start with http:// or https://")
        sys.exit(1)

def add_entry(ip, hostname):
    hosts_file = "/etc/hosts"
    entry = f"{ip} {hostname}\n"

    with open(hosts_file, "r") as file:
        if entry.strip() in [line.strip() for line in file.readlines()]:
            return

    with open(hosts_file, "a") as file:
        file.write(entry)

def remove_entry(ip, hostname):
    hosts_file = "/etc/hosts"
    entry = f"{ip} {hostname}"

    with open(hosts_file, "r") as file:
        lines = file.readlines()

    updated_lines = [line for line in lines if line.strip() != entry]

    with open(hosts_file, "w") as file:
        file.writelines(updated_lines)

def get_dns_history(hostname, api_key, page):
    url = f"https://api.securitytrails.com/v1/history/{hostname}/dns/a?page={page}"

    headers = {
        "accept": "application/json",
        "APIKEY": api_key
    }

    response = requests.get(url, headers=headers)
    dns_history = json.loads(response.text)
    try:
        for record in dns_history["records"]:
            for value in record["values"]:
                dns_history_ips.add(value["ip"])
    except:
        print(response.text)
        exit()
    
    if dns_history["pages"] != page:
        get_dns_history(hostname, api_key, page + 1)

def main():
    args = parse_arguments()
    url_we_want_origin_ip_of = args.url
    api_key = args.api_key

    validate_url(url_we_want_origin_ip_of)

    hostname_we_want_origin_ip_of = urlparse(url_we_want_origin_ip_of).hostname

    get_dns_history(hostname_we_want_origin_ip_of, api_key, 1)

    dns_history_ips_list = list(dns_history_ips)

    for ip in list(dns_history_ips_list):
        error_count = 0
        url_we_want_origin_ip_of_for_this_instance = f'http://{hostname_we_want_origin_ip_of}'
        while True:
            add_entry(ip, hostname_we_want_origin_ip_of)

            command = f"wafw00f {url_we_want_origin_ip_of_for_this_instance}"
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            remove_entry(ip, hostname_we_want_origin_ip_of)

            output = result.stdout.strip()
            error = result.stderr.strip()

            if error != "":
                error_count += 1

                if error_count % 2 == 0:
                    url_we_want_origin_ip_of_for_this_instance = f'http://{hostname_we_want_origin_ip_of}'
                else:
                    url_we_want_origin_ip_of_for_this_instance = f'https://{hostname_we_want_origin_ip_of}'

                if error_count == 3:
                    break
                continue

            if "no waf" not in output.lower():
                dns_history_ips_list.remove(ip)

            break

    with open(f'/tmp/dns_history_ips.txt', 'w') as dns_history_ips_file:
        for ip in dns_history_ips_list:
            dns_history_ips_file.write(f"{ip}\n")

    error_count = 0
    while True:
        command = f"cat /tmp/dns_history_ips.txt | hakoriginfinder -h {url_we_want_origin_ip_of}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.strip()
        error = result.stderr.strip()

        if error != "" or "Error" in output:
            print(error)
            error_count += 1
            if error_count == 3:
                break
            continue
        
        if args.output:
            with open(args.output, 'w') as output_file:
                output_file.write(output)
        else:
            print(output)

        break

    os.remove('/tmp/dns_history_ips.txt')

if __name__ == "__main__":
    main()
