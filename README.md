# Origin IP Finder

A Python script that uses SecurityTrails API, wafw00f, and hakoriginfinder to find the origin IP addresses of a given domain and hopefully bypass WAF. The more static the URL you provide, the better.

## Requirements
- Python 3.x
- Tools: 
  - [wafw00f](https://github.com/EnableSecurity/wafw00f)
  - [hakoriginfinder](https://github.com/hakluke/hakoriginfinder)

## Usage
1. Clone this repository:
   ```bash
   git clone https://github.com/seudnuredin/origin-ip-finder.git
   cd origin-ip-finder
2. Run
	```bash
	python3 origin_ip_finder.py -u https://example.com -k YOUR_API_KEY
## Notes
Ensure you have permissions to modify `/etc/hosts`:
```bash
sudo chown root:sudo /etc/hosts
chmod 664 /etc/hosts
