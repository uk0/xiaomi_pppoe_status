#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CloudFlare Dynamic DNS in Python

Usage example (same flags as the bash version):
  python cf_ddns.py \
    -k <API_KEY> \
    -u <EMAIL> \
    -h <HOSTNAME> \
    -z <ZONE_NAME> \
    -t A|AAAA \
    -f false|true

You can schedule it in cron, e.g.:
  */1 * * * * /usr/bin/python /path/to/cf_ddns.py >> /var/log/cf-ddns.log 2>&1
"""
import json
import sys
import os
import argparse
import requests

from xiaomi_ip import login_and_get_stok, get_ip_config, get_wan_info


def main():
    parser = argparse.ArgumentParser(description="Cloudflare DDNS Python version")
    parser.add_argument("-k", "--key", help="CloudFlare API Key", required=False, default="1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    parser.add_argument("-u", "--user", help="CloudFlare API Email/Username", required=False, default="xxxxxxxxxxxxxx@gmail.com")
    parser.add_argument("-hh", "--hostname", help="Hostname to update (FQDN)", required=False, default="openvpn_roosit_sys_deepseek_r1")
    parser.add_argument("-z", "--zone", help="Zone name (example.com)", required=False, default="cva.ai")
    parser.add_argument("-t", "--recordtype", help="DNS record type: A or AAAA", required=False, default="A")
    parser.add_argument("-p", "--plugin", help="DNS icanhazip or xiaomi", required=False, default="xiaomi")
    parser.add_argument("-f", "--force", help="Force update ignoring local IP cache", required=False, default="false", choices=["false","true"])

    args = parser.parse_args()

    CFKEY = args.key
    CFUSER = args.user
    CFRECORD_NAME = args.hostname
    CFZONE_NAME = args.zone
    CFRECORD_TYPE = args.recordtype.upper()
    USE_PLUGIN = args.plugin.upper()
    FORCE = (args.force.lower() == "true")

    # TTL
    CFTTL = 120  # Same default as bash script

    # Some validations
    if CFKEY.strip() == "":
        sys.exit("Missing Cloudflare API Key. Please set -k or modify script.")
    if CFUSER.strip() == "":
        sys.exit("Missing Cloudflare API Email. Please set -u or modify script.")
    if CFRECORD_NAME.strip() == "":
        sys.exit("Missing hostname. Please set -h or modify script.")
    if CFZONE_NAME.strip() == "":
        sys.exit("Missing zone. Please set -z or modify script.")

    # If the hostname is not fully qualified, assume we append CFZONE_NAME
    if CFRECORD_NAME != CFZONE_NAME and (not CFRECORD_NAME.endswith("."+CFZONE_NAME)):
        CFRECORD_NAME = f"{CFRECORD_NAME}.{CFZONE_NAME}"
        print(f"=> Hostname is not a FQDN, assuming {CFRECORD_NAME}")
    if USE_PLUGIN=="ICANHAZIP":
        # Determine how to get the WAN IP
        if CFRECORD_TYPE == "A":
            WANIPSITE = "http://ipv4.icanhazip.com"
        elif CFRECORD_TYPE == "AAAA":
            WANIPSITE = "http://ipv6.icanhazip.com"
        # 1) Get current WAN IP
        try:
            resp = requests.get(WANIPSITE, timeout=10)
            resp.raise_for_status()
            WAN_IP = resp.text.strip()
        except Exception as e:
            sys.exit(f"Failed to retrieve WAN IP from {WANIPSITE}: {e}")
    elif USE_PLUGIN=="XIAOMI":
        stok = login_and_get_stok()
        print("Login success, stok =", stok)

        wan_data = get_wan_info(stok)
        print("WAN info data:", json.dumps(wan_data, indent=2))

        wan_ip_data = get_ip_config(stok)
        print("WAN IP data:", json.dumps(wan_ip_data, indent=2))
        # 你可以根据 WAN 数据结构，从中提取 ip, dns 等关键信息
        WAN_IP = wan_ip_data['ip']['address']
        print("WAN IP to cf ddns -> ",WAN_IP)


    # 2) Compare with old WAN IP
    home_dir = os.path.expanduser("~")
    WAN_IP_FILE = os.path.join(home_dir, f".cf-wan_ip_{CFRECORD_NAME}.txt")
    old_wan_ip = ""
    if os.path.isfile(WAN_IP_FILE):
        with open(WAN_IP_FILE, "r") as f:
            old_wan_ip = f.read().strip()

    if WAN_IP == old_wan_ip and (not FORCE):
        print(f"WAN IP Unchanged ({WAN_IP}). Use -f true to force update.")
        sys.exit(0)

    # 3) Get zone_identifier & record_identifier from local cache or from CF
    ID_FILE = os.path.join(home_dir, f".cf-id_{CFRECORD_NAME}.txt")
    CFZONE_ID = ""
    CFRECORD_ID = ""

    # Check if cache is valid
    id_file_lines = []
    if os.path.isfile(ID_FILE):
        with open(ID_FILE, "r") as f:
            id_file_lines = [line.strip() for line in f.readlines()]

    # We expect 4 lines: zone_id, record_id, zone_name, record_name
    # and the last 2 lines should match CFZONE_NAME, CFRECORD_NAME
    if len(id_file_lines) == 4 \
       and id_file_lines[2] == CFZONE_NAME \
       and id_file_lines[3] == CFRECORD_NAME:
        CFZONE_ID = id_file_lines[0]
        CFRECORD_ID = id_file_lines[1]
    else:
        print("Updating zone_identifier & record_identifier from Cloudflare API")

        # Retrieve CFZONE_ID
        try:
            url_zones = f"https://api.cloudflare.com/client/v4/zones?name={CFZONE_NAME}"
            headers = {
                "X-Auth-Email": CFUSER,
                "X-Auth-Key": CFKEY,
                "Content-Type": "application/json"
            }
            resp_zone = requests.get(url_zones, headers=headers, timeout=10)
            resp_zone.raise_for_status()
            zone_data = resp_zone.json()

            # Extract zone id from result
            if not zone_data["success"] or len(zone_data["result"]) == 0:
                sys.exit(f"Cannot find zone id for {CFZONE_NAME}, response: {zone_data}")
            CFZONE_ID = zone_data["result"][0]["id"]

            # Retrieve CFRECORD_ID
            url_records = f"https://api.cloudflare.com/client/v4/zones/{CFZONE_ID}/dns_records?name={CFRECORD_NAME}"
            resp_record = requests.get(url_records, headers=headers, timeout=10)
            resp_record.raise_for_status()
            record_data = resp_record.json()

            if not record_data["success"]:
                sys.exit(f"Failed to retrieve record id, response: {record_data}")

            if len(record_data["result"]) == 0:
                sys.exit(f"No DNS record found for {CFRECORD_NAME} under zone {CFZONE_NAME}.\n"
                         "You may need to create that record first in Cloudflare UI.")

            CFRECORD_ID = record_data["result"][0]["id"]

            # Save to ID_FILE
            with open(ID_FILE, "w") as f:
                f.write(f"{CFZONE_ID}\n")
                f.write(f"{CFRECORD_ID}\n")
                f.write(f"{CFZONE_NAME}\n")
                f.write(f"{CFRECORD_NAME}\n")

        except Exception as e:
            sys.exit(f"Error retrieving zone/record id from Cloudflare: {e}")

    # 4) Update Cloudflare DNS with new WAN IP
    print(f"Updating DNS {CFRECORD_NAME} => {WAN_IP}")
    url_update = f"https://api.cloudflare.com/client/v4/zones/{CFZONE_ID}/dns_records/{CFRECORD_ID}"
    headers = {
        "X-Auth-Email": CFUSER,
        "X-Auth-Key": CFKEY,
        "Content-Type": "application/json"
    }
    data = {
        "id": CFZONE_ID,
        "type": CFRECORD_TYPE,
        "name": CFRECORD_NAME,
        "content": WAN_IP,
        "ttl": CFTTL
    }

    try:
        resp_update = requests.put(url_update, headers=headers, json=data, timeout=10)
        resp_update.raise_for_status()
        update_result = resp_update.json()
    except Exception as e:
        sys.exit(f"Failed to update DNS record: {e}")

    if update_result.get("success", False) is True:
        print(f"Updated successfully! {CFRECORD_NAME} now -> {WAN_IP}")
        # Save WAN IP to file
        with open(WAN_IP_FILE, "w") as f:
            f.write(WAN_IP)
    else:
        print("Something went wrong :(")
        print("Response:", update_result)
        sys.exit(1)

if __name__ == "__main__":
    main()