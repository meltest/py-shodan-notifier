import os
import json
import shodan
import time
import difflib
import datetime as dt
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")
SHODAN_API = os.environ.get("SHODAN_API")

client = WebClient(token=SLACK_BOT_TOKEN)
api = shodan.Shodan(SHODAN_API)

def fetch_scan_result(ip):
    try:
        result = []
        host = api.host(ip)
        ip_address = host["ip_str"]
        os = host.get("os", "None")
        if os is None:
            os = "-"

        data = host["data"]

        for item in data:
            port = item["port"]
            if not item["hostnames"]:
                hostnames = "-"
            else:
                hostnames = "|".join(item["hostnames"])
            if not item["domains"]:
                domains = "-"
            else:
                domains = "|".join(item["domains"])
            product = item.get("product", "-")
            version = item.get("version", "-")
            vulns = item.get("vulns", "-")
            if vulns != "-":
                keys = list(vulns.keys())
                vulns = "|".join(sorted(keys))	
            timestamp = item["timestamp"]

            # print(f"IP:{ip_address}, Port:{port}, OS:{os}, Domains:{domains}, Product:{product}, Version:{version}, Vulns:{vulns}, Timestamp: {timestamp}")
            text = f"{ip_address},{port},{os},{hostnames},{domains},{product},{version},{vulns},{timestamp}\n"

            result.append(text)

        return result

    except shodan.APIError as e:
        print('Error: {}'.format(e))

def sort_result(result):
    matrix = []
    sorted_result = []
    for item in result:
        list = item.split(',')
        matrix.append(list)

    # sorted by IP and Port(Int)
    sorted_matrix = sorted(matrix, key=lambda x: (x[0], int(x[1])))

    # back from matrix to list
    count = 1
    for item in sorted_matrix:
        item.insert(0, str(count))
        sorted_result.append(",".join(item))
        count += 1
    
    return sorted_result

def get_diffs(sorted_result):
    last_result = []
    decrements_header = f"""\
### Following shows DECREMENT from last results
No, IP, Port, OS, Hostnames, Domains, Product, Version, Vulns, Timestamp.
"""
    decrements = ""
    increments_header = f"""\
### Following shows INCREMENT from last results
No, IP, Port, OS, Hostnames, Domains, Product, Version, Vulns, Timestamp.
"""
    increments = ""
    contents = ""
    with open(os.path.join(os.path.dirname(__file__), "last_result.csv"), "r") as f:
        last_result = f.readlines()

    # remove unnecessary columns 
    slice_last_result = slice_columns(last_result)
    slice_sorted_result = slice_columns(sorted_result)

    line_count = 0
    for diff in difflib.unified_diff(slice_last_result, slice_sorted_result):
        # remove unnecessary outputs
        if line_count < 3 :
            line_count += 1
            continue

        # search and get original result for decrement and increment
        if diff.startswith('-'):
            # remove prefix '-'
            keyword = diff[1:]
            # get original result from last_result
            for result in last_result:
                if keyword in result:
                    original = result
                    break
            decrements += original
        elif diff.startswith('+'):
            # remove prefix '+'
            keyword = diff[1:]
            # get original result from sorted_result
            for result in sorted_result:
                if keyword in result:
                    original = result
                    break
            increments += original

        line_count += 1

    if not decrements:
        decrements = "No results\n"
    if not increments:
        increments = "No results\n"
        
    contents = decrements_header + decrements + "\n" + increments_header + increments
    return contents

def slice_columns(input_list):
    result = []
    for line in input_list:
        column_list = line.split(",")
        length = len(column_list)
        slice_list = column_list[1:length-1]
        item = ",".join(slice_list)
        result.append(item)
    return result

today = dt.date.today()

header = f"""\
Shodan notifier got following scan results on {today}.
If previous result exists, diffs are only shown.
========================================
"""

# list for holding shodan results
result = []
with open(os.path.join(os.path.dirname(__file__), "iplist.txt"), "r") as f:
    lines = f.read().splitlines()
    for line in lines:
        item = fetch_scan_result(line)

        # respect shodan API rate limit
        time.sleep(1)

        if not item:
            continue

        result.extend(item)

# sort shodan results by IP and Port
sorted_result = sort_result(result)

contents = ""
# check if last_result.csv already exists or not
if os.path.exists(os.path.join(os.path.dirname(__file__), "last_result.csv")):
    contents = get_diffs(sorted_result)
# if file doesn't exist, output all results
else:
    contents += f"No, IP, Port, OS, Hostnames, Domains, Product, Version, Vulns, Timestamp.\n"
    for item in sorted_result:
        contents += item

footer = f"""\
========================================
Have a good day!"""

# final output
report = header + contents + footer

# overwrite shodan results to last_result.csv for future comparison.
with open(os.path.join(os.path.dirname(__file__), "last_result.csv"), "w") as f:
    f.writelines(sorted_result)

with open(os.path.join(os.path.dirname(__file__), f"logs/{today}_result.csv"), "w") as f:
    f.writelines(sorted_result)

try: 
    # response = client.chat_postMessage(channel=SLACK_CHANNEL, text=report)
    response = client.files_upload(channels=SLACK_CHANNEL, content=report, title="Shodan_Notifier")
    # print(report)
except SlackApiError as e:
    assert e.response["ok"] is False
    assert e.response["error"]
    print(f"Got an error: {e.response['error']}")

