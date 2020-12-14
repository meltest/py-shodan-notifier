import os
import json
import shodan
import time
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
			hostnames = "|".join(item["hostnames"])
			domains = "|".join(item["domains"])
			product = item.get("product", "-")
			version = item.get("version", "-")
			vulns = item.get("vulns", "-")
			if vulns != "-":
				keys = vulns.keys()
				vulns = "|".join(keys)	
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

today = dt.date.today()
report = ""
report = f"""\
Shodan notifier got following scan results on {today}.
========================================
No, IP, Port, OS, Hostnames, Domains, Product, Version, Vulns, Timestamp.
"""

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

sorted_result = sort_result(result)

for item in sorted_result:
	report += item

report += "========================================\n"
report += "Have a good day!"

try: 
	# response = client.chat_postMessage(channel=SLACK_CHANNEL, text=report)
	response = client.files_upload(channels=SLACK_CHANNEL, content=report, title="Shodan_Notifier")
except SlackApiError as e:
	assert e.response["ok"] is False
	assert e.response["error"]
	print(f"Got an error: {e.response['error']}")


