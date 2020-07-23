import datetime
import elasticsearch
import slack
from dotenv import load_dotenv
import os
import re

load_dotenv()

# setup slack client
client = slack.WebClient(token=os.getenv("SLACK_TOKEN"))

# url for elasticsearch server
url = os.getenv("ES_URL")

# setup elasticsearch connector
es = elasticsearch.Elasticsearch(url, http_auth=(os.getenv("ES_USERNAME"),os.getenv("ES_PASSWORD")), scheme="https", verify_certs=False)

# window to search back for signals
window = -300
#window = -9000

def defaultOutput():
    return "Time: `{}` Rule: `{}` Description: `{}` Host: `{}`".format(alert['_source']['@timestamp'], alert['_source']['signal']['rule']['name'], alert['_source']['signal']['rule']['description'], alert['_source']['agent']['hostname'])

def base_output():
    return "Time: `{}` Rule: `{}`".format(alert['_source']['@timestamp'], alert['_source']['signal']['rule']['name'])


def get_output_text(Input, splitInput):
    arrayLength = len(splitInput)
    if(arrayLength == 1):
        return " {}: `{}`".format(Input, alert['_source'][splitInput[0]])
    if(arrayLength == 2):
        return " {}: `{}`".format(Input, alert['_source'][splitInput[0]][splitInput[1]])
    if(arrayLength == 3):
        return " {}: `{}`".format(Input, alert['_source'][splitInput[0]][splitInput[1]][splitInput[2]])
    if(arrayLength == 4):
        return " {}: `{}`".format(Input, alert['_source'][splitInput[0]][splitInput[1]][splitInput[2]][splitInput[3]])

# setup time offset (window set above)
ts = datetime.datetime.utcnow()
timestamp = ts + datetime.timedelta(seconds=window)

# query elasticsearch for open alerts
res = es.search(index=".siem-signals-*", scroll='2m', body={
    "sort": [{"@timestamp":{"order": "asc"}}],
    "size": 10000,
    "query": {
        "bool": {
            "filter": {
                "range": {
                    "@timestamp": {"gt": timestamp}
                }
            },
            "must": {
                "match": {
                    "signal.status": "open"
                    }
                }
            }
        }
    }
)
# narrow down list of hits (means I have to do less dictionary stuff below)
hits = res['hits']['hits']

# if there are actual results for the above search
if len(hits) != 0:

    last_alerts = open("last_alerts.txt", "r")

    last_alerts_list = last_alerts.read()

    # setup blank message to be added to below
    message = ""

    # setup blank string to track messages alerted on
    new_alerts_text = ""
    has_output = 0

    # itterate through all alerts and create message to send to slack
    for alert in hits:
        if alert['_id'] not in last_alerts_list:
            has_output = 0
            new_alerts_text = new_alerts_text + alert['_id'] + "\n"

            # Get correct output type
            rule_output = base_output()

            outputTriggers = re.findall(r'\$(.+?)\$', alert['_source']['signal']['rule']['description'])

            for trigger in outputTriggers:
                splitTrigger = re.split(r'\.\s*', trigger)
                try:
                    rule_output = rule_output + get_output_text(trigger, splitTrigger)
                    has_output = 1
                except Exception as ex:
                    print(ex)

            # if no output type already set
            if has_output == 1:
                message = message + rule_output + "\n"
            else:
                message = message + defaultOutput() + "\n"

    last_alerts.close()

    #print(new_alerts_text)
    new_alerts = open("last_alerts.txt", "w")
    new_alerts.write(new_alerts_text)

    # send message to slack
    client.chat_postMessage(channel="#ps_alerts", text=message)
else:
    new_alerts = open("last_alerts.txt", "w")
    new_alerts.write("")

