import os
import json
import asyncio
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from telegram import Bot
from dotenv import load_dotenv

load_dotenv()
try:
    ELASTIC_HOST = os.environ['ELASTIC_HOST']
    token = os.environ['token']
    chat_id = os.environ['chat_id']
    api_key = os.environ['api_key']
    message_thread_id = os.environ['message_thread_id']
except KeyError as e:
    raise KeyError(f"Environment variable {e} not found. Make sure the environment variables are defined.")

async def send_telegram_message(token, chat_id, message, message_thread_id=None):
    bot = Bot(token=token)
    await bot.send_message(
        chat_id=chat_id,
        text=message,
        parse_mode='Markdown',
        message_thread_id=message_thread_id
    )

def create_elasticsearch_client(host, api_key):
    return Elasticsearch(
        ELASTIC_HOST,
        api_key=api_key,
        verify_certs=False,
        ssl_show_warn=False
    )

def get_alerts(client, index_pattern, query):
    return scan(client=client, query=query, index=index_pattern)

def format_alerts(alerts):
    alert_summary_all = []
    for alert in alerts:
        source = alert['_source']
        if source['kibana.alert.workflow_status'] == "open":
            alert_summary = {
                "time": source['kibana.alert.start'],
                "description": source['kibana.alert.rule.parameters']['description'],
                "severity": source['kibana.alert.rule.parameters']['severity'],
                "host": source['host']['hostname'],
                "reason": source['kibana.alert.reason'],
                "id": source['kibana.alert.uuid']
            }
            alert_summary_all.append(alert_summary)
    return alert_summary_all

def read_processed_ids(file_path):
    if not os.path.exists(file_path):
        return set()
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file)

def write_processed_ids(file_path, ids):
    with open(file_path, 'a') as file:
        for id in ids:
            file.write(f"{id}\n")

async def main():
    now = datetime.utcnow()
    one_day_ago = now - timedelta(days=2)
    client = create_elasticsearch_client(ELASTIC_HOST, api_key)

    # Elastic query
    index_pattern = ".siem-signals-*"
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": one_day_ago.isoformat(),
                    "lte": now.isoformat()
                }
            }
        }
    }

    # Manage alerts
    processed_ids_file = "processed_ids.txt"
    processed_ids = read_processed_ids(processed_ids_file)
    alerts = get_alerts(client, index_pattern, query)
    alert_summary_all = format_alerts(alerts)
    new_processed_ids = set()

    # Send alerts to Telegram
    for alert in alert_summary_all:
        alert_id = alert["id"]
        if alert_id not in processed_ids:
            alert_json = json.dumps(alert, indent=2)
            alert_message = f"🔴 Elastic Detection:\n```\n{alert_json}\n```"
            await send_telegram_message(token, chat_id, alert_message,message_thread_id)
            new_processed_ids.add(alert_id)

    # Add IDs
    write_processed_ids(processed_ids_file, new_processed_ids)

if __name__ == "__main__":
    asyncio.run(main())
