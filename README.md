# Elastic-Alerts
There are more and better projects to send detection alerts to Telegram. But sometimes one likes just to code.

This script should be ran in cron. For example evry 5 minutes:
```
*/5 * * * * /location/elastic_alert.py
```

## Configuration
### Install dependencies
```
pip3 install -r requirements.txt
```
### Environment variables
Create a `.env` file:
```
ELASTIC_PASSWORD = ""
CERT_FINGERPRINT = ""
ELASTIC_HOST = ""
token = ""
chat_id = ""
```
### Create your Telegram bot
Check: [From BotFather to 'Hello World'](https://core.telegram.org/bots/tutorial)

## How it works
1. Connects to your Elastic
2. Checks for open alerts in the last day
3. Checks `processed_ids.txt` to not repeat alerts
4. Sends alert