#!/bin/bash 
#Test script used to test push notifications for PushBullet
TOKEN="" #put in your API token here
curl -X POST \
  https://api.pushbullet.com/v2/pushes \
  -H "access-token: $TOKEN" \
  -H "content-type: application/json" \
  -d "{
	\"type\": \"note\",
	\"title\": \"$(hostname)\",
	\"body\": \"$1\"
   }"
