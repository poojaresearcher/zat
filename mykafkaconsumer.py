from kafka import KafkaConsumer
import time
import subprocess
from collections import Counter
import math
import joblib
import pickle
import json

consumer = KafkaConsumer('dnslogs', bootstrap_servers=['localhost:9092'],
     value_deserializer=lambda x: json.loads(x.decode('utf-8')))

for message in consumer:
     dns_message = message.value
     query = dns_message['query']
     parsed_url = urlparse(query)
     domain = parsed_url.netloc
     print(dns_message['query'])




