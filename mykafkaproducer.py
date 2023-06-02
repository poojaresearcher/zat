from kafka import KafkaProducer
import time
import subprocess

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.2023-06-02-14-01-33.log'], stdout=subprocess.PIPE)

for line in iter(zeek_proc.stdout.readline, b''):
    producer.send('dnslogs', line.rstrip())
    time.sleep(0.1)

producer.close()

