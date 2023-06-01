from kafka import KafkaProducer
import time
import subprocess

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.log'], stdout=subprocess.PIPE)

for line in iter(zeek_proc.stdout.readline, b''):
    producer.send('dnslog', line.rstrip())
    time.sleep(0.1)

producer.close()

