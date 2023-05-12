from kafka import KafkaProducer
from kafka.consumer import KafkaConsumer
import time
import subprocess
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
from zat import zeek_log_reader
import io

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.log'], stdout=subprocess.PIPE)

consumer = KafkaConsumer('dnslogs', bootstrap_servers=['localhost:9092'])
model = joblib.load('dga_detection.joblib')


for line in iter(zeek_proc.stdout.readline, b''):
    # Preprocess the DNS logs
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df = df.dropna(axis=1, how='all')
    df.columns = ['query']
    df['query'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['label'] = label_encoder.transform(model.predict(df['query']))
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')

    # Send the preprocessed DNS logs to Kafka
    producer.send('dnslogs', preprocessed_line.encode('utf-8'))
    time.sleep(0.1)



for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')



