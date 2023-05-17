import pandas as pd
import numpy as np
import io
from kafka import KafkaProducer, KafkaConsumer
import joblib

# Load trained model
model = joblib.load('dga_detection.joblib')

# Define Kafka producer and consumer
producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
consumer = KafkaConsumer('dns1', bootstrap_servers=['localhost:9092'])

def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

# Preprocessing function to extract features from query column
def preprocess(df):
    # Feature: entropy
    df['domain'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    df['digits'] = df['query'].str.count('[0-9]')
   
    # Add more features as needed
    return df

# Prediction function
def predict(df):
    X = df[['domain', 'length', 'entropy', 'digits']]  # Use relevant features for prediction
    y_pred = model.predict(X)
    return y_pred

# Stream dns.log data to Kafka topic
for msg in consumer:
    line = msg.value
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df.columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
    df = preprocess(df)
    y_pred = predict(df)
    for p in y_pred:
        producer.send('dns1', str(p).encode())
