from kafka import KafkaProducer,KafkaConsumer
import time
import subprocess
from collections import Counter
import math
import joblib

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.log'], stdout=subprocess.PIPE)
consumer = KafkaConsumer('dns1', bootstrap_servers=['localhost:9092'])
model = joblib.load('dga_detection.joblib')


def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

# Preprocessing function to extract features from query column
def preprocess(df):
    # Feature: entropy
    df['domain'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(entropy)
    df['digits'] = df['query'].str.count('[0-9]')
    
    # Add more features as needed
    return df

# Prediction function
def predict(df):
    X = df[['domain', 'length', 'entropy', 'digits']]  # Use relevant features for prediction
    y_pred = model.predict(X)
    return y_pred

for line in iter(zeek_proc.stdout.readline, b''):
    msg = next(consumer)
    line = msg.value
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df.columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
    df = df.drop(['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id','qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected'], axis=1)
    df = preprocess(df)
    print(df.head(20))
    y_pred = predict(df)
    producer.send('pred', str(y_pred.tolist()).encode())
    print('y_pred')
    time.sleep(0.1)

producer.close()
consumer.close()

