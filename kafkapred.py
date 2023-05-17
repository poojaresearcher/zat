from kafka import KafkaProducer
import time
import subprocess
from collections import Counter
import math

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.log'], stdout=subprocess.PIPE)
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
    X = df[['domain', 'length', 'entropy', 'digits']].to_numpy()  # Use relevant features for prediction
    y_pred = model.predict(X)
    return y_pred

for line in iter(zeek_proc.stdout.readline, b''):
    msg = next(consumer)
    line = msg.value
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df.columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
    df = preprocess(df)
    y_pred = predict(df)
    for p in y_pred:
        producer.send('dns1', str(p).encode())
    time.sleep(0.1)

producer.close()

