import kafka
from kafka import KafkaConsumer
from zeek import LogReader
import pandas as pd
from sklearn.externals import joblib
from sklearn.preprocessing import StandardScaler

# Load the trained ML model and scaler
model = joblib.load('model.pkl')
scaler = joblib.load('scaler.pkl')

consumer = KafkaConsumer('dns_logs', bootstrap_servers=['localhost:9092'])

for message in consumer:
    # Convert the log entry to a pandas DataFrame
    log_entry = message.value.decode('utf-8')
    df = pd.read_csv(pd.compat.StringIO(log_entry), delimiter='\t', header=None, names=['ts', 'uid', 'id.orig_h', 'id.resp_h', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected'])
    
    # Preprocess the data using the scaler
    features = df[['qclass', 'qtype', 'AA', 'TC', 'RD', 'RA']].values
    features = scaler.transform(features)
    
    # Make a prediction using the ML model
    prediction = model.predict(features)
    
    # Print the prediction and the original log entry
    print(prediction, log_entry)

consumer.close()


