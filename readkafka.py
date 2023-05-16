import pandas as pd
import numpy as np
import io
from datetime import datetime
from kafka import KafkaProducer
from sklearn.externals import joblib
from dns_entropy import entropy
from feature_extraction import extract_features

# Load trained classifier model
model = joblib.load('classifier_model.pkl')

# Set up Kafka producer
producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

# Read DNS log from standard input
for line in io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8'):
    # Preprocess query column to extract features
    df = pd.read_csv(io.StringIO(line), delimiter='\t', header=None)
    df.columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
    df['entropy'] = df['query'].apply(entropy)
    df = pd.concat([df, extract_features(df['query'])], axis=1)
    X_test = df[['entropy', 'length', 'num_digits', 'num_dots', 'num_hyphens', 'num_alpha']]
    
    # Make prediction using trained classifier model
    y_pred = model.predict(X_test)
    
    # Stream log data and prediction to Kafka topic
    for index, row in df.iterrows():
        producer.send('dns_log_predictions', str(row.to_dict()) + ' predicted class: ' + str(y_pred[index]))

