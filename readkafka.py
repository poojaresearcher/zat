import pandas as pd
import numpy as np
import io
import sys
from datetime import datetime
from kafka import KafkaProducer
import time
import subprocess
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
from zat import zeek_log_reader
from zat import log_to_dataframe
import io
import math
from collections import Counter
import re
import numpy as np
from pandas import read_csv, concat
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score 
import sklearn.feature_extraction
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
from sklearn import feature_extraction, tree, model_selection, metrics
from yellowbrick.features import Rank2D
from yellowbrick.features import RadViz
from yellowbrick.features import ParallelCoordinates

# Load trained classifier model
model = joblib.load('dga_detection.joblib')

# Set up Kafka producer
producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

# Read DNS log from standard input
for line in io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8'):
    # Preprocess query column to extract features
    df = pd.read_csv(io.StringIO(line), delimiter='\t', header=None)
    df.columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
    df['domain'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    df['digits'] = df['query'].str.count('[0-9]')
    df['vowel-cons'] = df['query'].map(lambda x: vowel_consonant_ratio(x))
    df['ngrams'] = df['query'].map(lambda x: compute_ngrams(x))
    df['ngram_count'] = df['query'].map(lambda x: ngram_count(x))
    df = pd.concat([df, extract_features(df['query'])], axis=1)
    X_test = df[['entropy', 'length', 'domain', 'digits', 'vowel-cons', 'ngrams', 'ngram_count']]
    
    # Make prediction using trained classifier model
    y_pred = model.predict(X_test)
    
    # Stream log data and prediction to Kafka topic
    for index, row in df.iterrows():
        producer.send('domainpred', str(row.to_dict()) + ' predicted class: ' + str(y_pred[index]))

