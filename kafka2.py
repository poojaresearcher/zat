from kafka import KafkaProducer
from kafka import KafkaConsumer
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

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.log'], stdout=subprocess.PIPE)

consumer = KafkaConsumer('pred', bootstrap_servers=['localhost:9092'])
model = joblib.load('dga_detection.joblib')
label_encoder = LabelEncoder()

def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
   
def vowel_consonant_ratio (x):
    # Calculate vowel to consonant ratio
    x = x.lower()
    vowels_pattern = re.compile('([aeiou])')
    consonants_pattern = re.compile('([b-df-hj-np-tv-z])')
    vowels = re.findall(vowels_pattern, x)
    consonants = re.findall(consonants_pattern, x)
    try:
        ratio = len(vowels) / len(consonants)
    except: # catch zero devision exception 
        ratio = 0  
    return ratio

for line in iter(zeek_proc.stdout.readline, b''):
  
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df = pd.DataFrame(columns=['ts', 'uid', 'id.orig_h','id.orig_p','id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'rejected'])
    df = df.drop(['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'rejected'], axis=1)
    df['domain'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    df['digits'] = df['query'].str.count('[0-9]')
    df['vowel-cons'] = df['query'].map(lambda x: vowel_consonant_ratio(x))
    df = pd.concat([df[['entropy', 'length', 'domain', 'digits', 'vowel-cons']]], axis=1)
    print(df.head(10))
    print('df is ready')
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')
    
    producer.send('domainpred', preprocessed_line.decode('utf-8'))
    time.sleep(0.1)

producer.close()

for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')

