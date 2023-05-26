from kafka import KafkaProducer
from kafka.consumer import KafkaConsumer
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
import time
import subprocess

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
zeek_proc = subprocess.Popen(['tail', '-f', '/opt/zeek/logs/current/dns.log'], stdout=subprocess.PIPE)

consumer = KafkaConsumer('dnslogs', bootstrap_servers=['localhost:9092'])
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
    df = df.drop(df.columns[[0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]], axis=1, errors='ignore')
    print(df.head(20))
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')
    producer.send('dnslogs', preprocessed_line.encode('utf-8'))
    time.sleep(0.1)
    

for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    print(preprocessed_line)
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')
    df = df.drop([0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18], axis=1, errors='ignore')
    print(df.head(10))
    dns_message = df['query']
    print(dns_message)
    

producer.close()
consumer.close()

