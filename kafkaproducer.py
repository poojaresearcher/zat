from kafka import KafkaProducer
from kafka.consumer import KafkaConsumer
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
   
def compute_ngrams(word_list, S=3, T=3):
    """Compute NGrams in the word_list from [S-T)
        Args:
            word_list (list): A list of words to compute ngram set from
            S (int): The smallest NGram (default=3)
            T (int): The biggest NGram (default=3)
    """
    _ngrams = []
    if isinstance(word_list, str):
        word_list = [word_list]
    for word in word_list:
        for n in range(S, T+1):
            _ngrams += zip(*(word[i:] for i in range(n)))
    return [''.join(_ngram) for _ngram in _ngrams]


def ngram_count(word, ngrams):
    """Compute the number of matching NGrams in the given word"""
    return len(set(ngrams).intersection(compute_ngrams([word])))


for line in iter(zeek_proc.stdout.readline, b''):
    # Preprocess the DNS logs
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df = pd.DataFrame(df)
    columns_to_remove = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected']
    df = df.drop(columns_to_remove)
   
    
  
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')
   
    

    # Send the preprocessed DNS logs to Kafka
    producer.send('dnslogs', preprocessed_line.encode('utf-8'))
    time.sleep(0.1)



for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')



