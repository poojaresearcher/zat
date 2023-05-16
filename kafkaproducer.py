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
    # Preprocess the DNS logs
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df = pd.DataFrame(columns=['ts', 'uid', 'id.orig_h','id.orig_p','id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'rejected'])
    df = df.drop(['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'rejected'], axis=1)
    df['domain'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    df['digits'] = df['query'].str.count('[0-9]')
    df['vowel-cons'] = df['query'].map(lambda x: vowel_consonant_ratio(x))
    
    
test_data_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-4, max_df=1.0)

counts_matrix = test_data_vc.fit_transform(df['domain'])
td_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = test_data_vc.get_feature_names_out()

import operator
_sorted_ngrams = sorted(zip(ngrams_list, td_counts), key=operator.itemgetter(1), reverse=True)
print = ('Alexa NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = (ngram, count)


word_dataframe = pd.read_csv('words.txt', names=['word'], header=None, dtype={'word': np.str}, encoding='utf-8')


word_dataframe = word_dataframe[word_dataframe['word'].map(lambda x: str(x).isalpha())]
word_dataframe = word_dataframe.applymap(lambda x: str(x).strip().lower())
word_dataframe = word_dataframe.dropna()
word_dataframe = word_dataframe.drop_duplicates()
word_dataframe.head(10)

dict_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-5, max_df=1.0)
counts_matrix = dict_vc.fit_transform(word_dataframe['word'])
dict_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = dict_vc.get_feature_names_out()

import operator
_sorted_ngrams = sorted(zip(ngrams_list, dict_counts), key=operator.itemgetter(1), reverse=True)
print = ('Word NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = ('ngrams, count')


    df['alexa_grams']= td_counts * test_data_vc.transform(df['domain']).T
    df['word_grams']= dict_counts * dict_vc.transform(df['domain']).T
    df['diff'] = df['alexa_grams'] - df['word_grams']
    df = pd.concat([df[['entropy', 'length', 'domain', 'digits', 'vowel-cons', 'alexa_grams', 'word_grams']]], axis=1)
    print(df.head(10))
    X_test = df
    y_pred = model.predict(X_test)
    print(y_Pred)
    
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')
    # Send the preprocessed DNS logs to Kafka
    producer.send('dnslogs', preprocessed_line.encode('utf-8'))
    time.sleep(0.1)



for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')



