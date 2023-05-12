from kafka import KafkaProducer
from kafka.consumer import KafkaConsumer
import time
import subprocess
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
from zat import zeek_log_reader
import io
import math
from collections import Counter
import re
import numpy as np
 
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
   

# Well our Mom told us we were still cool.. so with that encouragement we're
# going to compute NGrams for every Alexa domain and see if we can use the
# NGrams to help us better differentiate and mark DGA domains...

# Scikit learn has a nice NGram generator that can generate either char NGrams or word NGrams (we're using char).
# Parameters: 
#       - ngram_range=(3,5)  # Give me all ngrams of length 3, 4, and 5
#       - min_df=1e-4        # Minimumum document frequency. At 1e-4 we're saying give us NGrams that 
#                            # happen in at least .1% of the domains (so for 100k... at least 100 domains)
test_data_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-4, max_df=1.0)


counts_matrix = test_data_vc.fit_transform(df['query'])
td_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = test_data_vc.get_feature_names_out()

import operator
_sorted_ngrams = sorted(zip(ngrams_list, td_counts), key=operator.itemgetter(1), reverse=True)
print = ('Alexa NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = (ngram, count)

# We're also going to throw in a bunch of dictionary words
word_dataframe = pd.read_csv('words.txt', names=['word'], header=None, dtype={'word': np.str}, encoding='utf-8')

# Cleanup words from dictionary
word_dataframe = word_dataframe[word_dataframe['word'].map(lambda x: str(x).isalpha())]
word_dataframe = word_dataframe.applymap(lambda x: str(x).strip().lower())
word_dataframe = word_dataframe.dropna()
word_dataframe = word_dataframe.drop_duplicates()
word_dataframe.head(10)

# Now compute NGrams on the dictionary words
# Same logic as above...
dict_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-5, max_df=1.0)
counts_matrix = dict_vc.fit_transform(word_dataframe['word'])
dict_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = dict_vc.get_feature_names_out()

import operator
_sorted_ngrams = sorted(zip(ngrams_list, dict_counts), key=operator.itemgetter(1), reverse=True)
print = ('Word NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = ('ngrams, count')





test_data['alexa_grams']= td_counts * test_data_vc.transform(test_data['domain']).T 
test_data['word_grams']= dict_counts * dict_vc.transform(test_data['domain']).T 
test_data.head()

test_data['diff'] = test_data['alexa_grams'] - test_data['word_grams']


for line in iter(zeek_proc.stdout.readline, b''):
    # Preprocess the DNS logs
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    df['query'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['query_length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    df['digits'] = df['query'].str.count('[0-9]')
    df['vowel-cons'] = df['query'].map(lambda x: vowel_consonant_ratio(x))
    df['alexa_grams']= td_counts * test_data_vc.transform(df['query']).T 
    df['word_grams']= dict_counts * dict_vc.transform(df['query']).T
    df['diff'] = df['alexa_grams'] - df['word_grams']

    print(df.head(20))
  
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')
    print(df)
    

    # Send the preprocessed DNS logs to Kafka
    producer.send('dnslogs', preprocessed_line.encode('utf-8'))
    time.sleep(0.1)



for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')



