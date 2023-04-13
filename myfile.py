import os
import sys
import argparse
import math
from collections import Counter
import pickle
import re

import numpy as np
import pandas as pd
from pandas import read_csv, concat
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score 
import sklearn.feature_extraction
import matplotlib.pyplot as plt
import seaborn as sns
import re
from sklearn import feature_extraction, tree, model_selection, metrics
from yellowbrick.features import Rank2D
from yellowbrick.features import RadViz
from yellowbrick.features import ParallelCoordinates

import sklearn.ensemble
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import cross_validate
from sklearn.model_selection import train_test_split


import tldextract
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation,Embedding
from keras.layers import LSTM
import warnings
warnings.filterwarnings('ignore')

# Third Party Imports
import pandas as pd

from sklearn.cluster import KMeans

# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix




if __name__ == '__main__':
    # Example to show the dataframe cache functionality on streaming data
    pd.set_option('display.width', 1000)

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Sanity check either http or dns log
        if 'http' in args.zeek_log:
            log_type = 'http'
            features = ['id.resp_p', 'method', 'resp_mime_types', 'request_body_len']
        elif 'dns' in args.zeek_log:
            log_type = 'dns'
            features = ['Z','query', 'proto', 'qtype_name', 'query_length', 'answer_length', 'entropy']
        else:
            print('This example only works with Zeek with http.log or dns.log files..')
            sys.exit(1)
            
        try:
            log_to_df = log_to_dataframe.LogToDataFrame()
            zeek_df = log_to_df.create_dataframe(args.zeek_log)
            print(zeek_df.head())
        except IOError:
            print('Could not open or parse the specified logfile: %s' % args.zeek_log)
            sys.exit(1)
        print('Read in {:d} Rows...'.format(len(zeek_df)))


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

if log_type == 'dns':
            zeek_df['query_length'] = zeek_df['query'].str.len()
            zeek_df['answer_length'] = zeek_df['answers'].str.len()
            zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))
            zeek_df['vowel-cons'] = zeek_df['query'].apply(vowel_consonant_ratio)
            zeek_df['subdomain'] = zeek_df['query'].map(lambda x: x.split('.')[0].strip().lower())
            zeek_df['digits'] = zeek_df['query'].str.count('[0-9]')
            zeek_df['uri'] = zeek_df['query']
            
import tldextract

def domain_extract(uri):
    ext = tldextract.extract(uri)
    if (not ext.suffix):
        return np.nan
    else:
        return ext.domain
def TLD_extract(uri):
    ext = tldextract.extract(uri)
    if (not ext.suffix):
        return np.nan
    else:
        return ext.suffix    
def subdomain_extract(uri):
    ext = tldextract.extract(uri)
    if (not ext.suffix):
        return np.nan
    else:
        return ext.subdomain     

if log_type == 'dns':
            zeek_df['query_length'] = zeek_df['query'].str.len()
            zeek_df['answer_length'] = zeek_df['answers'].str.len()
            zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))
            zeek_df['vowel-cons'] = zeek_df['query'].apply(vowel_consonant_ratio)
            zeek_df['digits'] = zeek_df['query'].str.count('[0-9]')
            zeek_df['domain'] = zeek_df['uri'].apply(domain_extract)           
            zeek_df['suffix'] = zeek_df['uri'].apply(TLD_extract) 
            zeek_df['subdomain'] = zeek_df['uri'].apply(subdomain_extract) 
            
            
print(zeek_df['domain'])
            
print(zeek_df['uri'])

zeek_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-4, max_df=1.0)


counts_matrix = zeek_vc.fit_transform(zeek_df['domain'].values.astype('U'))
zeek_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = zeek_vc.get_feature_names_out()


import operator
_sorted_ngrams = sorted(zip(ngrams_list, zeek_counts), key=operator.itemgetter(1), reverse=True)
print = ('domain NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = (ngram, count)
    
def ngram_count(domain):
    domain_match = zeek_counts * zeek_vc.transform([domain]).T  # Woot vector multiply and transpose Woo Hoo!
  
if log_type == 'dns':
            zeek_df['query_length'] = zeek_df['query'].str.len()
            zeek_df['answer_length'] = zeek_df['answers'].str.len()
            zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))
            zeek_df['vowel-cons'] = zeek_df['query'].apply(vowel_consonant_ratio)
            zeek_df['digits'] = zeek_df['query'].str.count('[0-9]')
            zeek_df['domain'] = zeek_df['uri'].apply(domain_extract)
            zeek_df['ngrams']= zeek_df['domain'].apply(lambda x: np.str_(x))
            zeek_df['suffix'] = zeek_df['uri'].apply(TLD_extract) 
            zeek_df['subdomain'] = zeek_df['uri'].apply(subdomain_extract)
            print('Read in {:d} Rows...'.format(len(zeek_df)))
                     
            
           
        

   
                


