#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import os
import sys
import argparse
import math
from collections import Counter

# Third Party Imports
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans

# Local imports
from zat import log_to_dataframe                         
from zat import dataframe_to_matrix

import numpy as np
import pandas as pd
from pandas import read_csv, concat
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score 



import tldextract
import tensorflow as tf
from tensorflow import keras
from keras.utils import pad_sequences
from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation,Embedding
from keras.layers import LSTM
import warnings
warnings.filterwarnings('ignore')

def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


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
            features = ['Z', 'proto', 'qtype_name', 'query_length', 'answer_length', 'entropy']
        else:
            print('This example only works with Zeek with http.log or dns.log files..')
            sys.exit(1)

        # Create a Pandas dataframe from a Zeek log
        try:
            log_to_df = log_to_dataframe.LogToDataFrame()
            zeek_df = log_to_df.create_dataframe(args.zeek_log)
            print(zeek_df.head())
        except IOError:
            print('Could not open or parse the specified logfile: %s' % args.zeek_log)
            sys.exit(1)
        print('Read in {:d} Rows...'.format(len(zeek_df)))

        # Using Pandas we can easily and efficiently compute additional data metrics
        # Here we use the vectorized operations of Pandas/Numpy to compute query length
        # We'll also compute entropy of the query
        if log_type == 'dns':
            zeek_df['query_length'] = zeek_df['query'].str.len()
            zeek_df['answer_length'] = zeek_df['answers'].str.len()
            zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))

        # Use the zat DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        zeek_matrix = to_matrix.fit_transform(zeek_df[features])
        print(zeek_matrix.shape)

        
legitDomains = pd.read_csv('top-1m.csv', names=['domain'])
dgaDomains = pd.read_csv('dgaDomains.txt', names=['domain'])


legitDomains.head()

dgaDomains.head()

legitDomains['tld'] = [tldextract.extract(d).domain for d in legitDomains['domain']]
dgaDomains['tld'] = [tldextract.extract(d).domain for d in dgaDomains['domain']]

legitDomains = legitDomains[-legitDomains['tld'].str.contains('\`|\.')]
dgaDomains = dgaDomains[-dgaDomains['tld'].str.contains('\`|\.')]

legitDomains = legitDomains.drop_duplicates()
dgaDomains = dgaDomains.drop_duplicates()

legitDomains['label'] = 0
dgaDomains['label'] = 1

allDomains = concat([legitDomains, dgaDomains], ignore_index = True)
allDomains = allDomains.sample(frac=1).reset_index(drop=True)

X,y = allDomains['tld'], allDomains['label']

allDomains.head()

allDomains.tail()

allDomains.info()

allDomains.sample()

allDomains.head()

validChars = { x: idx + 1 for idx, x in enumerate(set(''.join(X)))}
maxFeatures = len(validChars) + 1
maxlen = np.max([len(x) for x in X ])

X = [[validChars[y] for y in x] for x in X]
X = pad_sequences(X, maxlen=maxlen)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = Sequential()
model.add(Embedding(maxFeatures, 128, input_length=maxlen))

model.add(LSTM(128))
model.add(Dropout(0.5))
model.add(Dense(1))
model.add(Activation('sigmoid'))
model.compile(loss='binary_crossentropy',optimizer='rmsprop',metrics=['accuracy'])

for i in range(5):
    model.fit(X_train, y_train, batch_size=16, epochs=3, validation_split=0.2)
    
X_test = zeek_matrix

import matplotlib as plt

model.predict(query)

from sklearn.model_selection import cross_val_predict

proba = cross_val_predict

probs = model.predict(X_test)

tn, fp, fn, tp = confusion_matrix(y_test, probs > 0.5).ravel()

print('TP: %d\nTN: %d\nFP: %d\nFN: %d\n' % (tp, tn, fp, fn))
print('FP rate: %.3f%%\nFN rate: %.3f%%\n' % (fp / (fp + tn) * 100, fn / (fn + tp) * 100))

print('Sensitivity: %.3f%%\nSpecificity: %.3f%%\nAcuuracy: %.3f%%\n' % (
    tp / (tp + fn),
    tn / (tn + fp),
    (tp + tn) / (tp + tn + fp + fn)
))

print('AUC: %.3f%%' % roc_auc_score(y_test, probs))


        # Now group the dataframe by cluster
if log_type == 'dns':
    features += ['query']
else:
    features += ['host']
cluster_groups = display_df[features+['cluster']].groupby('cluster')

        # Now print out the details for each cluster
print('<<< Outliers Detected! >>>')
for key, group in cluster_groups:
    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
    print(group.head())

