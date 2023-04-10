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

new_model = tf.keras.models.load_model('dgadetection.h5')

# Check its architecture
new_model.summary()


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
            features = ['Z', 'proto', 'query', 'qtype_name', 'query_length', 'answer_length', 'entropy']
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
            zeek_df['tld'] = [tldextract.extract(d).domain for d in zeek_df['query']]
            zeek_df['query']

        # Use the zat DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        zeek_matrix = to_matrix.fit_transform(zeek_df[features])
        print(zeek_matrix.shape)
        
zeek_df['label'] = 0
zeek_df['label'] = 1        
        
X,y = zeek_matrix, zeek_df['label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

new_model = Sequential_2()
new_model.add(Embedding(maxFeatures, 128, input_length=maxlen))

new_model.add(LSTM(128))
new_model.add(Dropout(0.5))
new_model.add(Dense(1))
new_model.add(Activation('sigmoid'))
new_model.compile(loss='binary_crossentropy',optimizer='rmsprop',metrics=['accuracy'])

for i in range(5):
    new_model.fit(X_train, y_train, batch_size=16, epochs=3, test_split=0.2)

import matplotlib as plt

predictions = new_model.predict(zeek_matrix)
zeek1_df = zeek_df[features][predictions == 1]
display_df = zeek_df[predictions == 1].copy()
        
if zeek_df[features][predictions == 0]:
    display_Df = zeek_df[predictions == 0].copy()
    print('legit domains')
else:
    display_Df = zeek_df[predictions == 1].copy()
    print('dga domains')

loss, acc = new_model.evaluate(test_images, test_labels, verbose=2)
print('Restored model, accuracy: {:5.2f}%'.format(100 * acc))

from sklearn.model_selection import cross_val_predict

proba = cross_val_predict

probs = new_model.predict(x_test)

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

