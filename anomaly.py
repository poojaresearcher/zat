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

filename = "dga_detection.pickle"
loaded_model = pickle.load(open(filename, "rb"))

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
            zeek_df['vowel-cons'] = zeek_df['query'].apply(vowel_consonant_ratio)

        # Use the zat DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        zeek_matrix = to_matrix.fit_transform(zeek_df[features])
        print(zeek_matrix.shape)

        # Train/fit and Predict anomalous instances using the Isolation Forest model
        odd_clf = RandomForestClassifier(n_estimators=20)  # Marking 20% as odd
        odd_clf.fit(zeek_df)

        # Now we create a new dataframe using the prediction from our classifier
        predictions = odd_clf.predict(zeek_matrix)
        odd_df = zeek_df[features][predictions == -1]
        display_df = zeek_df[predictions == -1].copy()

        # Now we're going to explore our odd observations with help from KMeans
        odd_matrix = to_matrix.fit_transform(odd_df)
        num_clusters = min(len(odd_df), 4)  # 4 clusters unless we have less than 4 observations
        display_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
        print(odd_matrix.shape)

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
