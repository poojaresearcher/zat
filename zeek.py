


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







import pandas as pd
import sklearn
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import numpy as np

# Local imports
import zat
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
import warnings
warnings.filterwarnings("ignore")

# Good to print out versions of stuff
print('zat: {:s}'.format(zat.__version__))
print('Pandas: {:s}'.format(pd.__version__))
print('Numpy: {:s}'.format(np.__version__))
print('Scikit Learn Version:', sklearn.__version__)

# Create a Pandas dataframe from a Zeek log
log_to_df = LogToDataFrame()
zeek_df = log_to_df.create_dataframe('/home/logs/current/dns.log') 

# Print out the head of the dataframe
zeek_df.head()

zeek_df.head(100)

zeek_df['query'] 

zeek_df.head()

zeek_df['query_length'] = zeek_df['query'].str.len()

zeek_df['query_length']

zeek_df['query']

zeek_df['query_length']

zeek_df['query']


import math
from collections import Counter
 

zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))

zeek_df.head(10)

import tldextract

def domain_extract(query):
    ext = tldextract.extract(query)
    if (not ext.suffix):
        return np.nan
    else:
        return ext.domain


zeek_df['tld'] = [tldextract.extract(d).domain for d in zeek_df['query']]


zeek_df = zeek_df[-zeek_df['tld'].str.contains('\`|\.')]


zeek_df.head()

zeek_df['tld']
