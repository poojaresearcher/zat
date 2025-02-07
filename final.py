import os
import sys
import argparse
import time
import math
from collections import Counter
import pickle
import joblib

# Third Party Imports
import pandas as pd


# Local imports
from zat import zeek_log_reader, live_simulator
from zat import dataframe_to_matrix, dataframe_cache

classifier_model = joblib.load('dga_detection.pickle')


def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


if __name__ == '__main__':
    # Example to show the dataframe cache functionality on streaming data
    pd.set_option('display.width', 200)

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

        # Sanity check dns log
        if 'dns' in args.zeek_log:
            log_type = 'dns'
        else:
            print('This example only works with Zeek with dns.log files..')
            sys.exit(1)

        # Create a Zeek log reader
        print('Opening Data File: {:s}'.format(args.zeek_log))
        reader = zeek_log_reader.ZeekLogReader(args.zeek_log, tail=True)

        # Create a Zeek IDS log live simulator
        print('Opening Data File: {:s}'.format(args.zeek_log))
        reader = live_simulator.LiveSimulator(args.zeek_log, eps=10)  # 10 events per second

        # Create a Dataframe Cache
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=600)  # 10 minute cache

        # Use the ZeekThon DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()

        # Add each new row into the cache
        time_delta = 10
        timer = time.time() + time_delta
        FIRST_TIME = True
        for row in reader.rows():
            df_cache.add_row(row)

            # Every 30 seconds grab the dataframe from the cache
            if time.time() > timer:
                timer = time.time() + time_delta

                # Get the windowed dataframe (10 minute window)
                zeek_df = df_cache.dataframe()

                # Compute some addition data
                zeek_df['query_length'] = zeek_df['query'].str.len()
                zeek_df['answer_length'] = zeek_df['answers'].str.len()
                zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))

                # Use the zat DataframeToMatrix class
                features = ['qtype_name', 'query_length', 'answer_length', 'entropy']
                to_matrix = dataframe_to_matrix.DataFrameToMatrix()
                zeek_matrix = to_matrix.fit_transform(zeek_df[features])
                print(zeek_matrix.shape)
                
              
                
            

                # Print out the range of the daterange and some stats
                print('DataFrame TimeRange: {:s} --> {:s}'.format(str(zeek_df['ts'].min()), str(zeek_df['ts'].max())))
