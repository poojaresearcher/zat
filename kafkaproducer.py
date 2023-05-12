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
    # Preprocess the DNS logs
    df = pd.read_csv(io.StringIO(line.decode('utf-8')), delimiter='\t', header=None)
    print(df.head(10))
    df.columns = ['query']
    df['query'] = df['query'].str.split('.').str[::-1].str.join('.')
    df['query_length'] = df['query'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    df['digits'] = df['query'].str.count('[0-9]')
    df['vowel-cons'] = df['query'].map(lambda x: vowel_consonant_ratio(x))
    preprocessed_line = df.to_csv(header=False, index=False, sep='\t')
    print(df['vowel-cons'])
    

    # Send the preprocessed DNS logs to Kafka
    producer.send('dnslogs', preprocessed_line.encode('utf-8'))
    time.sleep(0.1)



for msg in consumer:
    preprocessed_line = msg.value.decode('utf-8')
    df = pd.read_csv(io.StringIO(preprocessed_line), delimiter='\t')



