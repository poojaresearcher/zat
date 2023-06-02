from kafka import KafkaConsumer, KafkaProducer
import time
import subprocess
from collections import Counter
import math
import joblib
import pickle
import json
import re 
import tldextract
import sklearn.feature_extraction.text
import numpy as np
import pandas as pd

def entropy(string):
    """Compute entropy on the string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def vowel_consonant_ratio(x):
    # Calculate vowel to consonant ratio
    x = x.lower()
    vowels_pattern = re.compile('([aeiou])')
    consonants_pattern = re.compile('([b-df-hj-np-tv-z])')
    vowels = re.findall(vowels_pattern, x)
    consonants = re.findall(consonants_pattern, x)
    try:
        ratio = len(vowels) / len(consonants)
    except ZeroDivisionError:
        ratio = 0
    return ratio

def extract_features(domai_features):
    features = {}
    
    extracted = tldextract.extract(query)
    domain = extracted.domain
    subdomain = extracted.subdomain
    
    domain_feature = {}
    domain_feature['length'] = len(domain)
    domain_feature['entropy'] = entropy(domain)
    domain_feature['vowel_consonant_ratio'] = vowel_consonant_ratio(domain)
    domain_feature['digits'] = sum(char.isdigit() for char in domain)
    features['domain'] = domain_feature
    
    
    subdomain_feature = {}
    subdomain_feature['length'] = len(subdomain)
    subdomain_feature['entropy'] = entropy(subdomain)
    subdomain_feature['vowel_consonant_ratio'] = vowel_consonant_ratio(subdomain)
    subdomain_feature['digits'] = sum(char.isdigit() for char in subdomain)
    features['subdomain'] = subdomain_feature
    
    
    return features

classifier = joblib.load('dga_detection.joblib')

consumer = KafkaConsumer('dnslog', bootstrap_servers=['localhost:9092'],
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')))

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

for message in consumer:
    dns_message = message.value
    query = dns_message.get('query', 'default_value')
    print(query)

    # Preprocess and extract features
    features = extract_features(query)
    print(features)

    # Predict with the classifier model
    prediction = classifier.predict([list(features.values())])[0]
    print(prediction)

    # Prepare prediction output message
    prediction_message = {
        'query': query,
        'prediction': prediction
    }

    predictions = 'output_topic'
    # Publish prediction output to Kafka topic
    producer.send(predictions, json.dumps(prediction_message).encode('utf-8'))
    
    producer.flush()
    consumer.commit()

consumer.close()
producer.close()

    


