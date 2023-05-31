from kafka import KafkaConsumer,KafkaProducer
import time
import subprocess
from collections import Counter
import math
import joblib
import pickle
import json
import re 
import tldextract

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

def extract_domain(query):
    
    domain_features = {}
    extracted = tldextract.extract(query)
    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix

    modified_query = query.replace(f".{suffix}", "")
    print("Modified Query:", modified_query)

    merged_domain = f"{subdomain}.{domain}.{suffix}"
    print("Merged Domain:", merged_domain)

    domain_features['domain'] = domain
    domain_features['subdomain'] = subdomain

    return domain_features

def extract_features(query):
    features = {}
  
    features['length'] = len(domain)
    features['entropy'] = entropy(domain)
    features['vowel_consonant_ratio'] = vowel_consonant_ratio(domain)
    
    return features

classifier = joblib.load('dga_detection.joblib')

consumer = KafkaConsumer('dnslogs', bootstrap_servers=['localhost:9092'],
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')))

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

for message in consumer:
    dns_message = message.value
    query = dns_message.get('query', 'default_value')
    print(query)

    # Preprocess and extract feature
    domain_features =  extract_domain(modified_query)
    features = extract_features(modified_query)
    print(domain_features)
    print(features)

    # Predict with the classifier model
    prediction = classifier.predict([list(features.values())])[0]

    # Prepare prediction output message
    prediction_message = {
        'query': domain,
        'prediction': prediction
    }

    # Publish prediction output to Kafka topic
    producer.send(prediction_output, json.dumps(prediction_message).encode('utf-8'))
    

producer.flush()
consumer.close()
producer.close()
    

     
    



