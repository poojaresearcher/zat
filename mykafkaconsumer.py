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
import sklearn.feature_extraction.text
import numpy as np
import pandas as pd


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
    
    return domain_features, modified_query


def extract_features(query):
    features = {}
  
    features['length'] = len(modified_query)
    features['entropy'] = entropy(modified_query)
    features['vowel_consonant_ratio'] = vowel_consonant_ratio(modified_query)
    features['digits'] = sum(char.isdigit() for char in modified_query)
    
    alexa_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3, 5), min_df=1e-4, max_df=1.0)


    alexa_counts_matrix = alexa_vc.fit_transform(modified_query)
    alexa_counts = np.log10(alexa_counts_matrix.sum(axis=0).A1)
    alexa_ngrams_list = alexa_vc.get_feature_names_out()
    
    word_dataframe = pd.read_csv('words.txt', names=['word'], header=None, dtype={'word': np.str}, encoding='utf-8')

# Cleanup words from dictionary
    word_dataframe = word_dataframe[word_dataframe['word'].map(lambda x: str(x).isalpha())]
    word_dataframe = word_dataframe.applymap(lambda x: str(x).strip().lower())
    word_dataframe = word_dataframe.dropna()
    word_dataframe = word_dataframe.drop_duplicates()
    


    word_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3, 5), min_df=1e-5, max_df=1.0)

    word_counts_matrix = word_vc.fit_transform(word_dataframe['word'])
    word_counts = np.log10(word_counts_matrix.sum(axis=0).A1)
    word_ngrams_list = word_vc.get_feature_names_out()

    def ngram_count(google):
        alexa_match = alexa_counts * alexa_vc.transform([google]).T
        dict_match = word_counts * word_vc.transform([google]).T
        print(f'{google} Alexa match: {alexa_match}, Dict match: {dict_match}')
    
    alexa_match = td_counts * test_data_vc.transform([modified_query]).T
    features['alexa_grams'] = alexa_match.item() if alexa_match.size > 0 else 0
    
    # Compute word NGrams for the query
    dict_match = dict_counts * dict_vc.transform([modified_query]).T
    features['word_grams'] = dict_match.item() if dict_match.size > 0 else 0
    
    # Compute the difference between Alexa NGrams and word NGrams
    features['diff'] = features['alexa_grams'] - features['word_grams']

    return features

classifier = joblib.load('dga_detection.joblib')

consumer = KafkaConsumer('dnslogs', bootstrap_servers=['localhost:9092'],
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')))

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

suffix = None

for message in consumer:
    dns_message = message.value
    query = dns_message.get('query', 'default_value')
    print(query)

    # Preprocess and extract feature
    domain_features, modified_query = extract_domain(query)
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
    

     
    



