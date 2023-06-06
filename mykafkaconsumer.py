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


def extract_features(query):
    features = {}
    
    extracted = tldextract.extract(query)
    domain = extracted.domain
    subdomain = extracted.subdomain
    print(domain)
    print(subdomain)
    
 
    features['length'] = len(subdomain)
    features['entropy'] = entropy(subdomain)
    features['vowel_consonant_ratio'] = vowel_consonant_ratio(subdomain)
    features['digits'] = sum(char.isdigit() for char in domain)
    
    
    alexa_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3, 5), min_df=1e-4, max_df=1.0)


    alexa_counts_matrix = alexa_vc.fit_transform([subdomain])
    alexa_counts = np.log10(alexa_counts_matrix.sum(axis=0).A1)
    alexa_ngrams_list = alexa_vc.get_feature_names_out()
    
    word_dataframe = pd.read_csv('words.txt', names=['word'], header=None, dtype={'word': str}, encoding='utf-8')

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
    
    alexa_match = alexa_counts * alexa_vc.transform([subdomain]).T
    features['alexa_grams'] = alexa_match.item() if alexa_match.size > 0 else 0
    
    # Compute word NGrams for the query
    dict_match = word_counts * word_vc.transform([subdomain]).T
    features['word_grams'] = dict_match.item() if dict_match.size > 0 else 0
    
    # Compute the difference between Alexa NGrams and word NGrams
    features['diff'] = features['alexa_grams'] - features['word_grams']
    
    return features

classifier = joblib.load('test_data/dga_detection3.joblib')

consumer = KafkaConsumer('dnslogs', bootstrap_servers=['localhost:9092'],
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                         enable_auto_commit=True)

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

suffix = None

for message in consumer:
    dns_message = message.value
    query = dns_message.get('query', 'default_value')
    print(query)

    # Preprocess and extract feature
   
    features = extract_features(query)
    print(features)

    subdomain_feature_values = list(features.values())
    subdomain_feature_array = np.array(subdomain_feature_values).reshape(1, -1)

        # Predict with the classifier model
    subdomain_prediction = classifier.predict(subdomain_feature_array)[0]
    print("Subdomain Prediction:", subdomain_prediction)

    # Prepare prediction output message
    prediction_message = {
    'query': query,
    'prediction': subdomain_prediction
}

    prediction_output = 'output_topic'
    # Publish prediction output to Kafka topic
    producer.send(prediction_output, json.dumps(prediction_message).encode('utf-8'))
    

producer.flush()
consumer.close()
producer.close()
    

     
    



