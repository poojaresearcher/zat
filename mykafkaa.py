from kafka import KafkaConsumer, KafkaProducer
from nltk import ngrams
from string import ascii_lowercase
import math
import json
import re
import time
import subprocess
from collections import Counter
import math
import joblib
import pickle
import json


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
    features['length'] = len(query)
    features['entropy'] = entropy(query)
    features['vowel_consonant_ratio'] = vowel_consonant_ratio(query)
    features['ngrams'] = list(ngrams(query.lower(), 2))
    features['digits'] = bool(re.search(r'\d', query))
    return features
  
classifier = joblib.load('')






