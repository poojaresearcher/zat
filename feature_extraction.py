

import numpy as np
import pandas as pd
from pandas import read_csv, concat
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score 
import sklearn.feature_extraction
import matplotlib.pyplot as plt
import seaborn as sns


import tldextract
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation,Embedding
from keras.layers import LSTM
import warnings
warnings.filterwarnings('ignore')

alexa_dataframe = pd.read_csv('test_data/top-1m.csv', names=['rank','uri'])
dga_dataframe = pd.read_csv('', names=['raw_domain'])

alexa_dataframe.head()

alexa_dataframe.tail()

import tldextract

def domain_extract(uri):
    ext = tldextract.extract(uri)
    if (not ext.suffix):
        return np.nan
    else:
        return ext.domain

alexa_dataframe['domain'] = [ domain_extract(uri) for uri in alexa_dataframe['uri']]
del alexa_dataframe['rank']
del alexa_dataframe['uri']
alexa_dataframe.head()

alexa_dataframe.head()

alexa_dataframe.tail()

alexa_dataframe = alexa_dataframe.dropna()
alexa_dataframe = alexa_dataframe.drop_duplicates()

alexa_dataframe = alexa_dataframe.reindex(np.random.permutation(alexa_dataframe.index))
alexa_dataframe_total = alexa_dataframe.shape[0]
print = ('Total legit domains %d') % alexa_dataframe_total


print = ('Number of legit domains: %d') % alexa_dataframe.shape[0]

alexa_dataframe.head()

alexa_dataframe.tail()

dga_dataframe['domain'] = dga_dataframe.applymap(lambda x: x.split('.')[0].strip().lower())
del dga_dataframe['raw_domain']

dga_dataframe_total = dga_dataframe.shape[0]
print = ('Total DGA domains %d') % dga_dataframe_total

print = ('Number of DGA domains: %d') % dga_dataframe.shape[0]

dga_dataframe.head()

dga_dataframe = dga_dataframe.dropna()
dga_dataframe = dga_dataframe.drop_duplicates()

alexa_dataframe['class'] = 'legit'
dga_dataframe['class'] = 'dga'


alexa_dataframe['label'] = 0
dga_dataframe['label'] = 1

alexa_dataframe['tld'] = [tldextract.extract(d).domain for d in alexa_dataframe['domain']]
dga_dataframe['tld'] = [tldextract.extract(d).domain for d in dga_dataframe['domain']]

alexa_dataframe = alexa_dataframe[-alexa_dataframe['tld'].str.contains('\`|\.')]
dga_dataframe = dga_dataframe[-dga_dataframe['tld'].str.contains('\`|\.')]

allDomains = concat([alexa_dataframe, dga_dataframe], ignore_index = True)
allDomains = allDomains.sample(frac=1).reset_index(drop=True)

X,y = allDomains['tld'], allDomains['label']

allDomains.head()

allDomains.tail()

allDomains.sample()

allDomains['length'] = [len(x) for x in allDomains['domain']]

allDomains.head()

validChars = { x: idx + 1 for idx, x in enumerate(set(''.join(X)))}
maxFeatures = len(validChars) + 1
maxlen = np.max([len(x) for x in X ])

X = [[validChars[y] for y in x] for x in X]
X = pad_sequences(X, maxlen=maxlen)

allDomains = allDomains[allDomains['length'] > 3]
allDomains = allDomains[allDomains['length'] < 63]

import math
from collections import Counter
 
def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

allDomains['entropy'] = [entropy(x) for x in allDomains['domain']]

allDomains.head()

allDomains.tail()

import pylab

pylab.rcParams['figure.figsize'] = (14.0, 5.0)
pylab.rcParams['axes.grid'] = True

allDomains.boxplot('length','class')
pylab.ylabel('Domain Length')
allDomains.boxplot('entropy','class')
pylab.ylabel('Domain Entropy')

cond = allDomains['class'] == 'dga'
dga = allDomains[cond]
alexa = allDomains[~cond]
plt.scatter(alexa['length'], alexa['entropy'], s=140, c='#aaaaff', label='Alexa', alpha=.2)
plt.scatter(dga['length'], dga['entropy'], s=40, c='r', label='DGA', alpha=.3)
plt.legend()
pylab.xlabel('Domain Length')
pylab.ylabel('Domain Entropy')

high_entropy_domains = allDomains[allDomains['entropy'] > 4]; 
print = ("Num Domains above 4 entropy: %.2f%% %d (out of %d)") % \
           (100.0*high_entropy_domains.shape[0]/allDomains.shape[0],high_entropy_domains.shape[0],allDomains.shape[0])
print = ("Num high entropy legit: %d") % high_entropy_domains[high_entropy_domains['class']=='legit'].shape[0]
print = ("Num high entropy DGA: %d") % high_entropy_domains[high_entropy_domains['class']=='dga'].shape[0];

high_entropy_domains[high_entropy_domains['class']=='legit'].head()

high_entropy_domains[high_entropy_domains['class']=='dga'].head()

# In preparation for using scikit learn we're just going to use
# some handles that help take us from pandas land to scikit land

# List of feature vectors (scikit learn uses 'X' for the matrix of feature vectors)
df = allDomains
X= df[['length', 'entropy']].to_numpy() 
  

# Labels (scikit learn uses 'y' for classification labels)
y = np.array(allDomains['class'].tolist()) # Yes, this is weird but it needs 
                                            # to be an np.array of strings

import sklearn.ensemble
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import cross_validate
from sklearn.model_selection import train_test_split

clf = RandomForestClassifier(n_estimators=20)

allDomains.head()

X

y

scores = cross_val_score(clf, X, y, cv=5)
scores

# Wow 96% accurate! At this point we could claim success and we'd be gigantic morons...
# Recall that we have ~100k 'legit' domains and only 3.5k DGA domains
# So a classifier that marked everything as legit would be about
# 96% accurate....

# So we dive in a bit and look at the predictive performance more deeply.

# Train on a 80/20 split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

# Now plot the results of the 80/20 split in a confusion matrix
from sklearn.metrics import confusion_matrix
labels = ['0', '1']
classes = ['legit', 'dga']
cm = confusion_matrix(y_test, y_pred, labels=classes)

def plot_cm(cm, labels):
    
    # Compute percentanges
    percent = (cm*100.0)/np.array(np.matrix(cm.sum(axis=1)).T)  # Derp, I'm sure there's a better way
    
    print = ("Confusion Matrix Stats")
    for i, label_i in enumerate(labels):
        for j, label_j in enumerate(labels):
            print = ("%s/%s: %.2f%% (%d/%d)") % (label_i, label_j, (percent[i][j]), cm[i][j], cm[i].sum())

    # Show confusion matrix
    # Thanks kermit666 from stackoverflow :)
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.grid()
    cax = ax.matshow(percent, cmap='coolwarm')
    pylab.title('Confusion matrix of the classifier')
    fig.colorbar(cax)
    ax.set_xticklabels([''] + labels)
    ax.set_yticklabels([''] + labels)
    pylab.xlabel('Predicted')
    pylab.ylabel('True')
    pylab.show()

plot_cm(cm, labels)

from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

# Well our Mom told us we were still cool.. so with that encouragement we're
# going to compute NGrams for every Alexa domain and see if we can use the
# NGrams to help us better differentiate and mark DGA domains...

# Scikit learn has a nice NGram generator that can generate either char NGrams or word NGrams (we're using char).
# Parameters: 
#       - ngram_range=(3,5)  # Give me all ngrams of length 3, 4, and 5
#       - min_df=1e-4        # Minimumum document frequency. At 1e-4 we're saying give us NGrams that 
#                            # happen in at least .1% of the domains (so for 100k... at least 100 domains)
alexa_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-4, max_df=1.0)

# I'm SURE there's a better way to store all the counts but not sure...
# At least the min_df parameters has already done some thresholding
counts_matrix = alexa_vc.fit_transform(alexa_dataframe['domain'])
alexa_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = alexa_vc.get_feature_names_out()

import operator
_sorted_ngrams = sorted(zip(ngrams_list, alexa_counts), key=operator.itemgetter(1), reverse=True)
print = ('Alexa NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = (ngram, count)

# We're also going to throw in a bunch of dictionary words
word_dataframe = pd.read_csv('/content/drive/MyDrive/words.txt', names=['word'], header=None, dtype={'word': np.str}, encoding='utf-8')

# Cleanup words from dictionary
word_dataframe = word_dataframe[word_dataframe['word'].map(lambda x: str(x).isalpha())]
word_dataframe = word_dataframe.applymap(lambda x: str(x).strip().lower())
word_dataframe = word_dataframe.dropna()
word_dataframe = word_dataframe.drop_duplicates()
word_dataframe.head(10)

# Now compute NGrams on the dictionary words
# Same logic as above...
dict_vc = sklearn.feature_extraction.text.CountVectorizer(analyzer='char', ngram_range=(3,5), min_df=1e-5, max_df=1.0)
counts_matrix = dict_vc.fit_transform(word_dataframe['word'])
dict_counts = np.log10(counts_matrix.sum(axis=0).getA1())
ngrams_list = dict_vc.get_feature_names_out()

import operator
_sorted_ngrams = sorted(zip(ngrams_list, dict_counts), key=operator.itemgetter(1), reverse=True)
print = ('Word NGrams: %d') % len(_sorted_ngrams)
for ngram, count in _sorted_ngrams[:10]:
    print = ('ngrams, count')

# We use the transform method of the CountVectorizer to form a vector
# of ngrams contained in the domain, that vector is than multiplied
# by the counts vector (which is a column sum of the count matrix).
def ngram_count(domain):
    alexa_match = alexa_counts * alexa_vc.transform([domain]).T  # Woot vector multiply and transpose Woo Hoo!
    dict_match = dict_counts * dict_vc.transform([domain]).T
    print = ('%s Alexa match:%d Dict match: %d') % (domain, alexa_match, dict_match)

# Examples:
ngram_count('google')
ngram_count('facebook')
ngram_count('1cb8a5f36f')
ngram_count('pterodactylfarts')
ngram_count('ptes9dro-dwacty2lfa5rrts')
ngram_count('beyonce')
ngram_count('bey666on4ce')

allDomains['alexa_grams']= alexa_counts * alexa_vc.transform(allDomains['domain']).T 
allDomains['word_grams']= dict_counts * dict_vc.transform(allDomains['domain']).T 
allDomains.head()

allDomains.tail()

allDomains['diff'] = allDomains['alexa_grams'] - allDomains['word_grams']


# The table below shows those domain names that are more 'dictionary' and less 'web'

allDomains['diff'].head(10)

allDomains.tail()

allDomains.sort_values(['diff'], ascending=True).head(10)

allDomains.sort_values(['diff'], ascending=False).head(30)

# The table below shows those domain names that are more 'web' and less 'dictionary'
# Good O' web....

# Lets plot some stuff!
# Here we want to see whether our new 'alexa_grams' feature can help us differentiate between Legit/DGA
cond = allDomains['class'] == 'dga'
dga = allDomains[cond]
legit = allDomains[~cond]
plt.scatter(legit['length'], legit['alexa_grams'], s=120, c='#aaaaff', label='Alexa', alpha=.1)
plt.scatter(dga['length'], dga['alexa_grams'], s=40, c='r', label='DGA', alpha=.3)
plt.legend()
pylab.xlabel('Domain Length')
pylab.ylabel('Alexa NGram Matches')

# Lets plot some stuff!
# Here we want to see whether our new 'alexa_grams' feature can help us differentiate between Legit/DGA
cond = allDomains['class'] == 'dga'
dga = allDomains[cond]
legit = allDomains[~cond]
plt.scatter(legit['entropy'], legit['alexa_grams'],  s=120, c='#aaaaff', label='Alexa', alpha=.2)
plt.scatter(dga['entropy'], dga['alexa_grams'], s=40, c='r', label='DGA', alpha=.3)
plt.legend()
pylab.xlabel('Domain Entropy')
pylab.ylabel('Alexa Gram Matches')

# Lets plot some stuff!
# Here we want to see whether our new 'word_grams' feature can help us differentiate between Legit/DGA
# Note: It doesn't look quite as good as the Alexa_grams but it might generalize better (less overfit).
cond = allDomains['class'] == 'dga'
dga = allDomains[cond]
legit = allDomains[~cond]
plt.scatter(legit['length'], legit['word_grams'],  s=120, c='#aaaaff', label='Alexa', alpha=.2)
plt.scatter(dga['length'], dga['word_grams'], s=40, c='r', label='DGA', alpha=.3)
plt.legend()
pylab.xlabel('Domain Length')
pylab.ylabel('Dictionary NGram Matches')

# Lets look at which Legit domains are scoring low on the word gram count
allDomains[(allDomains['word_grams']==0)].head(10)

# Okay these look kinda weird, lets use some nice Pandas functionality
# to look at some statistics around our new features.
allDomains[allDomains['class']=='legit'].describe()

legit = allDomains[(allDomains['class']=='legit')]
max_grams = np.maximum(legit['alexa_grams'],legit['word_grams'])
ax = max_grams.hist(bins=80)
ax.figure.suptitle('Histogram of the Max NGram Score for Domains')
pylab.xlabel('Number of Domains')
pylab.ylabel('Maximum NGram Score')

# Lets look at which Legit domains are scoring low on both alexa and word gram count
weird_cond = (allDomains['class']=='legit') & (allDomains['word_grams']<3) & (allDomains['alexa_grams']<2)
weird = allDomains[weird_cond]
weird.head(10)

allDomains.loc[weird_cond, 'class'] = 'weird'
allDomains['class'].value_counts()
allDomains[allDomains['class'] == 'weird'].head(10)

# Now we try our machine learning algorithm again with the new features
# Alexa and Dictionary NGrams and the exclusion of the bad exemplars.
df = allDomains
X =df[['length', 'entropy', 'alexa_grams', 'word_grams']].to_numpy()

# Labels (scikit learn uses 'y' for classification labels)
y = np.array(allDomains['class'].tolist())

# Train on a 80/20 split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

from sklearn.metrics import confusion_matrix

labels = ['0', '2', '1']
classes = ['legit', 'weird', 'dga']
cm = confusion_matrix(y_test, y_pred, labels=classes)
plot_cm(cm, labels)

# Perhaps we will just exclude the weird class from our ML training
not_weird = allDomains[allDomains['class'] != 'weird']
X = not_weird[['length', 'entropy', 'alexa_grams', 'word_grams']].to_numpy()

# Labels (scikit learn uses 'y' for classification labels)
y = np.array(not_weird['class'].tolist())

# Train on a 80/20 split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

labels = ['0', '1']
classes = ['legit', 'dga']
cm = confusion_matrix(y_test, y_pred, labels=classes)
plot_cm(cm, labels)

import re
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

df = allDomains
df['vowel-cons'] = df.domain.apply(vowel_consonant_ratio)

df.head()

df['digits'] = df.domain.str.count('[0-9]')

df.head(50)

