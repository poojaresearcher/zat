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
dga_dataframe = pd.read_csv('test_data/dgaDomains.txt', names=['raw_domain'])

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