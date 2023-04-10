#!/usr/bin/env python
# coding: utf-8

# In[64]:


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


# In[18]:


alexa_dataframe = pd.read_csv(r'test_data/top-1m.csv', names=['rank','uri'])
dga_dataframe = pd.read_csv(r'test_data/dgaDomains.txt', names=['raw_domain'])


# In[19]:


alexa_dataframe.head()


# In[20]:


alexa_dataframe.tail()


# In[21]:


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


# In[22]:


alexa_dataframe.head()




# In[23]:


alexa_dataframe.tail()


# In[24]:


alexa_dataframe = alexa_dataframe.dropna()
alexa_dataframe = alexa_dataframe.drop_duplicates()


# In[25]:


alexa_dataframe = alexa_dataframe.reindex(np.random.permutation(alexa_dataframe.index))
alexa_dataframe_total = alexa_dataframe.shape[0]
print = ('Total legit domains %d') % alexa_dataframe_total

print = ('Number of legit domains: %d') % alexa_dataframe.shape[0]


# In[26]:


alexa_dataframe.head()


# In[27]:


alexa_dataframe.tail()


# In[28]:


dga_dataframe['domain'] = dga_dataframe.applymap(lambda x: x.split('.')[0].strip().lower())
del dga_dataframe['raw_domain']


# In[29]:


dga_dataframe_total = dga_dataframe.shape[0]
print = ('Total DGA domains %d') % dga_dataframe_total

print = ('Number of DGA domains: %d') % dga_dataframe.shape[0]


# In[30]:


dga_dataframe.head()


# In[31]:


dga_dataframe = dga_dataframe.dropna()
dga_dataframe = dga_dataframe.drop_duplicates()


# In[32]:


alexa_dataframe['class'] = 'legit'
dga_dataframe['class'] = 'dga'


alexa_dataframe['label'] = 0
dga_dataframe['label'] = 1


# In[33]:


alexa_dataframe['tld'] = [tldextract.extract(d).domain for d in alexa_dataframe['domain']]
dga_dataframe['tld'] = [tldextract.extract(d).domain for d in dga_dataframe['domain']]

alexa_dataframe = alexa_dataframe[-alexa_dataframe['tld'].str.contains('\`|\.')]
dga_dataframe = dga_dataframe[-dga_dataframe['tld'].str.contains('\`|\.')]


# In[34]:


allDomains = concat([alexa_dataframe, dga_dataframe], ignore_index = True)
allDomains = allDomains.sample(frac=1).reset_index(drop=True)

X,y = allDomains['tld'], allDomains['label']


# In[35]:


allDomains.head()


# In[36]:


allDomains.tail()


# In[37]:


allDomains.sample()


# In[38]:


allDomains['length'] = [len(x) for x in allDomains['domain']]


# In[39]:


allDomains.head()


# In[40]:


validChars = { x: idx + 1 for idx, x in enumerate(set(''.join(X)))}
maxFeatures = len(validChars) + 1
maxlen = np.max([len(x) for x in X ])


# In[41]:


X = [[validChars[y] for y in x] for x in X]
X = pad_sequences(X, maxlen=maxlen)


# In[42]:


allDomains = allDomains[allDomains['length'] > 3]
allDomains = allDomains[allDomains['length'] < 63]


# In[43]:


import math
from collections import Counter
 
def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())


# In[44]:


allDomains['entropy'] = [entropy(x) for x in allDomains['domain']]


# In[45]:


allDomains.head()


# In[46]:


allDomains.tail()


# In[47]:


import pylab


# In[48]:


pylab.rcParams['figure.figsize'] = (14.0, 5.0)
pylab.rcParams['axes.grid'] = True


# In[49]:


allDomains.boxplot('length','class')
pylab.ylabel('Domain Length')
allDomains.boxplot('entropy','class')
pylab.ylabel('Domain Entropy')


# In[50]:


cond = allDomains['class'] == 'dga'
dga = allDomains[cond]
alexa = allDomains[~cond]
plt.scatter(alexa['length'], alexa['entropy'], s=140, c='#aaaaff', label='Alexa', alpha=.2)
plt.scatter(dga['length'], dga['entropy'], s=40, c='r', label='DGA', alpha=.3)
plt.legend()
pylab.xlabel('Domain Length')
pylab.ylabel('Domain Entropy')


# In[51]:


high_entropy_domains = allDomains[allDomains['entropy'] > 4]; 
print = ("Num Domains above 4 entropy: %.2f%% %d (out of %d)") % \
           (100.0*high_entropy_domains.shape[0]/allDomains.shape[0],high_entropy_domains.shape[0],allDomains.shape[0])
print = ("Num high entropy legit: %d") % high_entropy_domains[high_entropy_domains['class']=='legit'].shape[0]
print = ("Num high entropy DGA: %d") % high_entropy_domains[high_entropy_domains['class']=='dga'].shape[0];


# In[52]:


high_entropy_domains[high_entropy_domains['class']=='legit'].head()


# In[53]:


high_entropy_domains[high_entropy_domains['class']=='dga'].head()


# In[54]:
        
        
        
if log_type == 'dns':
    zeek_df['query_length'] = zeek_df['query'].str.len()
    zeek_df['answer_length'] = zeek_df['answers'].str.len()
    zeek_df['entropy'] = zeek_df['query'].map(lambda x: entropy(x))
    zeek_df['tld'] = zeek_df[tldextract.extract(d).domain for d in zeek_df['domain']]

to_matrix = dataframe_to_matrix.DataFrameToMatrix()
zeek_matrix = to_matrix.fit_transform(zeek_df[features])
print(zeek_matrix.shape)

        # Train/fit and Predict anomalous instances using the Isolation Forest model
odd_clf = IsolationForest(contamination=0.2)  # Marking 20% as odd
odd_clf.fit(zeek_matrix)

        # Now we create a new dataframe using the prediction from our classifier
predictions = odd_clf.predict(zeek_matrix)
odd_df = zeek_df[features][predictions == 1]
display_df = zeek_df[predictions == 1].copy()

        # Now we're going to explore our odd observations with help from KMeans
odd_matrix = to_matrix.fit_transform(odd_df)
num_clusters = min(len(odd_df), 4)  # 4 clusters unless we have less than 4 observations
display_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
print(odd_matrix.shape)

        # Now group the dataframe by cluste
if log_type == 'dns':
    features += ['query']
else:
    features += ['host']
cluster_groups = display_df[features+['cluster']].groupby('cluster')

        # Now print out the details for each cluster
print('<<< dga domains Detected! >>>')
for key, group in cluster_groups:
    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
    print(group.head())




# List of feature vectors (scikit learn uses 'X' for the matrix of feature vectors)
df = allDomains
X= df[['length', 'entropy']].to_numpy() 
  

# Labels (scikit learn uses 'y' for classification labels)
y = np.array(allDomains['class'].tolist()) # Yes, this is weird but it needs 
                                            # to be an np.array of strings


# In[55]:


import sklearn.ensemble
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import cross_validate
from sklearn.model_selection import train_test_split


# In[56]:


clf = RandomForestClassifier(n_estimators=20)


# In[57]:


allDomains.head()


# In[58]:


allDomains.tail()


# In[59]:


X


# In[60]:


y


# In[61]:


scores = cross_val_score(clf, X, y, cv=5)
scores


# In[62]:


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)


# In[63]:


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





