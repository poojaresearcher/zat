# -*- coding: utf-8 -*-
"""model.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1bRqLp4vWZ-auGTzGjVARZudzmTQy5kB0
"""

import numpy as np
import pandas as pd
from pandas import read_csv, concat
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score 



import tldextract
import tensorflow as tf
from tensorflow import keras
from keras_preprocessing.sequence import pad_sequences
from keras.models import Sequential, load_model
from keras.layers.core import Dense, Dropout, Activation,Embedding
from keras.layers import LSTM
import warnings
warnings.filterwarnings('ignore')

legitDomains = pd.read_csv('test_data/top-1m.csv', names=['domain'])
dgaDomains = pd.read_csv('test_data/dgaDomains.txt', names=['domain'])

legitDomains.head()

dgaDomains.head()

legitDomains['tld'] = [tldextract.extract(d).domain for d in legitDomains['domain']]
dgaDomains['tld'] = [tldextract.extract(d).domain for d in dgaDomains['domain']]

legitDomains = legitDomains[-legitDomains['tld'].str.contains('\`|\.')]
dgaDomains = dgaDomains[-dgaDomains['tld'].str.contains('\`|\.')]

legitDomains = legitDomains.drop_duplicates()
dgaDomains = dgaDomains.drop_duplicates()

legitDomains['label'] = 0
dgaDomains['label'] = 1

allDomains = concat([legitDomains, dgaDomains], ignore_index = True)
allDomains = allDomains.sample(frac=1).reset_index(drop=True)

X,y = allDomains['tld'], allDomains['label']

allDomains.head()

allDomains.tail()

allDomains.info()

allDomains.sample()

allDomains.head()

validChars = { x: idx + 1 for idx, x in enumerate(set(''.join(X)))}
maxFeatures = len(validChars) + 1
maxlen = np.max([len(x) for x in X ])

X = [[validChars[y] for y in x] for x in X]
X = pad_sequences(X, maxlen=maxlen)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = Sequential()
model.add(Embedding(maxFeatures, 128, input_length=maxlen))

model.add(LSTM(128))
model.add(Dropout(0.5))
model.add(Dense(1))
model.add(Activation('sigmoid'))
model.compile(loss='binary_crossentropy',optimizer='rmsprop',metrics=['accuracy'])

for i in range(5):
    model.fit(X_train, y_train, batch_size=16, epochs=3, validation_split=0.2)

import matplotlib as plt

domain = [[validChars[ch] for ch in tldextract.extract('wikipedia.com').domain]]
domain = pad_sequences(domain, maxlen=maxlen)

model.predict(domain)

from sklearn.model_selection import cross_val_predict

proba = cross_val_predict

probs = model.predict(X_test)

tn, fp, fn, tp = confusion_matrix(y_test, probs > 0.5).ravel()

print('TP: %d\nTN: %d\nFP: %d\nFN: %d\n' % (tp, tn, fp, fn))
print('FP rate: %.3f%%\nFN rate: %.3f%%\n' % (fp / (fp + tn) * 100, fn / (fn + tp) * 100))

print('Sensitivity: %.3f%%\nSpecificity: %.3f%%\nAcuuracy: %.3f%%\n' % (
    tp / (tp + fn),
    tn / (tn + fp),
    (tp + tn) / (tp + tn + fp + fn)
))

print('AUC: %.3f%%' % roc_auc_score(y_test, probs))

model.save('dgadetection1.h5')















