import argparse
import csv
import itertools
import json
import os

import gensim
import keras
import keras.backend as K
import numpy as np
import pandas as pd
from gensim.models import KeyedVectors
from keras import backend as K
from keras.layers import Layer
from keras.models import load_model
from keras.preprocessing.sequence import pad_sequences
from nltk.corpus import stopwords

# from util import make_w2v_embeddings
# from util import split_and_zero_padding, text_to_word_list

max_seq_length = 160
# canshu
# parser = argparse.ArgumentParser()

# parser.add_argument('-i', '--input_path', dest='input_path',
#                     help='The data folder saving binaries information', type=str, required=True)
# # parser.add_argument('-o', '--output_path', dest='output_path', help='The file saving the output file.',
# #                     type=str, required=False, default='../result/SiameseLSTM_1.png')

# load model
# args = parser.parse_args()
model = load_model("model/dim300_w8_mc8_e11.h5")

def text_to_word_list(text):
    # Pre process and convert texts to a list of words
    text = str(text)
    text = text.lower()

    # Clean the text
    #
    text = text.split(' ')

    return text
def split_and_zero_padding(df, max_seq_length):
    # Split to dicts
    X = {'left': df}

    # Zero padding
    for dataset, side in itertools.product([X], ['left']):
        dataset[side] = pad_sequences(dataset[side], padding='post', truncating='pre', maxlen=max_seq_length)
    return dataset['left']

class EmptyWord2Vec:
    """
    Just for test use.
    """
    vocab = {}
    word_vec = {}


def embedding(df):
    vocabs = {}
    vocabs_cnt = 0

    vocabs_not_w2v = {}
    vocabs_not_w2v_cnt = 0

    # Stopwords

    # Load word2vec
    file_json = open('code_prediction/vocabs.json','r')
    vocabs = json.load(file_json)
    vocabs_cnt = len(vocabs)
    for index, row in df.iterrows():
        # Print the number of embedded sentences.
       # if index != 0 and index % 1000 == 0:
        #    print("{:,} sentences embedded.".format(index), flush=True)

        # Iterate through the text of both questions of the row
        question = 'Op'
        # print(row[question])
        q2n = []  # q2n -> question numbers representation
        for word in text_to_word_list(row[question]):
            # Check for unwanted words
            if word not in vocabs:
                # vocabs_cnt += 1
                # vocabs[word] = vocabs_cnt
                q2n.append(0)
            else:
                q2n.append(vocabs[word])

            # Append question as number representation
            df.at[index, question + '_n'] = q2n
           # print(q2n)
    # print(df['Op_n'])
    return df

def prediction(path_exe):
    # load data
    PRED_CSV = path_exe
    csvFileObj = open(PRED_CSV, 'r')


    pred_df = pd.read_csv(PRED_CSV)
    # Load prediction set
    # pred_df = pd.read_csv(PRED_CSV)
    pred_df['Op' + '_n'] = pred_df['Op']
    pred_df = embedding(pred_df)

    # Split to train validation

    X = pred_df['Op_n']
    X = split_and_zero_padding(X, max_seq_length)
    # print(X[1].shape)

    pred = model.predict(X)
        # pred = model.predict(vec)
    # print(pred)

    csvReader = csv.reader(csvFileObj)
    lines = [l for l in csvReader]
    dict_fun={}
    # 使用字典保存数据，并返回
    for index in range(len(pred)+1):
        pred_int = 0 if pred[index-1][0] > 0.996 else 1
        if index == 0:
            
            lines[index].append("Type")
        else:
            lines[index].append(pred_int)
            dict_fun[lines[index][0]] = pred_int
    csvFileObj = open(PRED_CSV[:-4]+'_p'+PRED_CSV[-4:], 'w')
    csvWriter = csv.writer(csvFileObj)
    csvWriter.writerows(lines)
    # print(dict_fun)
    json_fun = json.dumps(dict_fun)
    return json_fun
# def ExtractFun(name_exe):
#     os.system("ida64 ida64 -A -S\"../extract_fun/extract_trace_v3.py\" "+name_exe)
# ExtractFun()
# print(prediction('../../test/test.csv'))
# for row in csvReader:
#     x = row[3]
#     print(x)
#     pred = model.predict([1,2,3,4,5,6,7,8,9,10,0])
#     print(pred)
