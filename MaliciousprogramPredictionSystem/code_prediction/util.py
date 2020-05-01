import itertools
import json

import gensim
import numpy as np
from gensim.models import KeyedVectors
from keras import backend as K
from keras.layers import Layer
from keras.preprocessing.sequence import pad_sequences
from nltk.corpus import stopwords


def text_to_word_list(text):
    # Pre process and convert texts to a list of words
    text = str(text)
    text = text.lower()

    # Clean the text
    #
    text = text.split(' ')

    return text


def make_w2v_embeddings(df, model, embedding_dim=300, empty_w2v=False ):
    vocabs = {}
    vocabs_cnt = 0

    vocabs_not_w2v = {}
    vocabs_not_w2v_cnt = 0

    # Stopwords


    # Load word2vec
    print("Loading word2vec model(it may takes 2-3 mins) ...")

    if empty_w2v:
        word2vec = EmptyWord2Vec
    else:
       # word2vec = KeyedVectors.load_word2vec_format("./data/GoogleNews-vectors-negative300.bin.gz", binary=True)
        word2vec = gensim.models.word2vec.Word2Vec.load(model).wv

    for index, row in df.iterrows():
        # Print the number of embedded sentences.
       # if index != 0 and index % 1000 == 0:
        #    print("{:,} sentences embedded.".format(index), flush=True)

        # Iterate through the text of both questions of the row
        question = 'Op'
        #print(row[question])
        q2n = []  # q2n -> question numbers representation
        for word in text_to_word_list(row[question]):
            # Check for unwanted words

            # If a word is missing from word2vec model.
            if word not in word2vec.vocab:
                if word not in vocabs_not_w2v:
                    vocabs_not_w2v_cnt += 1
                    vocabs_not_w2v[word] = 1

            # If you have never seen a word, append it to vocab dictionary.
            if word not in vocabs:
                vocabs_cnt += 1
                vocabs[word] = vocabs_cnt
                q2n.append(vocabs_cnt)
            else:
                q2n.append(vocabs[word])

            # Append question as number representation
            df.at[index, question + '_n'] = q2n
           # print(q2n)
    str_dict = json.dumps(vocabs)
    file1= open('vocabs.json','w')
    file1.write(str_dict)
    embeddings = 1 * np.random.randn(len(vocabs) + 1, embedding_dim)  # This will be the embedding matrix
    embeddings[0] = 0  # So that the padding will be ignored

    # Build the embedding matrix
    for word, index in vocabs.items():
        if word in word2vec.vocab:
            embeddings[index] = word2vec.word_vec(word)
    del word2vec
    file_json = open('vocabs.json','w')
    str_dict = json.dumps(vocabs)
    file_json.write(str_dict)
    print(df['Op_n'])
    return df, embeddings

class Attention(Layer):
    def __init__(self, attention_size, **kwargs):
        self.attention_size = attention_size
        super(Attention, self).__init__(**kwargs)
 
    def build(self, input_shape):
        # W: (EMBED_SIZE, ATTENTION_SIZE)
        # b: (ATTENTION_SIZE, 1)
        # u: (ATTENTION_SIZE, 1)
        self.W = self.add_weight(name="W_{:s}".format(self.name),
                                 shape=(input_shape[-1], self.attention_size),
                                 initializer="glorot_normal",
                                 trainable=True)
        self.b = self.add_weight(name="b_{:s}".format(self.name),
                                 shape=(input_shape[1], 1),
                                 initializer="zeros",
                                 trainable=True)
        self.u = self.add_weight(name="u_{:s}".format(self.name),
                                 shape=(self.attention_size, 1),
                                 initializer="glorot_normal",
                                 trainable=True)
        super(Attention, self).build(input_shape)
 
    def call(self, x, mask=None):
        # input: (BATCH_SIZE, MAX_TIMESTEPS, EMBED_SIZE)
        # et: (BATCH_SIZE, MAX_TIMESTEPS, ATTENTION_SIZE)
        et = K.tanh(K.dot(x, self.W) + self.b)
        # at: (BATCH_SIZE, MAX_TIMESTEPS)
        at = K.softmax(K.squeeze(K.dot(et, self.u), axis=-1))
        if mask is not None:
            at *= K.cast(mask, K.floatx())
        # ot: (BATCH_SIZE, MAX_TIMESTEPS, EMBED_SIZE)
        atx = K.expand_dims(at, axis=-1)
        ot = atx * x
        # output: (BATCH_SIZE, EMBED_SIZE)
        output = K.sum(ot, axis=1)
        return output
 
    def compute_mask(self, input, input_mask=None):
        return None
 
    def compute_output_shape(self, input_shape):
        return (input_shape[0], input_shape[-1])

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
