from config import Paths
import torch
import string
import csv
from tqdm import tqdm
from base_func import *
from password_model.model import PasswordModel


def _limit_torch_cpu_threads():
    """Avoid massive thread over-subscription when many worker processes run in parallel."""
    try:
        torch.set_num_threads(1)
    except RuntimeError:
        pass
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass


def char_to_index(character, alphabet):
    return alphabet.find(character)


def one_hot_encode(seq, alphabet, max_length=30):
    X = torch.zeros(len(alphabet), max_length)
    for index_char, char in enumerate(seq[::-1]):
        if char_to_index(char, alphabet) != -1:
            X[char_to_index(char, alphabet)][index_char] = 1.0
    return X


def predict(text, model, max_length, alphabet, cuda=False):
    assert isinstance(text, str)
    with torch.no_grad():
        model.eval()
        x = one_hot_encode(text, alphabet, max_length)
        x = torch.unsqueeze(x, 0)
        if cuda:
            x = x.cuda()
        output = model(x)
        # print(torch.exp(output))
        _, predicted = torch.max(output, 1)
        return predicted, torch.exp(output)


def predict_finetuned(text, model, max_length, alphabet, cuda=False):
    assert isinstance(text, str)
    with torch.no_grad():
        model.eval()
        x = one_hot_encode(text, alphabet, max_length)
        x = torch.unsqueeze(x, 0)
        if cuda:
            x = x.cuda()
        output = model(x)
        prob = torch.exp(output)[0]
        if prob[0] > 0.2:
            pred = 0
        else:
            if prob[1] > prob[2]:
                pred = 1
            else:
                pred = 2
        return pred, prob

def filter_password(hit_dict):
    _limit_torch_cpu_threads()
    alphabet = string.ascii_letters + string.digits + string.punctuation
    model = PasswordModel(len(alphabet))
    max_length = 30
    checkpoint = torch.load(Paths.password_model,map_location=torch.device('cpu'))
    model.load_state_dict(checkpoint['state_dict'])
    model.eval()
    
    filtered=[]
    for tmp in hit_dict:
        if 'pass' in tmp['rule_name']:
            predicted, exp=predict(tmp['value'][:30],model, max_length, alphabet, cuda=False)
            if predicted.item()==0:    #人工密钥包括人工+机械
                continue
        filtered.append(tmp)

    return filtered
if __name__ == '__main__':
    
    hit_dict=read_dict_bin('<PATH>')
    res=filter_password(hit_dict)
    print(len(res))
    write_json('<PATH>',res)
