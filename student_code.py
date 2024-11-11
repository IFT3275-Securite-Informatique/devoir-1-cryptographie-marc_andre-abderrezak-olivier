from crypt import gen_key, load_text_from_web # type: ignore
from collections import defaultdict
import time
import random
import math
import json
from collections import Counter
from difflib import SequenceMatcher, unified_diff

# Copied from test.py
def similarity_ratio(str1, str2):
    """
    Calcule le pourcentage de similarité entre deux chaînes de caractères.
    """
    return SequenceMatcher(None, str1, str2).ratio()

def count_corpus_symbols(text, symbols):
    freq = Counter()
    i = 0
    while i < len(text):
        found = False
        if i < len(text) - 1:
            two_chars = text[i:i+2]
            if two_chars in symbols:
                freq[two_chars] += 1
                i += 2
                found = True
        if not found and text[i] in symbols:
            freq[text[i]] += 1
            i += 1
        elif not found:
            i += 1
    return freq

def count_cryptogram_symbols(ciphertext):
    frequency_counter = Counter()
    for i in range(0, len(ciphertext), 8):
        symbol = ciphertext[i:i+8]
        frequency_counter[symbol] += 1
    return frequency_counter

def text_to_symbols(text, symbols):
    result = []
    i = 0
    while i < len(text):
        two_char = text[i:i+2]
        if two_char in symbols:
            result.append(two_char)
            i += 2
        else:
            if text[i] in symbols:
                result.append(text[i])
            i += 1
    return result

def process_hill_climbing_step(cipher_bigrams, ngram_counts, decrypted_symbols):
    score = 0.0
    possible_chars = set(decrypted_symbols.values()) | {'_'}
    prefix_totals = {}
    
    # Calculate score for each unique bigram
    for cipher_bigram, _ in cipher_bigrams.items(): 
        decrypted_bigram = tuple(decrypted_symbols.get(sym, '_') for sym in cipher_bigram)
        prefix = decrypted_bigram[:-1]
        
        # Get ngram count
        ngram_count = ngram_counts.get(decrypted_bigram, 0)
        
        # Get or calculate prefix total
        if prefix not in prefix_totals:
            prefix_total = 0
            for char in possible_chars:
                possible_ngram = prefix + (char,)
                prefix_total += ngram_counts.get(possible_ngram, 0)
            prefix_totals[prefix] = prefix_total
        
        prefix_total = prefix_totals[prefix]
        
        # Calculate probability and score
        if prefix_total > 0:
            probability = (ngram_count + 1) / (prefix_total + 1)
            score += -math.log(probability)
        else:
            score += -math.log(1e-10)
    
    return score

def build_ngram_counts(corpus, symbols, n=2):
    ngram_counts = defaultdict(int)
    corpus_symbols = text_to_symbols(corpus, symbols)
    
    # Add padding
    padded_text = ['_'] * (n-1) + corpus_symbols + ['_'] * (n-1)
    
    # Count all bigrams
    for i in range(len(corpus_symbols)):
        ngram = tuple(padded_text[i:i+n]) 
        ngram_counts[ngram] += 1
    
    return ngram_counts

def get_self_distances_score(crypto_symbol, corpus_symbol, crypto_self_distances, corpus_self_distances):
    crypto_dist = crypto_self_distances[crypto_symbol]
    corpus_dist = corpus_self_distances[corpus_symbol]
    
    # Calculate ratio of distances (smaller/larger)
    ratio = min(crypto_dist, corpus_dist) / max(crypto_dist, corpus_dist)
    
    return ratio

# Only used for debugging
def get_current_decrypted_text(mapping, crypto_bits):
    return ''.join(mapping.get(bit, '?') for bit in crypto_bits)

def decode_ciphertext(ciphertext, corpus, symbols):
    # Build bigram counts first
    ngram_counts = build_ngram_counts(corpus, symbols)
    
    # Count bigrams in ciphertext
    crypto_bits = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    cipher_bigrams = defaultdict(int)
    padded_bits = ['_'] * 1 + crypto_bits + ['_'] * 1
    for i in range(len(crypto_bits)):
        bigram = tuple(padded_bits[i:i+2])
        cipher_bigrams[bigram] += 1
    
    # Convert corpus to symbols
    corpus_symbols = text_to_symbols(corpus, symbols)
    # Split ciphertext into 8-bit chunks
    unique_bits = set(crypto_bits)
    
    # Calculate average distances between same symbols in corpus
    corpus_self_distances = {}
    for symbol in symbols:
        distances = []
        positions = [i for i, s in enumerate(corpus_symbols) if s == symbol]
        for i in range(len(positions)-1):
            distances.append(positions[i+1] - positions[i])
        if distances:
            corpus_self_distances[symbol] = sum(distances) / len(distances)
    
    # Calculate average distances between same symbols in cryptogram
    crypto_self_distances = {}
    for bits in unique_bits:
        distances = []
        positions = [j for j, b in enumerate(crypto_bits) if b == bits]
        for k in range(len(positions)-1):
            distances.append(positions[k+1] - positions[k])
        if distances:
            crypto_self_distances[bits] = sum(distances) / len(distances)
        else:
            crypto_self_distances[bits] = 0
    
    # Replace crypto_self_distances with a distance of 0 with the max distance found in crypto_self_distances
    max_distance = max(crypto_self_distances.values())
    for bits in crypto_self_distances:
        if crypto_self_distances[bits] == 0:
            crypto_self_distances[bits] = max_distance
    
    # INITIAL FREQUENCY ANALYSIS
    
    cipher_freq = count_cryptogram_symbols(ciphertext)
    corpus_freq = count_corpus_symbols(corpus, symbols)
    
    sorted_cipher_freq = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
    sorted_corpus_freq = sorted(corpus_freq.items(), key=lambda x: x[1], reverse=True)
    
    # DECRYPTION
    
    decryption_map = {}
    for (cipher_symbol, _), (plain_symbol, _) in zip(sorted_cipher_freq, sorted_corpus_freq):
        decryption_map[cipher_symbol] = plain_symbol
    
    start_time = time.time()
    
    # Initial score calculation
    best_score = process_hill_climbing_step(cipher_bigrams, ngram_counts, decryption_map)
    
    end_time = time.time()
    print(f"Initial scoring took {end_time - start_time:.2f} seconds")

    best_mapping = decryption_map.copy()

    print("\nInitial Scores:")
    print(f"Score: {best_score:.4f}")
    
    # # UNCOMMENT TO DEBUG SYMBOL ACCURACY
    # random.seed(42) # TODO : Revert to random seed

    # a = random.randint(3400, 7200)
    # b = random.randint(96000, 125000)
    # l = a+b
    # c = random.randint(0, len(corpus)-l)
    # M = corpus[c:c+l]
    
    # dictionnaire = gen_key(symbols)
    # # inverse the dictionnaire
    # inverse_dictionnary = {v: k for k, v in dictionnaire.items()}
    
    # # calculate the percentage of correct symbols
    # correct_symbols = sum(1 for symbol in best_mapping if best_mapping[symbol] == inverse_dictionnary[symbol])
    # print(f"\nDecryption symbols accuracy: {correct_symbols / len(dictionnaire) * 100:.2f}%")
    
    # HILL CLIMBING

    steps = 30000
    symbol_index = 0
    
    for step in range(steps):
        # # UNCOMMENT TO DEBUG SIMILARITY METRIC
        # if step % 1000 == 0:
        #     # Calculer la similarité
        #     temp_decrypted_text = get_current_decrypted_text(best_mapping, crypto_bits)
        #     similarity = similarity_ratio(M, temp_decrypted_text)
        #     print(f"Similarity after {step} steps: {similarity:.2%}")
        
        # current symbol (try each in order, then repeat)
        first_symbol = sorted_cipher_freq[symbol_index][0]
        # second symbol (probability of switch based on frequency)
        other_symbols = [s for s, _ in sorted_cipher_freq if s != first_symbol]
        
        # second symbol (self distance)
        self_distances_ratios= []
        for symbol in other_symbols:
            distance_score = get_self_distances_score(first_symbol, decryption_map[symbol], crypto_self_distances, corpus_self_distances)
            self_distances_ratios.append(distance_score)
            
        exp_ratios = [math.exp(ratio * 5) for ratio in self_distances_ratios]  
        sum_exp = sum(exp_ratios)
        self_distances_probabilities = [exp/sum_exp for exp in exp_ratios]
        
        second_symbol = random.choices(other_symbols, weights=self_distances_probabilities, k=1)[0]
        symbols_to_swap = [first_symbol, second_symbol]
        
        # Swap
        temp_map = decryption_map.copy()
        temp_map[symbols_to_swap[0]], temp_map[symbols_to_swap[1]] = temp_map[symbols_to_swap[1]], temp_map[symbols_to_swap[0]]

        # Calculate new score only for unseen mappings
        new_score = process_hill_climbing_step(cipher_bigrams, ngram_counts, temp_map)
        
        # UNCOMMENT TO DEBUG SYMBOL ACCURACY
        # correct_symbols = sum(1 for symbol in temp_map if temp_map[symbol] == inverse_dictionnary[symbol])
        
        explanation = f"{decryption_map[symbols_to_swap[0]]} -> {decryption_map[symbols_to_swap[1]]} | Old score: {best_score} | New score: {new_score}"
        
        # explanation = f"{decryption_map[symbols_to_swap[0]]} -> {decryption_map[symbols_to_swap[1]]} | Old score: {best_score} | New score: {new_score} | Symbol accuracy: {correct_symbols / len(dictionnaire) * 100:.2f}%"
        
        if new_score < best_score:
            print(f"Step {step} (improvement): " + explanation)
                
            # Accept the swap
            decryption_map = temp_map
            best_score = new_score
            best_mapping = temp_map.copy()
            
        # Move to next symbol to switch
        symbol_index = (symbol_index + 1) % len(sorted_cipher_freq)

    print("\nFinal Scores:")
    print(f"Score: {best_score:.4f}")
    
    # Decrypt using best mapping found
    decrypted_text = ''
    for i in range(0, len(ciphertext), 8):
        binary_symbol = ciphertext[i:i+8]
        decrypted_text += best_mapping.get(binary_symbol, '?')
    
    return decrypted_text

def decrypt(C):
  symbols = ['b', 'j', '\r', 'J', '”', ')', 'Â', 'É', 'ê', '5', 't', '9', 'Y', '%', 'N', 'B', 'V', '\ufeff', 'Ê', '?', '’', 'i', ':', 's', 'C', 'â', 'ï', 'W', 'y', 'p', 'D', '—', '«', 'º', 'A', '3', 'n', '0', 'q', '4', 'e', 'T', 'È', '$', 'U', 'v', '»', 'l', 'P', 'X', 'Z', 'À', 'ç', 'u', '…', 'î', 'L', 'k', 'E', 'R', '2', '_', '8', 'é', 'O', 'Î', '‘', 'a', 'F', 'H', 'c', '[', '(', "'", 'è', 'I', '/', '!', ' ', '°', 'S', '•', '#', 'x', 'à', 'g', '*', 'Q', 'w', '1', 'û', '7', 'G', 'm', '™', 'K', 'z', '\n', 'o', 'ù', ',', 'r', ']', '.', 'M', 'Ç', '“', 'h', '-', 'f', 'ë', '6', ';', 'd', 'ô', 'e ', 's ', 't ', 'es', ' d', '\r\n', 'en', 'qu', ' l', 're', ' p', 'de', 'le', 'nt', 'on', ' c', ', ', ' e', 'ou', ' q', ' s', 'n ', 'ue', 'an', 'te', ' a', 'ai', 'se', 'it', 'me', 'is', 'oi', 'r ', 'er', ' m', 'ce', 'ne', 'et', 'in', 'ns', ' n', 'ur', 'i ', 'a ', 'eu', 'co', 'tr', 'la', 'ar', 'ie', 'ui', 'us', 'ut', 'il', ' t', 'pa', 'au', 'el', 'ti', 'st', 'un', 'em', 'ra', 'e,', 'so', 'or', 'l ', ' f', 'll', 'nd', ' j', 'si', 'ir', 'e\r', 'ss', 'u ', 'po', 'ro', 'ri', 'pr', 's,', 'ma', ' v', ' i', 'di', ' r', 'vo', 'pe', 'to', 'ch', '. ', 've', 'nc', 'om', ' o', 'je', 'no', 'rt', 'à ', 'lu', "'e", 'mo', 'ta', 'as', 'at', 'io', 's\r', 'sa', "u'", 'av', 'os', ' à', ' u', "l'", "'a", 'rs', 'pl', 'é ', '; ', 'ho', 'té', 'ét', 'fa', 'da', 'li', 'su', 't\r', 'ée', 'ré', 'dé', 'ec', 'nn', 'mm', "'i", 'ca', 'uv', '\n\r', 'id', ' b', 'ni', 'bl']
  #symbols = ['b', 'j', '\r', 'J', '”', ')', 'Â', 'É', 'ê', '5', 't', '9', 'Y', '%', 'N', 'B', 'V', '\ufeff', 'Ê', '?', '’', 'i', ':', 's', 'C', 'â', 'ï', 'W', 'y', 'p', 'D', '—', '«', 'º', 'A', '3', 'n', '0', 'q', '4', 'e', 'T', 'È', '$', 'U', 'v', '»', 'l', 'P', 'X', 'Z', 'À', 'ç', 'u', '…', 'î', 'L', 'k', 'E', 'R', '2', '_', '8', 'é', 'O', 'Î', '‘', 'a', 'F', 'H', 'c', '[', '(', "'", 'è', 'I', '/', '!', ' ', '°', 'S', '•', '#', 'x', 'à', 'g', '*', 'Q', 'w', '1', 'û', '7', 'G', 'm', '™', 'K', 'z', '\n', 'o', 'ù', ',', 'r', ']', '.', 'M', 'Ç', '“', 'h', '-', 'f', 'ë', '6', ';', 'd', 'ô']
  
  # Charger le premier corpus et enlever les 10 000 premiers caractères
  url1 = "https://www.gutenberg.org/ebooks/13846.txt.utf-8"
  corpus1 = load_text_from_web(url1)

  # Charger le deuxième corpus et enlever les 10 000 premiers caractères
  url2 = "https://www.gutenberg.org/ebooks/4650.txt.utf-8"
  corpus2 = load_text_from_web(url2)

  # Combiner les deux corpus
  corpus = corpus1 + corpus2

  M = decode_ciphertext(C, corpus, symbols)
  
  return M
