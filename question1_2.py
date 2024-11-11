import csv

# convert string to list of integer
def str_to_int_list(text):
  z = [ord(a) for a in text]
  for x in z:
    if x > 256:
      print("Code > 256: ", text)
      return False
  return z

# convert a strint to an integer
def str_to_int(x):
  x = str_to_int_list(x)
  if x == False:
    print("Le text n'est pas compatible!")
    return False

  res = 0
  for a in x:
    res = res * 256 + a
  i = 0
  res = ""
  for a in x:
    ci = "{:08b}".format(a )
    if len(ci)>8:
      print()
      print("long",a)
      print()
    res = res + ci
  res = eval("0b"+res)
  return res

# exponentiation modulaire
def modular_pow(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# inverse multiplicatif de a modulo m
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("Pas d'inverse multiplicatif")
    else:
      return x % m


# Clé publique Question 1.2
N = 172219604291138178634924980176652297603347655313304280071646410523864939208855547078498922947475940487766894695848119416017067844129458299713889703424997977808694983717968420001033168722360067307143390485095229367172423195469582545920975539060699530956357494837243598213416944408434967474317474605697904676813343577310719430442085422937057220239881971046349315235043163226355302567726074269720408051461805113819456513196492192727498270702594217800502904761235711809203123842506621973488494670663483187137290546241477681096402483981619592515049062514180404818608764516997842633077157249806627735448350463
e = 173

# Cryptogramme 1.2
C = 25782248377669919648522417068734999301629843637773352461224686415010617355125387994732992745416621651531340476546870510355165303752005023118034265203513423674356501046415839977013701924329378846764632894673783199644549307465659236628983151796254371046814548224159604302737470578495440769408253954186605567492864292071545926487199114612586510433943420051864924177673243381681206265372333749354089535394870714730204499162577825526329944896454450322256563485123081116679246715959621569603725379746870623049834475932535184196208270713675357873579469122917915887954980541308199688932248258654715380981800909

def encode_rsa_message(message, e, n):
    # Convert the string to an integer
    m = str_to_int(message)
    
    # Perform RSA encryption: C = M^e mod N
    c = modular_pow(m, e, n)
    
    return c
    
# Add this new function to handle the authors
def process_authors_from_csv(filename, is_tsv=False):
    authors = []
    with open(filename, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile) if not is_tsv else csv.DictReader(csvfile, delimiter='\t')
        for row in reader:
            if 'author' in row or 'authors' in row or 'name' in row:
                col_name = 'author' if 'author' in row else ('authors' if 'authors' in row else 'name')
                # Split authors by comma and strip whitespace
                row_authors = [author.strip() for author in row[col_name].split(',')]
                authors.extend(row_authors)
    
    # Remove duplicates while preserving order
    unique_authors = list(dict.fromkeys(authors))
    return unique_authors
  
# Loop over the unique authors and encode them using the public key (e, N). If the encoded message == C, print the author and exit the loop
def find_person_from_encoded_message(encoded_message, unique_authors):
  for author in unique_authors:
    encoded_message = encode_rsa_message(author, e, N)
    #encoded_message_lowercase = encode_rsa_message(author.lower(), e, N)
    if encoded_message == C:
      print("The encoded message is the same as the decoded message")
      return author
  return None
  
# https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/28201
unique_people = process_authors_from_csv('pantheon.tsv', is_tsv=True)
print(f"Number of unique famous people in pantheon.tsv: {len(unique_people)}")

person = find_person_from_encoded_message(C, unique_people)
if person is not None:
  print(f"The person is: {person}")
else:
  print("The person was not found")
