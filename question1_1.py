# convert string to list of integer
def str_to_int_list(x):
  z = [ord(a) for a in x  ]
  for x in z:
    if x > 256:
      print(x)
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

# Public key
N = 143516336909281815529104150147210248002789712761086900059705342103220782674046289232082435789563283739805745579873432846680889870107881916428241419520831648173912486431640350000860973935300056089286158737579357805977019329557985454934146282550582942463631245697702998511180787007029139561933433550242693047924440388550983498690080764882934101834908025314861468726253425554334760146923530403924523372477686668752567287060201407464630943218236132423772636675182977585707596016011556917504759131444160240252733282969534092869685338931241204785750519748505439039801119762049796085719106591562217115679236583
e = 3

# Encoded message
C = 1101510739796100601351050380607502904616643795400781908795311659278941419415375

def find_cube_root(n):
    # Use integer binary search for cube root
    low, high = 0, n
    while low <= high:
        mid = (low + high) // 2
        mid_cubed = mid * mid * mid
        
        if mid_cubed == n:
            return mid
        elif mid_cubed < n:
            low = mid + 1
        else:
            high = mid - 1
    return high

def decode_rsa_message(C):
    # Use a more accurate cube root calculation
    M = find_cube_root(C)
    
    # Convert the integer back to a string
    decoded_message = ""
    while M > 0:
        char_code = M % 256
        decoded_message = chr(char_code) + decoded_message
        M //= 256
    
    return decoded_message

# Decode the message
decoded_message = decode_rsa_message(C)

print("Decoded message:", decoded_message)

def encode_rsa_message(message, e, N):
    # Convert the string to an integer
    M = str_to_int(message)
    
    # Perform RSA encryption: C = M^e mod N
    C = modular_pow(M, e, N)
    
    return C

# Encode Umberto Eco using the public key (e, N)
encoded_message = encode_rsa_message("Umberto Eco", e, N)
print("Encoded message:", encoded_message)

if encoded_message == C:
    print("The encoded message is the same as the decoded message")
else:
    print("The encoded message is not the same as the decoded message")