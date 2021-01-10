#!/usr/bin/python3.9

import argparse, hashlib, sys


def hashing(hash):
  print('\033[32;1m[!] RESULT:\033[00;0m')
  print('\033[32;3m(#) String:\033[00;0m',hash)
  print('\033[32;3m(#) Bytes length:\033[00;0m',len(hash))
  quit('\nHOPE USEFULL ^_^')

def main():
  
  parser = argparse.ArgumentParser(prog='D-Hashes',usage='hashes.py [OPTIONS] STRING',description='Thanks for used this tool. It\'s support me to make many tool others. This is script for hashes function in python using hashlib.',epilog="""
\033[31;1m[! NOTES ]\033[00;0m
If your input string use spaces the quote or double quotes symbol (\' or ").

FOR EXAMPLE: \'This is my query string input\'

and if your string include a quote use like this:

\033[32;1mExample1:\033[00;0m \'Hai namaku "Arya" salken.\'
\033[32;1mExample2:\033[00;0m "Hai namaku \'Arya\' salken."
\033[32;1mExample3:\033[00;0m "Hai namaku \\"Arya\\" salken."
\033[32;1mExample4:\033[00;0m \'Hai namaku \\\'Arya\\\' salken.\'
\n
OR YOUR TEXT CAN BE LIKE THIS:
\"\"\"
This is my textarea data
Hole of spaces and quote
with 3 doublequotes
\"\"\"""")
  
  parser.add_argument('-blake2b',metavar='Blake2b',help='blake2b hash algorithm')
  parser.add_argument('-blake2s',metavar='Blake2s',help='blake2s hash algorithm')
  parser.add_argument('-md5',help='MD5 hash algorithm')
  parser.add_argument('-sha1',help='Sha1 hash algorithm')
  parser.add_argument('-sha224',help='sha224 hash algorithm')
  parser.add_argument('-sha256',help='sha256 hash algorithm')
  parser.add_argument('-sha384',help='sha384 hash algorithm')
  parser.add_argument('-sha3-224',help='sha3/224 hash algorithm')
  parser.add_argument('-sha3-256',help='sha3/256 hash algorithm')
  parser.add_argument('-sha3-384',help='sha3/384 hash algorithm')
  parser.add_argument('-sha3-512',help='sha3/512 hash algorithm')
  parser.add_argument('-sha512',help='sha512 hash algorithm')
  parser.add_argument('-shake128',help='shake-128 hash algorithm')
  parser.add_argument('-shake256',help='shake-256 hash algorithm')
  
  arg = parser.parse_args()
  
  if len(sys.argv) < 2:
    print(parser.print_help())
  else:
    if arg.blake2b:
      hash = hashlib.blake2b(arg.blake2b.encode())
      hashing(hash)
    if arg.blake2s:
      hash = hashlib.blake2s(arg.blake2s.encode()).hexdigest()
      hashing(hash)
    if arg.md5:
      hash = hashlib.md5(arg.md5.encode()).hexdigest()
      hashing(hash)
    if arg.sha1:
      hash = hashlib.sha1(arg.sha1.encode()).hexdigest()
      hashing(hash)
    if arg.sha224:
      hash = haslib.sha224(arg.sha224.encode()).hexdigest()
      hashing(hash)
    if arg.sha384:
      hash = hashlib.sha384(arg.sha384.encode()).hexdigest()
      hashing(hash)
    if arg.sha512:
      hash = hashlib.sha512(arg.sha512.encode()).hexdigest()
      hashing(hash)
    if arg.sha3_224:
      hash = hashlib.sha3_224(arg.sha3_224.encode()).hexdigest()
      hashing(hash)
    if arg.sha3_256:
      hash = hashlib.sha3_256(arg.sha3_256.encode()).hexdigest()
      hashing(hash)
    if arg.sha3_384:
      hash = hashlib.sha3_384(arg.sha3_384.encode()).hexdigest()
      hashing(hash)
    if arg.sha3_512:
      hash = hashlib.sha3_512(arg.sha3_512.encode()).hexdigest()
      hashing(hash)
    if arg.sha512:
      hash = hashlib.sha512(arg.sha512.encode()).hexdigest()
      hashing(hash)
    if arg.shake_128:
      hash = hashlib.shake_128(arg.shake_128.encode()).hexdigest()
      hashing(hash)
    if arg.shake_256:
      hash = hashlib.shake_256(arg.shake_256.encode()).hexdigest()
      hashing(hash)
    
  
if __name__ == '__main__':
  main()