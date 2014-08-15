#!/usr/bin/python3
#__author__ = 'Nokta_strigo'

import hashlib
import sys
import os
import random
import getpass

chars = '`1234567890-=\\~!@#$%^&*()_+|qwertyuiop[]QWERTYUIOP{}asdfghjkl;\'ASDFGHJKL:"zxcvbnm,./ZXCVBNM<>? '

def convert_from_bin_to_string(bin_str):
    """Generates a text password from bytes. The last chars in password are less random."""
    rand_l = 0
    for i in bin_str:
        rand_l = rand_l * 256 + i
    s = ''
    while rand_l > 0:
        s += chars[rand_l % len(chars)]
        rand_l //= len(chars)
    return s

def ver2str(version):
    s = ""
    for i in range(version, -1, -1):
        s += str(i)
    return s

def calc_site_pwd(version, site, login, master_password):
    """Generates site-specific password from the master password.
    version - integer, used for changing password for specific site
    site - name of the site
    login - login on the site
    master_password - master (very secret) password

    SitePwd = ripemd160(ver2str(version) + sha512_hex(ver2str(version) + master_password + site + login) + site)
    all strings are encoded in utf-8
    where ver2str(version) returns (version+1) of consecutive decreasing numbers ending with 0, for example:
    ver2str(0) = 0
    ver2str(4) = 43210
    ver2str(12) = 1211109876543210

    Only first 24 chars are returned.
    """
    s = ver2str(version) + master_password + site + login
    h1 = hashlib.sha512(s.encode("utf-8")).hexdigest()
    h1 = ver2str(version) + h1 + site
    h2 = hashlib.new("ripemd160", h1.encode('utf-8')).digest()
    return convert_from_bin_to_string(h2)[:24]

def get_master_password_fingerprint(master_password):
    return hashlib.sha512(master_password.encode()).hexdigest()[:4]

def generate_site_pwd(master_password):
    print("version")
    ok = False
    while not ok:
        try:
            version = int(sys.stdin.readline())
        except ValueError:
            print("Must be non-negative integer")
            continue
        if version < 0:
            print("Must be non-negative integer")
            continue
        ok = True
    print("site")
    site = sys.stdin.readline()
    print("login")
    login = sys.stdin.readline()
    print(calc_site_pwd(version, site, login, master_password))

def generate_site_pwd_once():
    master_password = getpass.getpass('Enter master password')
    print("Pass fingerprint = %s" % get_master_password_fingerprint(master_password))
    generate_site_pwd(master_password)

def generate_site_pwd_many():
    master_password = getpass.getpass('Enter master password')
    print("Pass fingerprint = %s" % get_master_password_fingerprint(master_password))
    Finished = False
    while not Finished:
        generate_site_pwd(master_password)

def generate_random_pwd():
    """Generates random password.
    It uses several sources of randomness: user input string, OS crypto and non-crypto random generators."""
    print("Enter random string:")
    s1 = sys.stdin.readline().encode()
    random.seed()
    i1 = random.randint(0, 31)
    s2 = os.urandom(i1 + 31)
    h1 = hashlib.sha512(s1 + s2).digest()
    i1 = random.randint(0, 31)
    s2 = os.urandom(i1 + 31)
    h2 = hashlib.sha1(h1 + s2).digest()
    print(convert_from_bin_to_string(h2)[:20])

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '-r':
        generate_random_pwd()
    elif len(sys.argv) > 1 and sys.argv[1] == '-h':
        print("site_pass_gen.py [argument]\nArgument can be one of following:\n-h prints this help\n-r generates random "
              "password\n-m lets you generate many passwords from one master password.\nno argument - generates one "
              "password from your master password")
    elif len(sys.argv) > 1 and sys.argv[1] == '-m':
        print("Press Ctrl+C to exit")
        try:
            generate_site_pwd_many()
        except KeyboardInterrupt:
            print("\tExiting")
            Finished = True
    else:
        try:
            generate_site_pwd_once()
        except KeyboardInterrupt:
            print("\tExiting")
            Finished = True


