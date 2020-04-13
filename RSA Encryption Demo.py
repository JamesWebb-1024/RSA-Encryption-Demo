from tkinter import *
import struct
import os
from math import gcd
from mod import Mod


# Returns true if a is prime, false if not
def IsPrime(a):
    for b in range(2, a - 1):
        if a % b == 0:
            return False
    return True


# Generates cryptographically secure 4 digit random numbers until it finds a prime.
def GenPrime():
    while True:
        rand = int(struct.unpack('I', os.urandom(4))[0])
        prime = round(rand / 1000000)
        if prime > 1000 and IsPrime(prime):
            return prime


# Calls gen_prime() twice to obtain 2 different primes that are different
def GenPQ():
    p1 = GenPrime()
    while True:
        p2 = GenPrime()
        if p2 != p1:
            return p1, p2


# Function for lowest common multiple, used in calculating u
def lcm(a, b):
    greater = 0
    if a > b:
        greater = a
    if a < b:
        greater = b
    while True:
        if (greater % a == 0) and (greater % b == 0):
            Lcm = greater
            break
        else:
            greater += 1
    return Lcm


# Chooses a value for e, which is the power that the message is raised to to encrypt it.
# E and N must be co-prime (gcd of the 2 is 1).
# Inputs are (n, u)
def GenE(n, u):
    while True:
        x = int(struct.unpack('I', os.urandom(4))[0])
        x = round(x / 1000000)
        if x < n and gcd(x, u) == 1:
            break
    return x


# Find D using Extended Euclidean Algorithm. D is the power that the encrypted message is raised to to decrypt it and
# is the modular inverse of E at mod N
def eucld(e, u):
    if e == 0:
        return u, 0, 1
    else:
        g, y, x = eucld(u % e, e)
        return g, x - (u // e) * y, y


def ModInv(e, u):
    g, x, y = eucld(e, u)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % u


# Combine into function that generates a full key
def GenKey():
    p, q = GenPQ()
    # print("p =", p)
    # print("q =", q)
    n = p * q
    # print("n =", n)
    u = lcm(p - 1, q - 1)
    # print("u =", u)
    e = GenE(n, u)
    # print("e =", e)
    d = ModInv(e, u)
    # print("d =", d)
    # pu_key = Mod(e, n)
    # pr_key = Mod(d, n)
    return n, e, d


# Input string of message
def SplitPairs(m):
    if len(m) % 2 != 0:
        m += " "
    split_m = []
    for a in range(0, int(len(m) / 2)):
        split = m[2 * a] + m[2 * a + 1]
        split_m.append(split)
    return split_m


# Input string of 2 characters, output 6 digit integer
def ASCIIPair(m):
    a = str(ord(m[0]))
    b = str(ord(m[1]))
    lengths = False
    while not lengths:
        if len(a) != 3:
            a = a[::-1]
            a = a + "0"
            a = a[::-1]
        if len(b) != 3:
            b = b[::-1]
            b = b + "0"
            b = b[::-1]
        else:
            lengths = True
    c = a + b
    return int(c)


# Input list of 2 character pairs, output list of 6 digit integers
def ApplyASCII(m):
    Asc = []
    for a in range(0, len(m)):
        Asc.append(ASCIIPair(m[a]))
    return Asc


# Input 6 digit integer and key, output encrypted integer as 8 digit string.
def Encrypt_Pair(m, pu_key):
    IntPair = int(m ** pu_key)
    StrPair = str(IntPair)
    while True:
        if len(StrPair) == 8:
            return StrPair
        else:
            StrPair = StrPair[::-1]
            StrPair = StrPair + "0"
            StrPair = StrPair[::-1]


# Input message, output list of encrypted integers
def Encrypt(m, pu_key):
    m = SplitPairs(m)
    m = ApplyASCII(m)
    enc = ""
    for a in range(0, len(m)):
        enc_str = Encrypt_Pair(m[a], pu_key)
        enc += enc_str
    return enc


def EncPairSeparate(m):
    SplitMes = []
    for a in range(0, int(len(m) / 8)):
        split = m[8 * a] + m[8 * a + 1] + m[8 * a + 2] + m[8 * a + 3] + m[8 * a + 4] + m[8 * a + 5] + m[8 * a + 6] + m[
            8 * a + 7]
        SplitMes.append(int(split))
    return SplitMes


# Takes raw encrypted message and decrypts each block to a 2 ASCII integer
def DecryptPairs(m, pr_key):
    dec = []
    for a in range(0, len(m)):
        p = int(m[a] ** pr_key)
        dec.append(p)
    return dec


# Separates one ASCII pair into 2 ASCII integers
def PairSeparate(m):
    s = str(m)
    s = s[::-1]
    # l1 = ""
    l2 = s[0] + s[1] + s[2]
    if len(s) == 6:
        l1 = s[3] + s[4] + s[5]
    if len(s) == 5:
        l1 = s[3] + s[4] + "0"
    if len(s) == 4:
        l1 = s[3] + "00"
    l1 = l1[::-1]
    l2 = l2[::-1]
    return int(l1), int(l2)


# Loops over message separating all ASCII pairs
def NumSeparate(m):
    sep = []
    for a in range(0, len(m)):
        l1, l2 = PairSeparate(m[a])
        sep.append(l1)
        sep.append(l2)
    return sep


# Converts ASCII numbers to characters and combines all into one string
def ASCIIReverse(m):
    mes = ""
    for a in range(0, len(m)):
        mes = mes + chr(m[a])
    return mes


# Combines all decryption functions together
def Decrypt(m, pr_key):
    EncSepMessage = EncPairSeparate(m)
    DecMessage = DecryptPairs(EncSepMessage, pr_key)
    SepMessage = NumSeparate(DecMessage)
    return ASCIIReverse(SepMessage)


# Home page
Home = Tk()

HomeTitle = Label(Home, text="RSA key generation, encryption and decryption system")
HomeTitle.pack()

KeyPageOpen = False

HomeFrame = Frame(Home)
HomeFrame.pack()


def KeyCall():
    n, e, d = GenKey()
    print("Public key: E =", e, ", N =", n)
    print("Private key: D =", d, ", N =", n)


# Key generation page
def KeySwitch():
    print("Opening key generation page")
    KeyGen = Toplevel()

    KeyGenTitle = Label(KeyGen, text="Key generation page")
    KeyGenTitle.pack()

    Key = Button(KeyGen, text="Generate Key", command=KeyCall)
    Key.pack(side=LEFT)

    KeyQuit = Button(KeyGen, text="QUIT", fg="red", command=Home.quit)
    KeyQuit.pack(side=RIGHT)


# Encryption page
def EncryptionSwitch():
    print("Opening encryption page")
    EncryptGen = Toplevel()
    EncryptGenTitle = Label(EncryptGen, text="Encryption page")
    EncryptGenTitle.pack()

    TextInputTitle = Label(EncryptGen, text="Input message here:")
    TextInputTitle.pack(side=TOP)

    TextInput = Entry(EncryptGen)
    TextInput.pack(side=TOP)
    m = TextInput.get()

    EEntryTitle = Label(EncryptGen, text="Input E here:")
    EEntryTitle.pack(side=LEFT)

    EInput = Entry(EncryptGen)
    EInput.pack(side=LEFT)

    NInput = Entry(EncryptGen)
    NInput.pack(side=RIGHT)

    NEntryTitle = Label(EncryptGen, text="Input N here:")
    NEntryTitle.pack(side=RIGHT)

    def EncryptPress():
        n = int(NInput.get())
        e = int(EInput.get())
        message = TextInput.get()
        pu_key = Mod(e, n)
        EncMessage = Encrypt(message, pu_key)
        print("Your encrypted message is:", EncMessage)

    EncryptionButton = Button(EncryptGen, text="Encrypt", command=EncryptPress)
    EncryptionButton.pack(side=BOTTOM)


# Decryption page
def DecryptionSwitch():
    print("Opening decryption page")
    DecryptGen = Toplevel()
    DecryptGenTitle = Label(DecryptGen, text="Decryption page")
    DecryptGenTitle.pack()

    TextInputTitle = Label(DecryptGen, text="Input message here:")
    TextInputTitle.pack(side=TOP)

    TextInput = Entry(DecryptGen)
    TextInput.pack(side=TOP)
    m = TextInput.get()

    DEntryTitle = Label(DecryptGen, text="Input D here:")
    DEntryTitle.pack(side=LEFT)

    DInput = Entry(DecryptGen)
    DInput.pack(side=LEFT)

    NInput = Entry(DecryptGen)
    NInput.pack(side=RIGHT)

    NEntryTitle = Label(DecryptGen, text="Input N here:")
    NEntryTitle.pack(side=RIGHT)

    def DecryptPress():
        n = int(NInput.get())
        d = int(DInput.get())
        message = TextInput.get()
        pu_key = Mod(d, n)
        DecMessage = Decrypt(message, pu_key)
        print("Your decrypted message is:", DecMessage)

    DecryptionButton = Button(DecryptGen, text="Decrypt", command=DecryptPress)
    DecryptionButton.pack(side=BOTTOM)


HomeQuit = Button(HomeFrame, text="QUIT", fg="red", command=Home.quit)
HomeQuit.pack(side=RIGHT)

KeyButton = Button(HomeFrame, text="Key Generation Page", command=KeySwitch)
KeyButton.pack(side=LEFT)

EncryptButton = Button(HomeFrame, text="Encryption Page", command=EncryptionSwitch)
EncryptButton.pack(side=LEFT)

DecryptButton = Button(HomeFrame, text="Decryption Page", command=DecryptionSwitch)
DecryptButton.pack(side=LEFT)

# Start the main loop
Home.mainloop()
