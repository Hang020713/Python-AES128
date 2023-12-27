'''
128bit - 10 rounds
192bit - 12 rounds
256bit - 14 rounds

1 block = 16byte(128bit)
4row 4col

Round progression:
SubBytes
ShiftRows
MixColumns
AddRoundKey
*Last Round don't require to mixColumns

min: 128, max: 256bits

Full progression: https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf
'''

'''
SubBytes:
substitude each byte in plain text by a fixed table
the table called S-Box
'''
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
sboxInverse = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]
def subBytes(data):
    for i in range(len(data)):
        data[i] = sbox[data[i]]

def subBytesInverse(data):
    for i in range(len(data)):
        data[i] = sboxInverse[data[i]]

'''
ShiftRows
1st no change
2nd shift left once
3rd shift left twice
4th shift left thrice

Example:
Before
1 2 3 4
5 6 7 8
1 2 3 4
5 6 7 8
After
1 2 3 4
6 7 8 5
3 4 1 2
8 5 6 7
'''
def shiftRows(data):
    #Restruct new data
    for r in range(4):
        #Get row by row
        tmp = []
        for c in range(4):
            tmp.append(data[r + c * 4])
        
        #Shift
        tmp = tmp[r:] + tmp[0:r]
        
        #Replace
        for c in range(4):
            data[r + c * 4] = tmp[c]
def shiftRowsInverse(data):
    #Restruct new data
    for r in range(4):
        #Get row by row
        tmp = []
        for c in range(4):
            tmp.append(data[r + c * 4])
        
        #Shift
        tmp = tmp[4-r: 4] + tmp[0:4-r]
        
        #Replace
        for c in range(4):
            data[r + c * 4] = tmp[c]

'''
MixColumns
r for result
a for data
[r0]   [2 3 1 1]   [a0]
[r1] = [1 2 3 1] x [a1]
[r2]   [1 1 2 3]   [a2]
[r3]   [3 1 1 2]   [a3]

fixed polynomial
a(a) = 
3x^3 + x^2 + x + 2
a3x^3 + a2x^2 + a1x + a0

a^-1(x) = 
11x^3 + 13x^2 + 9x + 14


Galois field GF(28)
Rijndael MixColumns
Credit: https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
Credit: https://stackoverflow.com/questions/66115739/aes-mixcolumns-with-python
'''
def gmul(a, b):
    if b == 1:
        return a
    #0xff = 1111 1111
    #& And
    #128 = 1000 0000 (highest bit)
    #0x1b = 0001 1011
    tmp = (a << 1) & 0xff
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1b
    if b == 3:
        return gmul(a, 2) ^ a
    if b == 9:
        return gmul(gmul(gmul(a, 2), 2), 2)^a
    if b == 11:
        return gmul(gmul(gmul(a, 2), 2)^a, 2)^a
    if b == 13:
        return gmul(gmul(gmul(a, 2)^a, 2), 2)^a
    if b == 14:
        return gmul(gmul(gmul(a, 2)^a, 2)^a, 2)

def mixColumns(data):
    table = [
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2
    ]

    new_data = []
    for r in range(4):
        for c in range(4):
            tmp = 0
            for k in range(4):
                if(k == 0):    
                    tmp = gmul(data[r * 4 + k], table[c * 4 + k])
                else:
                    tmp = tmp ^ gmul(data[r * 4 + k], table[c * 4 + k])
            new_data.append(tmp)
    
    for i in range(len(data)):
        data[i] = new_data[i]
    return

def mixColumnsInverse(data):
    table = [
        14, 11, 13, 9,
        9, 14, 11, 13,
        13, 9, 14, 11,
        11, 13, 9, 14
    ]

    new_data = []
    for r in range(4):
        for c in range(4):
            tmp = 0
            for k in range(4):
                if(k == 0):    
                    tmp = gmul(data[r * 4 + k], table[c * 4 + k])
                else:
                    tmp = tmp ^ gmul(data[r * 4 + k], table[c * 4 + k])
            new_data.append(tmp)
    
    for i in range(len(data)):
        data[i] = new_data[i]
    return

'''
AddRoundKey

w refer original key
split into w[0], w[1], w[2] and w[3]
w[0] = (54, 68, 61, 74), w[1] = (73, 20, 6D, 79), w[2] = (20, 4B, 75, 6E), w[3] = (67, 20, 46, 75)

g(w[3])
1. left shift once
2. byte subsitution
3. add round constant (1, 0, 0, 0)
constant = [01, 02, 04, 08, 10, 20, 40, 80, 1B, 36] in hex

w[4] = g(w[3]) ^ w[0]
w[5] = w[4] ^ w[1]
w[6] = w[5] ^ w[2]
w[7] = w[6] ^ w[3]
'''
def addRoundKey(data, key, round):
    #Process g(w[3])
    constant = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    if(round > len(constant)):
        return

    new_key = []
    for i in range(len(key)):
        new_key.append(key[i])

    for i in range(round):
        gw3 = new_key[12:]
        gw3 = gw3[1:] + gw3[0:1]
        subBytes(gw3)
        gw3[0] ^= constant[i]

        #Process others
        tmp = []
        for k in range(4):
            for w in range(4):
                gw3[w] ^= new_key[k*4 + w]
                tmp.append(gw3[w])
        
        for i in range(len(tmp)):
            new_key[i] = tmp[i]
    
    '''
    #Print key
    print('[Key]:')
    for k in range(len(new_key)):
        print(hex(new_key[k]), end=' ')
    print()
    '''

    #Add key round
    for i in range(len(data)):
        data[i] = data[i] ^ new_key[i]

#128 16bit, 192 24bit, 256 32bit
def printHex(data):
    for r in range(4):
        for i in range(r, len(data), 4):
            print(hex(data[i]), end=' ')
        print()
    print()

def encrypt(data, key):
    #Loop block
    for b in range(int(len(data) / 16)):
        #Round 1
        for i in range(11):
            tmp_data = data[b * 16: (16)*(b + 1)]
            if(i == 0):
                addRoundKey(tmp_data, key, i)
                data[b * 16: (16)*(b + 1)] = tmp_data
                continue
            if(i == 10):
                #Last Round
                subBytes(tmp_data)
                shiftRows(tmp_data)
                addRoundKey(tmp_data, key, i)
                data[b * 16: (16)*(b + 1)] = tmp_data
                break
            subBytes(tmp_data)
            shiftRows(tmp_data)
            mixColumns(tmp_data)
            addRoundKey(tmp_data, key, i)

            #Replace
            data[b * 16: (16)*(b + 1)] = tmp_data

    return data

def decrypt(data, key):
    #Loop block
    for b in range(int(len(data) / 16)):
        #Loop round
        for i in range(10, -1, -1):
            tmp_data = data[b * 16: (16)*(b + 1)]
            if(i == 0):
                #Last Round
                shiftRowsInverse(tmp_data)
                subBytesInverse(tmp_data)
                addRoundKey(tmp_data, key, i)
                data[b * 16: (16)*(b + 1)] = tmp_data
                break
            if(i == 10):
                #First Round
                addRoundKey(tmp_data, key, i)
                data[b * 16: (16)*(b + 1)] = tmp_data
                continue

            shiftRowsInverse(tmp_data)
            subBytesInverse(tmp_data)
            addRoundKey(tmp_data, key, i)
            mixColumnsInverse(tmp_data)
            data[b * 16: (16)*(b + 1)] = tmp_data

    return data

def padding(data):
    #Not fit 128 bit
    if(len(data) % 16 == 0):
        return
    
    #More/Less then 128 bit
    while(len(data) % 16 != 0):
        data.append(0)

key =  'Thats my Kung Fu'
data = input('Enter plain text: ')
key_data = [ord(c) for c in key]
data_data = [ord(x) for x in data]
padding(data_data)

#Original data
print("[Original]", end=' ')
for i in range(len(data_data)):
    print(chr(data_data[i]), end='')
print()

#Encrypt text
encrypt_data = encrypt(data_data, key_data)
print("[Encrypt]", end=' ')
for i in range(len(encrypt_data)):
    print(chr(encrypt_data[i]), end='')
print()

#Decrypted text
decrypt_data = decrypt(encrypt_data, key_data)
print("[Decrypt]", end=' ')
for i in range(len(decrypt_data)):
    print(chr(decrypt_data[i]), end='')
print()