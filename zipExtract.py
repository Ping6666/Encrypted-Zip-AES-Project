import os
import json, getpass
# pip install pyzipper
import pyzipper
# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
"""
pycryptodome  3.10.1
pycryptodomex 3.10.1
pyzipper      0.3.5
"""


def clearConsole():
    os.system('cls' if os.name == 'nt' else 'clear')
    return


def listProcessandPrint(nameList, num):
    clearConsole()
    # num: is divideNum, 1~4 will be good
    # n = len(nameList) // num
    nameList_ = [nameList[i:i + num] for i in range(0, len(nameList), num)]
    colWidth = max(len(word) for row in nameList_ for word in row) + 2
    for i, row in enumerate(nameList_):
        tmpString = ""
        for j, word in enumerate(row):
            wordNow = str('%02d: ' % (2 * i + j)) + word
            tmpString += wordNow.ljust(colWidth) + "  \t"
        print(tmpString)
    return


def decryptePass(myFile, salt, divideNum, txtPass):
    targetName = ' '
    a = -1
    # get decypte item
    while targetName not in myFile.keys():
        # break if targetName is All or correct name, or a number which in correct range
        listProcessandPrint(list(myFile.keys()), divideNum)
        targetName = input('Target name : ')
        # decrypte all mode
        if targetName == 'All':
            targetName = list(myFile.keys())
            break
        # decrypte single mode
        try:
            # decrypte single mode (with item sorted number)
            a = int(targetName)
            if a >= 0 and a <= len(list(myFile.keys())) - 1:
                # item number is good
                break
            else:
                # item out of range
                continue
        except:
            # item not a number
            continue
    # clear the name list
    clearConsole()
    # decrypte single mode (then print name)
    if type(targetName) != list:
        if int(a) != -1:
            # decrypte single mode (with item sorted number)
            print('Target name : ' + list(myFile.keys())[int(targetName)])
        else:
            # decrypte single mode
            print('Target name : ' + targetName)
        a = 0
    else:
        print('Target name : ' + 'All')
        a = -1
    # set txt password if no pre-set
    if txtPass == '':
        password = getpass.getpass('Password : ')
    else:
        password = txtPass
    try:
        # make targetName to be a list
        if type(targetName) != list:
            targetName = targetName.split()
        for target in targetName:
            # check password is correct or not
            key = PBKDF2(password, salt, dkLen=32)
            name = target
            try:
                # take out target by num (string to int)
                Target = myFile[list(myFile.keys())[int(target)]]
                name = list(myFile.keys())[int(target)]
            except:
                # take out target by name (string)
                Target = myFile[target]
            cipher = AES.new(key, AES.MODE_EAX, bytes.fromhex(Target["Nonce"]))
            data = cipher.decrypt_and_verify(bytes.fromhex(Target["Password"]),
                                             bytes.fromhex(Target["Tag"]))
            if a == 0:
                print(name + ': ' + str(Target["Level"]) + ': ' +
                      str(Target["Account"]) + ': ' + str(data.decode()))
            else:
                print(name.ljust(25) + '\t: ' + str(Target["Level"]) + ': ' + \
                    str(Target["Account"]).ljust(30) + ': ' + str(data.decode()))
        continue_ = input('continue (Y/N) : ')
        if continue_ != 'Y':
            return 0
        # clear the output
        clearConsole()
        return 1
    except:
        print("Bad AES password.")
        return 1


def encryptePass(password, key):
    clearConsole()
    print("Password     : " + str(password))
    data = bytes(input('Data         : '), 'utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    cipheredData, tag = cipher.encrypt_and_digest(data)
    print("cipheredData : " + str(cipheredData.hex()))
    print("Nonce        : " + str(cipher.nonce.hex()))
    print("Tag          : " + str(tag.hex()))
    # check if data is original data
    cipher_ = AES.new(key, AES.MODE_EAX, cipher.nonce)
    data_ = cipher_.decrypt_and_verify(cipheredData, tag)
    if str(data_.decode()) != str(data.decode()):
        print("Cipher incorrect with some unknow error!")
    continue_ = input('continue (Y/N) : ')
    if continue_ != 'Y':
        return 0
    return 1


def extractFile(inputFile, zipPass, txtPass, mode=0):
    # check if file exists.
    try:
        zf = pyzipper.AESZipFile(inputFile)
    except:
        print("File does not exist.")
        return 0
    # set zip password if no pre-set
    if zipPass == '':
        zipPassword = bytes(getpass.getpass('zip password : '), 'utf-8')
        zipPass = zipPassword
    else:
        zipPassword = zipPass
    zf.setpassword(zipPassword)
    # check zip file's hierarchy
    if 'salt.txt' not in zf.namelist() or 'pass.txt' not in zf.namelist():
        print("Bad zip file hierarchy.")
        return 0
    # try open the zip file, check password is correct or not
    try:
        bytes.fromhex(zf.read('salt.txt').decode())
    except:
        print("Bad zip password.")
        return 1
    clearConsole()
    if mode != 0:
        # encryption mode
        salt = bytes.fromhex(zf.read('salt.txt').decode())
        password = input('Password     : ')
        key = PBKDF2(password, salt, dkLen=32)
        while True:
            if encryptePass(password, key) != 1:
                break
    else:
        # decryption mode
        myFile = json.loads(zf.read('pass.txt').decode())
        salt = bytes.fromhex(zf.read('salt.txt').decode())
        while True:
            if decryptePass(myFile, salt, 2, txtPass) == 1:
                txtPass = ''
            else:
                break
    # clear all output
    clearConsole()
    return 0
