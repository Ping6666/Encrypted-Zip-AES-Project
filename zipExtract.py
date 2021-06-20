import os, sys, getopt
import json, getpass
# pip install pyzipper
import pyzipper
# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def clearConsole():
    os.system('cls' if os.name == 'nt' else 'clear')


def listProcessandPrint(nameList, divideNum):
    clearConsole()
    n = len(nameList) // divideNum
    nameList_ = [nameList[i:i + n] for i in range(0, len(nameList), n)]
    colWidth = max(len(word) for row in nameList_ for word in row) + 2
    for i, row in enumerate(nameList_):
        print("  ".join(word.ljust(colWidth) for word in row))


def aesProcess(myFile, salt, divideNum, txtPass):
    while True:
        targetName = ' '
        while targetName not in myFile.keys():
            listProcessandPrint(list(myFile.keys()), divideNum)
            targetName = input('Target name : ')
            if targetName == 'All':
                targetName = list(myFile.keys())
                break
        if txtPass == '':
            password = getpass.getpass('Password : ')
        else:
            password = txtPass
        try:
            if type(targetName) != list:
                targetName = targetName.split()
            for target in targetName:
                key = PBKDF2(password, salt, dkLen=32)
                Target = myFile[target]
                cipher = AES.new(key, AES.MODE_EAX,
                                 bytes.fromhex(Target["Nonce"]))
                data = cipher.decrypt_and_verify(
                    bytes.fromhex(Target["Password"]),
                    bytes.fromhex(Target["Tag"]))
                print(
                    target.ljust(15) + ' : ' + str(Target["Level"]) + ' : ' +
                    str(Target["Account"]).ljust(20) + ' : ' +
                    str(data.decode()))
            continue_ = input('continue (Y/N) : ')
            clearConsole()
        except:
            print("Bad AES password.")
            return 1
        if continue_ != 'Y':
            return 2


def extractFile(inputFile, zipPass, txtPass, mode=0):
    try:
        zf = pyzipper.AESZipFile(inputFile)
    except:
        print("File does not exist.")
        return 4
    if zipPass == '':
        zipPassword = bytes(getpass.getpass('zip password : '), 'utf-8')
        zipPass = zipPassword
    else:
        zipPassword = zipPass
    try:
        zf.setpassword(zipPassword)
    except:
        print("Bad zip password.")
        return 1
    if 'salt.txt' not in zf.namelist() or 'pass.txt' not in zf.namelist():
        print("Bad zip file hierarchy.")
        return 3
    try:
        if mode != 0:
            salt = bytes.fromhex(zf.read('salt.txt').decode())
            password = input('Password : ')
            key = PBKDF2(password, salt, dkLen=32)
            while True:
                clearConsole()
                print("Password     : " + str(password))
                data = bytes(input('Data         : '), 'utf-8')
                cipher = AES.new(key, AES.MODE_EAX)
                cipheredData, tag = cipher.encrypt_and_digest(data)
                print("cipheredData : " + str(cipheredData.hex()))
                print("Nonce        : " + str(cipher.nonce.hex()))
                print("Tag          : " + str(tag.hex()))
                cipher_ = AES.new(key, AES.MODE_EAX, cipher.nonce)
                data = cipher_.decrypt_and_verify(cipheredData, tag)
                print("Data         : " + str(data.decode()) + '\n')
                continue_ = input('continue (Y/N) : ')
                if continue_ != 'Y':
                    break
        else:
            myFile = json.loads(zf.read('pass.txt').decode())
            salt = bytes.fromhex(zf.read('salt.txt').decode())
            while True:
                good = aesProcess(myFile, salt, 8, txtPass)
                if good == 0:
                    break
                elif good == 1:
                    txtPass = ''
                elif good == 2:
                    return 2
                else:
                    break
    except:
        print("Bad trying to open zip file by force.")
        return 1
    clearConsole()
    return 0


def main(argv):
    check = 0
    inputFile, zipPass, txtPass = '', '', ''
    outputStr = 'zipExtract.py -i <fileName.zip> [-z <zipPassword>][-e] [-t <txtPassword>]'
    try:
        opts, args = getopt.getopt(argv, "hi:ez:t:",
                                   ["iFile=", "zPass=", "tPass="])
    except getopt.GetoptError:
        print(outputStr)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(outputStr)
            sys.exit(1)
        elif opt in ("-i", "--iFile"):
            if '.zip' not in arg:
                print("Input file need to be a zip file.")
                sys.exit(1)
            else:
                inputFile = arg
                check += 1
        elif opt in ("-z", "--zPass"):
            zipPass = arg
        elif opt in ("-t", "--tPass"):
            txtPass = arg
        elif opt in ("-e"):
            check += 1
    if check >= 1:
        while True:
            good = extractFile(inputFile, zipPass, txtPass, check - 1)
            if good == 0:
                sys.exit(0)
            elif good == 1:
                zipPass = ''
            elif good == 2:
                sys.exit(0)
            else:
                sys.exit(1)
    else:
        print("Argv wrong.")
        print(outputStr)


if __name__ == "__main__":
    main(sys.argv[1:])