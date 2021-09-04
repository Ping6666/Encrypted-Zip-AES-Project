import os, sys, getopt
from zipExtract import extractFile


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
            if good == 1:
                zipPass = ''
            else:
                sys.exit(0)
    else:
        print("Argv wrong.")
        print(outputStr)


if __name__ == "__main__":
    main(sys.argv[1:])