""" This module define constants that can be used to change terminal colors
"""
RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"

def printBlue(textos):
    print_string = ""
    for x in textos:
        print_string += (str(x)+" ")
    print_string = print_string[:-1]
    print(BLUE, print_string, RESET)

def printGreen(textos):
    print_string = ""
    for x in textos:
        print_string += (str(x)+" ")
    print_string = print_string[:-1]
    print(GREEN, print_string, RESET)