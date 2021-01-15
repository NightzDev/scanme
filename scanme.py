from lib.interface import *
from scripts.script import *
from time import sleep

header('''                                          
 _______ _______ _______ _______ _______ _______ 
|\     /|\     /|\     /|\     /|\     /|\     /|
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
| |   | | |   | | |   | | |   | | |   | | |   | | alpha
| |S  | | |C  | | |A  | | |N  | | |M  | | |E  | |
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|

by:Nightz''')

while True: 
 resposta = menu()
 if resposta == 1:
    webcrawler()
    break
 elif resposta == 2:
    whois()
    break
 elif resposta == 3:
    portscan()
    break
 elif resposta == 0:
    print("\u001b[31m[-]Saindo o Scanme...\u001b[0m") 
    break
 else:
    print("\u001b[31m[-]Sua opção está incorreta!\u001b[0m")
    sleep(2)
      
