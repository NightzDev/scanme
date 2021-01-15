from os import replace
from sys import exit
import sys
from dns.tsig import Key
import whois
from lib.interface import *
from http_crawler import crawl
import socket

def webcrawler():
    inputcrawler = input('Digite seu alvo para iniciar o web crawler:')
    for rsp in crawl(inputcrawler):
        if rsp.status_code != 200:
            print('Obtive {} em {}'.format(rsp.status_code, rsp.url))
def whois():
    dominio = input('Qual site você deseja fazer o whois:')
    whoisdominio = whois.whois(dominio)
    print("\033[1mRelatório")
    print(linha())
    a = str(whoisdominio).replace("],","---------------------------------------------------------------------").replace("{", "").replace("}", "")
    print(a)
def portscan():
    host = input("Digite seu alvo:")
    iphost = socket.gethostbyname(host)
    try:
      for port in range(1,1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            resultport = sock.connect_ex((iphost, port))
            if resultport == 0:
                print("A porta {}: Aberta".format(port))
            sock.close()
    except KeyboardInterrupt:
        print("Você apertou Ctrl+C")
        sys.exit()
    except socket.gaierror:
        print('Hostname não pode ser escaneado')
        sys.exit()
    except socket.error:
        print("Não posso conectar ao servidor")
        sys.exit()


