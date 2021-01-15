def readInt(msg):
    while True:
        try:
            n = int(input(msg))
        except (ValueError, TypeError):
            print('[-]Erro: Digite uma opção valida.\033')
            continue
        except (KeyboardInterrupt):
            print('\n[-]Bye World!!')
            return 0
        else:
            return n


def linha(tam = 42):
    return '-' * tam

def header(txt):
    print(linha())
    print(txt)
    print(linha())

def menu():
    print('''
    
[1]Web Crawl
[2]Whois
[3]Port Scan
[0]Sair
    ''')
    opc = readInt('Escolha uma opção: ')
    return opc


