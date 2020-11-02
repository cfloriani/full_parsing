#!/usr/bin/python3
import re, sys, validators, socket, whois
from bs4 import BeautifulSoup
from urllib.request import urlopen
from base import topPorts, urls_conhecidas
from ftplib import FTP

# pega o banner do serviço da porta aberta
def banner(sckt, ip, porta):
	try:
		sckt.settimeout(1)
		sckt.connect((ip, porta))
		banner = sckt.recv(1024)
		return banner
	except:
		return ''

# faz o scan das portas no ip do dominio encontrado
def portScan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
    except:
        pass
    if s.connect_ex((ip, int(port))) == 0:
        print("Porta [ABERTA] -> {}/tcp".format(port), ' ' ,banner(s, ip, port))

        # verifica se existe web server
        if port != 80 or port != 443:
            try:
                try: web = urlopen('http://'+ip+':'+str(port))
                except: web = urlopen('https://'+ip+':'+str(port))
                if web.code == 200: srv_web_port_desconhecida.append(ip+':'+str(port))
            except:
                pass
        
        # tenta acessar o ftp como anonimo
        if port == 21: 
            try: 
                FTP(ip)
                FTP.login()
                ftp_anonimo.append(ip)
            except:
                pass

# faz uma limpeza no dominio pra funcionar com o BS4
def domainClear(url):
    try:
        url = url.replace("https://","").replace("http://","")
        clean = re.compile(re.escape('/')+'.*')
        return clean.sub('', url)
    except:
        pass

# abre a url, faz a leitura e captura o que está em href
def webScrap(domain):
    if 'http://' not in domain: domain = 'http://'+domain
    print('#####################################################################')
    print('### Analisando o site -> ', domain)
    print('')
    try: html = urlopen(domain)
    except: print('Erro ao carregar o site')
    soup = BeautifulSoup(html, "lxml")
    urls_encontradas = []

    # abre a página e pega as urls
    for url in soup.findAll('a'):
        url = domainClear(url.get('href'))
        if validators.domain(url) and url not in urls_conhecidas:
            if url not in urls_encontradas:
                urls_encontradas.append(url)

    # varre as páginas encontradas
    for url in urls_encontradas:
        try: ip = socket.gethostbyname(url)
        except: ip = 'IP não Localizado'
        ips.append(ip)
        print('IP/Dominio -> [', ip ,']', url)
        print('### Whois')
        print(whois.whois(url))
        if not config.portscan:
            if input('Analisar TopPorts desse Host? [s/n]') in 's':
                print('### Ports')
                for port in topPorts: 
                    portScan(ip,port)
        else: 
            print('### Ports')
            for port in topPorts: 
                portScan(ip,port)
        print('')
    return urls_encontradas

# processa a analise nos hosts localizados no dominio
def repWebScrap(urls_encontradas):
    ips = []
    novas_urls = urls_encontradas
    for url in novas_urls:
        webScrap(url)
    return urls_encontradas

############################# início ##############################

# classe para configurar script
class config():
    portscan = False
    alldomain = False

domain = sys.argv[1]
ips = []
urls_encontradas = [domain.replace("https://","").replace("http://","")]
srv_web_port_desconhecida = []
ftp_anonimo = []

# configura o script
print('-> Configuração <-')
print('Por padrão, não será realizado em todos os hosts')
print('-> TopPortsScan')
print('-> WebScraping')
if input('Alterar as configurações padrões? [s/n]') in 's':
    if input('WebScraping em todos os hosts? [s/n]') in 's': config.alldomain = True
    if input('TopPortsScan em todos os hosts? [s/n]') in 's': config.portscan = True

# puxa o procedimento para webscraping
urls_encontradas = webScrap(domain)

# refaz o teste nas urls localizadas
if not config.alldomain:
    if input('Analisar todas os dominios encontrados? [s/n]') in 's':
        repWebScrap(urls_encontradas)
else:
    repWebScrap(urls_encontradas)

# exibe webservers em portas desconhecidas
print('#####################################################################')
print('Servidores Web em portas fora do padrão')
for web_srv in srv_web_port_desconhecida:
    print(web_srv)

# exibe ftps que aceita login anonimo
print('#####################################################################')
print('Servidores FTP com acesso Anônimo')
for ftp in ftp_anonimo:
    print(ftp)
