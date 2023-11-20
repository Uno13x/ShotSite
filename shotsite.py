import requests
import re
import ssl
import time
import os
import socket
from colorama import Fore, Style
import subprocess

os.system('clear')

def verificar_dns(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        ip_address = puxar_ip(url)
        if ip_address:
            return f"DNS Resolvido: {domain} => {ip_address}"
        else:
            return "Erro ao resolver DNS."
    except Exception:
        return "Erro ao verificar DNS."
def verificar_firewall(url):
    try:
        response = requests.head(url)
        firewall_info = response.headers.get("X-Firewall", "Não disponível")
        if firewall_info.lower() == "closed":
            return "Firewall fechado"
        elif firewall_info.lower() == "open":
            return "Firewall aberto"
        else:
            return firewall_info
    except requests.RequestException as e:
        return f"Erro ao verificar o firewall: {str(e)}"

def obter_versao_servidor(url):
    try:
        response = requests.get(url)
        server_version = response.headers.get("Server", "Não disponível")
        return server_version
    except requests.RequestException as e:
        return f"Erro ao obter a versão do servidor: {str(e)}"

def puxar_ip(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "IP não encontrado."

def verificar_disponibilidade(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
        return False
    except requests.RequestException:
        return False

def verificar_robots_txt(url):
    robots_url = f"{url}/robots.txt"
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            return response.text
        return "Arquivo robots.txt não encontrado."
    except requests.RequestException:
        return "Erro ao acessar robots.txt."

def verificar_tempo_de_carregamento(url):
    try:
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        load_time = end_time - start_time
        return load_time
    except requests.RequestException:
        return "Erro ao medir o tempo de carregamento."

def verificar_ssl_tls(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        s.connect((hostname, 443))
        cert = s.getpeercert()
        return cert
    except Exception:
        return "Erro ao verificar SSL/TLS."

def verificar_servicos_adicionais(url, portas):
    try:
        host = url.split("//")[-1].split("/")[0]
        servicos_disponiveis = []
        for porta in portas:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            resultado = sock.connect_ex((host, porta))
            sock.close()
            if resultado == 0:
                servicos_disponiveis.append(porta)
        return servicos_disponiveis
    except Exception:
        return "Erro ao verificar serviços adicionais."

def exibir_dados_do_site_e_portas_abertas(url):
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    portas_comuns = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

    print("\nDADOS DO SITE:", url)
    if verificar_disponibilidade(url):
        print("O site está online.")
    else:
        print("O site não está disponível.")

    ip = puxar_ip(url)
    if ip:
        print(f"IP: {ip}")
    else:
        print("IP não encontrado.")

    robots_txt = verificar_robots_txt(url)
    print(robots_txt)

    load_time = verificar_tempo_de_carregamento(url)
    if isinstance(load_time, float):
        print(f"Tempo de carregamento: {load_time:.2f} segundos")
    else:
        print(load_time)

    ssl_info = verificar_ssl_tls(url)
    if isinstance(ssl_info, dict):
        print("Certificado SSL/TLS válido.")
    else:
        print(ssl_info)

    servicos_disponiveis = verificar_servicos_adicionais(url, portas_comuns)
    if isinstance(servicos_disponiveis, list) and len(servicos_disponiveis) > 0:
        print("Serviços adicionais disponíveis nas portas:", servicos_disponiveis)
    else:
        print("Nenhum serviço adicional disponível nas portas comuns.")

    urls_verificar = ["/admin", "/login", "/register", "/wp-admin", "/contact",
        "/about", "/terms", "/privacy", "/services", "/blog",
        "/faq", "/shop", "/products", "/portfolio", "/pricing",
        "/news", "/events", "/gallery", "/testimonials", "/clients",
        "/team", "/careers", "/download", "/feedback", "/sitemap",
        "/error", "/subscribe", "/unauthorized", "/dashboard", "/members",
        "/logout", "/account" "/contact.php" "/fotos.php" "/videos", "/podcasts", "/partnerships", "/guest-posts", "/customer-stories",
     "/daily-deals", "/recent-projects", "/local-events", "/success-stories", "/social-media",
    "/user-forum", "/job-openings", "/official-blog", "/photo-gallery", "/our-team",
    "/product-reviews", "/client-reviews", "/support-center", "/terms-of-service", "/privacy-policy",
    "/cookie-policy", "/community-forum", "/how-it-works", "/meet-the-team", "/behind-the-scenes",
    "/awards-and-recognition", "/our-values", "/why-choose-us", "/charity-work", "/news-and-updates",
    "/help-center", "/recent-news"
    ]
    dns_info = verificar_dns(url)
    print(dns_info)
    firewall_status = verificar_firewall(url)
    print(f"Informações do firewall: {firewall_status}")
    server_version = obter_versao_servidor(url)
    print(f"Versão do servidor web: {server_version}")
    for url_verificar in urls_verificar:
        url_completa = f"{url}{url_verificar}"
        if verificar_disponibilidade(url_completa):
            print(f"URL {url_verificar} encontrada no site.")
        else:
            print(f"URL {url_verificar} não encontrada no site.")

if __name__ == "__main__":
 texto_verde = """
/$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$$ /$$$$$$  /$$$$$$ /$$$$$$$$ /$$$$$$$$
/$$__  $$| $$  | $$ /$$__  $$|__  $$__/$$__  $$|_  $$_/|__  $$__/| $$_____/
| $$  \ $$| $$  | $$| $$  \ $$   | $$  | $$  \__/  | $$     | $$   | $$      
|  $$$$$$/| $$$$$$$$| $$  | $$   | $$  |  $$$$$$   | $$     | $$   | $$$$$   
\____  $$| $$__  $$| $$  | $$   | $$   \____  $$  | $$     | $$   | $$__/   
/$$  \ $$| $$  | $$| $$  | $$   | $$   /$$  \ $$  | $$     | $$   | $$      
|  $$$$$$/| $$  | $$|  $$$$$$/   | $$  |  $$$$$$/ /$$$$$$   | $$   | $$$$$$$$
\______/ |__/  |__/ \______/    |__/   \______/ |______/   |__/   |________/
"""
texto_formatado = f"{Fore.GREEN}{texto_verde}{Style.RESET_ALL}"
print(texto_formatado)
print("\033[32mCreate by Uno version 1.1")
print("\033[32mEscreva sem http ou https ex: www.escrevaassim.com")
print("\033[32m__________________________________________________")
url = input("\033[32mInsira o site que deseja escanear: ")
exibir_dados_do_site_e_portas_abertas(url)
print("\033[32m__________________________________________________")
print("\033[34mUno fica agradecido por ter usado este código!")

