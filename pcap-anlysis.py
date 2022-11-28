import argparse
import os
import sys
from scapy.all import *
from scapy.utils import RawPcapReader
import requests
import json
import numpy as np
from datetime import datetime
import numpy as np
import seaborn as sns
from matplotlib import pyplot as plt, dates as mdates, figure as figure
import pandas as pd
import heapq
import time
tempo_inicial = time.time()

def process_dst(ip_packet, ips_dst, ip_mais_acessado, dispositivos):
    ip_dst = ip_packet.dst
    if ip_dst not in ips_dst and ip_dst not in dispositivos:             
        ips_dst.update({ip_dst : {'count' : 1, 'data': np.array([ip_packet.src])}})
        if ip_mais_acessado['count'] < 1:
            ip_mais_acessado = {'ip':ip_dst, 'count': 1}
    elif ip_dst in ips_dst:
        data = ips_dst[ip_dst]['data'].copy()
        count = ips_dst[ip_dst]['count']+1   
        ips_dst.update({ip_dst : {'count' : count, 'data': np.append(data, ip_packet.src)}})
        if ip_mais_acessado['count'] < count:
            ip_mais_acessado = {'ip':ip_dst, 'count': count}
    return ips_dst, ip_mais_acessado

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    ips_origin_extern = {}
    ips_dst = {}
    dispositivos = {}
    
    horarios = []
    tamanhos = []
    tipos = []
    tipos_ip = []
    
    disp_mais_usou_rede = {'ip': None, 'count': 0}
    ip_mais_acessado = {'ip': None, 'count': 0}

    for packet in PcapReader(file_name):
        horarios.append(datetime.fromtimestamp(packet.time))
        tamanhos.append(len(packet))          
        tipos.append(packet.getlayer(1).name)
        if packet.haslayer('IP'):
            tipos_ip.append(packet.getlayer(2).name) 
            ip_packet = packet[IP]
            if ip_packet.src not in dispositivos and ip_packet.src not in ips_origin_extern:
                ip_beggin = ip_packet.src.split('.')[0]
                if ip_beggin == '10' or  ip_beggin == '172' or ip_beggin == '192' or ip_beggin == '239':
                    #print('http://ip-api.com/json/{}'.format(ip_packet.src))
                    response = None
                    while response is None:
                        try:
                            response = requests.get(f'http://ip-api.com/json/{ip_packet.src}').json()
                        except:
                            time.sleep(5)
                            continue                        
                    if response['status'] == 'fail' and response['message'] == 'private range':
                        dispositivos.update({ip_packet.src : {'count' : 1}})
                        if disp_mais_usou_rede['count'] < 1:
                            disp_mais_usou_rede = {'ip': ip_packet.src, 'count': 1}
                        ips_dst, ip_mais_acessado = process_dst(ip_packet, ips_dst,ip_mais_acessado, dispositivos)
                    elif ip_packet.src not in ips_origin_extern: 
                        ips_origin_extern.update({ip_packet.src : {'count' : 1, 'data': response}})
                    else:
                        ips_origin_extern.update({ip_packet.src : {'count' : ips_origin_extern[ip_packet.src]['count']+1}})
                elif ip_packet.src not in ips_origin_extern: 
                    ips_origin_extern.update({ip_packet.src : {'count' : 1}})
                else:
                    ips_origin_extern.update({ip_packet.src : {'count' : ips_origin_extern[ip_packet.src]['count']+1}})
            elif ip_packet.src in dispositivos:
                count = dispositivos[ip_packet.src]['count']+1
                dispositivos.update({ip_packet.src : {'count' : count}})
                ips_dst, ip_mais_acessado = process_dst(ip_packet, ips_dst,ip_mais_acessado, dispositivos)                
                if disp_mais_usou_rede['count'] < count:
                        disp_mais_usou_rede = {'ip': ip_packet.src, 'count': count}

    dez_mais = heapq.nlargest(10 + len(dispositivos), ips_dst.items(), key=lambda i: i[1]['count'])
    print("Os dez IPs de destino externos mais requisitados por dispositivos da rede são:\n")
    contador_ips_dst = 0
    for key, value in dez_mais:
        unique, counts = np.unique(value['data'], return_counts=True) 
        response = requests.get(f'http://ip-api.com/json/{key}').json()
        if response['status'] == 'success':
            contador_ips_dst +=1  
            print("\t {}: {} (nº de requisições {}, {})\n".format(key,response, value['count'],  dict(zip(unique, counts))))
        if contador_ips_dst == 10:
            break



    print("Total de {} dispositivos {})\n".format(len(dispositivos), dispositivos))
    print("Dispositivo que mais usou a rede {} )\n".format(disp_mais_usou_rede))
    ip = ip_mais_acessado['ip']
    ip_mais_acessado_data = requests.get(f'http://ip-api.com/json/{ip}').json()
    print("Ip de destino mais acessado {} com {} acessos : {})\n".format(ip, ip_mais_acessado['count'], ip_mais_acessado_data))

    
    plt.figure(1)    
    sns.kdeplot(data=tamanhos, cut=0, fill=True)
    plt.xlabel('Tamanho do pacote')
    plt.ylabel('Densidade') 
    plt.grid()
    plt.savefig("tamanhos.png")
    print('O grafico de tamanhos de pacote  esta salvo em tamanhos.png para {} pacotes\n'.format(len(horarios)))

    plt.figure(2)
    tipos = pd.DataFrame(tipos, columns=['name'])
    sns.histplot(data=tipos, x='name', stat="percent", discrete=True)
    plt.xlabel('Tipo do pacote')
    plt.ylabel('%')    
    plt.grid()
    plt.savefig("tipos_pacote.png")
    print('O grafico de tipos de pacote esta salvo em tipos_pacote.png para {} pacotes\n'.format(len(horarios)))

    plt.figure(3)
    tipos_ip = pd.DataFrame(tipos_ip, columns=['name'])
    sns.histplot(data=tipos_ip, x='name', stat="percent", discrete=True)
    plt.xlabel('Tipo de pacote IP')
    plt.ylabel('%')    
    plt.grid()
    plt.savefig("tipos_pacote_ip.png")
    print('O grafico de tipos de pacote ip esta salvo em tipos_pacote_ip.png para {} pacotes\n'.format(len(horarios)))
    
    
    plt.figure(4)   
    horarios = pd.DataFrame(horarios, columns=['datetime'])
    plt.figure(figsize=(15,7))
    horariosax = sns.histplot(data=horarios, x='datetime')
    horariosax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.xlabel('Horário de captura', fontsize=13)
    plt.ylabel('Número de pacotes', fontsize=16)
    plt.xticks(rotation=90)
    plt.gca().xaxis.set_major_locator(mdates.MinuteLocator(byminute=[0,30], interval = 1))
    plt.grid()
    
    plt.savefig("pacote_hora.png")
    print('O grafico de densidade de horarios esta salvo em pacote_hora.png para {} pacotes\n'.format(len(horarios)))

    sec = (time.time() - tempo_inicial)
    td = timedelta(seconds=sec)
    print("--- Tempo de execução: %s ---" % (td))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)