#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  NNIDS - Neural Network Intrusion Detection System
#     Protótipo elaborado para a obtenção do título de bacharel pela UNISUL
#     Copyright (C) 2015  - Rômullo Furtado Beltrame

#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.

#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.

#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.

from scapy.all import *
import pybrain
from pybrain.tools.customxml.networkwriter import NetworkWriter
from pybrain.tools.customxml.networkreader import NetworkReader
from pybrain.tools.shortcuts import buildNetwork
from pybrain.structure import TanhLayer
from pybrain.datasets import SupervisedDataSet
from pybrain.supervised.trainers import BackpropTrainer
from pybrain.tests.helpers import gradientCheck
from optparse import OptionParser
from datetime import datetime
import binascii
global count
count = 0

def Cria_Rede():
    global net
    net = buildNetwork(50,25,1,bias=True,hiddenclass=TanhLayer)
    net = NetworkReader.readFrom('brain.xml')

def Treinar():
    print 'Inicializando o treinamento da Rede......Aguarde'
    ds = SupervisedDataSet(50,1)
    with open('trainning.txt') as f:
        for line in f:
            if line[0] != '#':
                line = line.replace('\n','')
                line = line.split(',')
                exemplo = []
                for x in line: exemplo.append(x)
                ds.addSample(exemplo[1:],exemplo[:1]) # o 1: pega o primeiro valor que e targer.
    ## Dataset
    #trainer = BackpropTrainer(net, learningrate = 0.04, momentum = 0.07, verbose = False)
    trainer = BackpropTrainer(net, learningrate = 0.04, momentum = 0.07, verbose = False)
    trainer.trainOnDataset(ds,10000) 
    NetworkWriter.writeToFile(net, 'filename.xml')
    print 'Treinado e Pronto'

def isHTTPS(dport,sport):
    if dport == 443 or sport == 443:
        return True
    else:
        return False

def pkt_callback(pkt):
    if pkt.haslayer(Raw) and isHTTPS(pkt[TCP].dport,pkt[TCP].sport) == False:
        load = repr(pkt[Raw].load) #[1:-1]
        load = binascii.hexlify(load)
        preprocessor(pkt,load.replace("5c",""))

def preprocessor(pkt,load):
    # --> protocolo[1],fragmentacao[1],dest_port[16],tamanho[16],estanalista?[16] <-- Tamanho total 50
    global count
    count += 1
    print count
    impulso = [0] * 2
    if pkt[IP].proto is 'udp': impulso[0] = 1
    if pkt[IP].flags is 'MF': impulso[1] = 1 # se e fragmentado
    dport = list('%0*d' % (16, int(bin(pkt[IP].dport)[2:]))) #Convert a porta para binario
    [impulso.append(int(x)) for x in dport] #adiciona o binario da porta no fim da lista
    tamanho = list('%0*d' % (16, int(bin(pkt[IP].len)[2:])))
    [impulso.append(int(x)) for x in tamanho]
    dic = ('2f62696e2f62617368', #/bin/bash
    '2731202731273d27310d0a', # '1 '1'='1 exemplo básico de injection
    '7831305a6668', #x10Zfh from apache exploit
    '7368682f62696e', #shh/bin
    '61646d696e', #admin
    '726f655f74', # root
    '2f6367692d737973', # /cgi-sys
    '6e63202d6c', # nc -l
    '2f6574632f706173737764', # /etc/passwd
    '6d65746572707265746572', # meterpreter
    '7368656c6c5f65786563', # shell_exe - função do php
    '6d656d6265724163636573735b22616c6c6f775374617469634d6574686f64416363',#memberAccess["allowStaticMethodAcc do struts_code_exec_exception_delegator
    '2f6574632f736861646f770d0a', # /etc/shadow
    '57838327863397865667838316e337862346f6e78636578666178643478', # parte do payload linux/x86/meterpreter/reverse_tcp
    '736f66742057696e646f7773205b56', # parte do payload windows/shell_reverse_tcp
    '2f6d616e616765722f736572766572696e666f20485454', #/manager/serverinfo HT do exploit exploit/multi/http/tomcat_mgr_deploy 
    )
    for w in dic:
        if w in load:
            impulso.append(1)
        else:
            impulso.append(0)
    print impulso, len(impulso)
    Classificar(impulso,pkt)

def Classificar(pacote_final,pkt):
    taxa = net.activate(pacote_final)
    print taxa
    if 0.6 < taxa < 1.4:
        now = datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
        texto = "----------------------------------------------------------------------------\n"\
        "Alerta de Nível Alto - Taxa de Proximidade: %f - Data: %s"\
        "\nIP de Origem: %s\nIP de Destino: %s Porta: %d\n" \
        "----------------------------------------------------------------------------\n" %(float(taxa),now,pkt[IP].src,pkt[IP].dst,pkt[IP].dport )
        Output('alerta_alto.txt',texto)
    elif 0.3 < taxa < 0.6:
        now = datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
        texto = "----------------------------------------------------------------------------\n"\
        "Alerta de Nível Médio - Taxa de Proximidade: %f - Data: %s"\
        "\nIP de Origem: %s\nIP de Destino: %s Porta: %d\n" \
        "----------------------------------------------------------------------------\n" %(float(taxa),now,pkt[IP].src,pkt[IP].dst,pkt[IP].dport )
        Output('alerta_medio.txt',texto)

def Output(file,texto):
    with open(file,'a') as f:
        f.write(texto)

## Initializing
argv = OptionParser()
argv.add_option("-i", "--interface", action = "store", dest = "interface", type ="string",
                    help = "Define a interface que o sistema monitorara")
argv.add_option("-m", "--mode", action = "store", dest = "mode", type ="int", 
                    help = "Define o mode de operacao do Sistema. 1 - Para iniciar o monitor. 2 - Para somente treinar a rede. ")
argv.add_option("-p", "--ports", action = "store", dest = "ports", type ="string", 
                    help = "Define a(s) porta(s) que o sistema ira monitorar. Ex: -p 80,21,22")
(argumentos, palha_que_nao_interessa) = argv.parse_args()
Cria_Rede()
if argumentos.mode == 2:
    Treinar()
elif argumentos.mode == 1: 
    if not argumentos.interface:   # if filename is not given
        parser.error('-i ou --interface nao foi definida.')
    if argumentos.ports:   # if filename is not given
        ports = str(argumentos.ports)
        portas = ports.split(',')
        text = '(port ' + portas[0]
        for port in portas[1:]:
            text += ' or port ' + port
        text += ')'
    else:
        parser.error('-p ou --ports nao foi definida.')
    sniff(iface=argumentos.interface,filter='tcp port 80',store=0,prn=pkt_callback)
    print count
else:
    print "-m ou --mode Invalido. Escolha 1 para iniciar o monitoramento ou 2 para treinar a rede."