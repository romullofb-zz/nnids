# NNIDS - Sistema de Detecção de Intrusão baseado em Redes Neurais
##Por Rômullo F. Beltrame
A prototype to a Network Intrusion Detect System based on Neural Networks. Presented in 2015 to obtain a degree.
### Introdução
Este protótipo faz parte do Projeto de Conclusão de Curso para o obtenção do grau de bacharel em Ciência da Computação pela UNISUL - Universidade do Sul de Santa Catarina no ano de 2015.
<br>
Propõe a utilização de Redes Neurais no apoio à detecção de intrusão, utilizando conceitos como deep-inspection, machine learning e match.
###Pré-Requisitos do Sistema
É necessário ter instalado ou operante:
* Python na versão 2.7;
* A biblioteca PyBrain e seus dependentes;
* A biblioteca Scapy e seus dependentes.

###Inicialização
Para iniciar o sistema é necessário conferir se os seguintes arquivos estão dispostos na mesma pasta que o executável python:
* **nnids.py** - Arquivo principal (executável Python);
* **brain.xml** - Arquivo contendo os pesos da Rede Neural;
* **trainning.txt** - Arquivo contendo a base de conhecimento;
* **alerta_medio.txt** - Arquivo de output dos alertas de nível médio;
* **alerta_alto.txt** - Arquivo de output dos alertas de nível alto.

### Modo de Uso ou Usage
Para iniciar o sistema de monitoramento deve-se definir 3 argumentos: modo de operação, interface e porta. Exemplos:
##### Para monitorar a porta 80 da interface 'eth0'
* python nnids.py -m 1 -p 80 -i eth0

##### Para monitorar a porta 80, 8080 e 4444 da interface 'eth0'
* python nnids.py -m 1 -p 8080,80,4444 -i eth0

O modo de operação 1 é o principal, representando o monitoramento de intrusão.

### Treinamento da Rede Neural
Caso haja uma atualização da base de conhecimento ou modificação no código original será necessário efetuar um novo treinamento da rede neural, este treinamento pode ser feito de maneira rápida através do comando:
* python nnids.py -m 2 ou
* python nnids.py --mode 2
O modo de operação 2 treina a rede novamente.
