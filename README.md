# Coding For Security - Checkpoint 6, Python sniffer & API for capturing raw frames.
O código representa um conjunto de duas aplicações, uma API feita com o uso da biblioteca `Flask` e uma aplicação construída a base de sockets para a interceptação de pacotes sendo enviados ou recebidos entre a máquina que está rodando a aplicação e a origem ou destino dos pacotes recebidos/enviados. Os PDUs estão sendo capturados desde o nível dois do modelo OSI, o "Data-link layer", e suas informações estão sendo armazenadas num banco de dados do tipo NoSQL, o `MongoDb`. Pelo fato dos pacotes estarem sendo recuperados de forma "pura" -- percebe-se tal fato ao se instanciar um socket do tipo `SOCK_RAW` --, isto é, sem o processamento de demais camadas, todas as suas informações são retornadas para a aplicação em forma de um array de bytes, e por isso todos os campos devem ser obtidos por meio de operações que envolvem cálculos de posição de cada campo; este fora o mecanismo usado na aplicação, um tanto quanto mais manual e talvez mais complexo, entretanto, métodos como `unpack` e `pack` da biblioteca `struct` podem ser usados.

## Detalhes e dependências
Existem inúmeros detalhes, pontos e dependências a se considerar antes de começar a execução do código em si, como o sistema operacional alvo, a conexão com o banco de dados e mesmo as bibliotecas dependentes.
### Sistema Operacional
O código fora construído voltado à sistemas UNIX, principalmente pelo fato do socket criado ser da família `AF_PACKET`, como a seguinte declaração indica:
```python
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
```

### Dependências
Todas as dependências estão listadas a seguir, assim como no arquivo `requirements.txt`, onde suas versões também podem ser encontradas:
 - `pymongo`,
 - `Flask`,
 - `requests`

#### Instalação automática de dependências
O arquivo `requirements.txt` é um arquivo, como dito previamente, que armazena todas as dependências necessárias para que o código seja executado. Entretanto, instalar cada dependência pode não ser tão trivial, e por isso pode-se usar um utilitário para a instalação automática de todas as dependências: o gerenciador de pacotes `pip`. Entretanto, diferentes formas de instalação do `pip` existem para diferentes sistemas operacionais, então você deve procurar um guia de instalação para o seu SO. Por exemplo, no Ubuntu, para se instalar o `pip`, pode-se fazer:
```shell
sudo apt install python3-pip
```

Após a instalação do gerenciador de pacotes, todas as dependências podem ser recuperadas por meio do seguinte comando:
```shell
# Já estando no mesmo diretório que o arquivo requirements.txt, faça:
pip install -r requirements.txt
```

### Conexão com o banco de dados
Ao começo do projeto, o banco de dados já deve estar sendo iniciado, o que significa que o serviço `mongod` precisa estar sendo executado. De qualquer maneira, não basta o banco estar ativo; deve-se, se assim necessário, arrumar a *string* de conexão com o banco de dados, que pode ser encontrada na linha 15 do arquivo `api.py`, como mostra a declaração a seguir. Por favor, consulte as informações necessárias a se passar na *string* de conexão nos sites oficiais do **MongoDb**, pois diferentes maneiras de instalação mudam a forma de se alterar a conexão com o banco. 
```
# Substitua ""mongodb://localhost:27017" por sua string de conexão.
client = pymongo.MongoClient("mongodb://localhost:27017")
```

### Sistema de geração de logs de exceções
A aplicação também possui um sistema de geração de logs caso algum problema ocorra, como uma `exception`. Logs são gerados com base na data, e são gerados no seguinte formato: `%d%m%Y_%H%M%S.log`.

## Passo a passo de execução
Após a garantia de que o serviço do banco de dados está rodando, e que a conexão pode ser efetuada a partir da *string* de conexão usada, pode-se executar o projeto com os seguintes comandos (múltiplos terminais podem ser necessários):
```shell
# Clonando repositório (esta etapa deve ser feita apenas uma vez, já que o repositório clonado é baixado e fica no sistema de arquivos).
git clone https://github.com/arakakivl/PythonSniffer

# A partir daqui é possível que múltiplos terminais sejam necessários, já que cada um rodará uma das aplicações.
# Entrando no diretório do repositório
cd PythonSniffer

# Executando a API
cd api
flask run

# Executando o sniffer
cd sniffer
sudo python3 snifffer.py
```

## Endpoins da API
A API possui exatos dois endpoints, um para a criação e outro para a listagem de todos os PDUs. São eles:
 - POST /pdus: registra um novo dado no banco de dados.
 - GET /pdus: lista todos os dados armazenados no banco de dados.

## Integrantes
 - Guilherme Valloto, RM550353,
 - Victória Ventrilho, RM94872,
 - Vitor Arakaki, RM98824

## Referências
 - Sobre sockets no geral: https://docs.python.org/3/library/socket.html
 - Sobre SOCK_RAW: https://stackoverflow.com/questions/30780082/sock-raw-option-in-socket-system-call, https://medium.com/nerd-for-tech/raw-sockets-with-python-sniffing-and-network-packet-injections-486043061bd5
 - Sobre ethernet frames (PDU do layer 2 do OSI): https://en.wikipedia.org/wiki/EtherType
 - Sobre IPv4: https://en.wikipedia.org/wiki/Internet_Protocol_version_4
 - Sobre converter objetos p json: https://pynative.com/make-python-class-json-serializable/
 - Sobre ICMP, TCP e UDP: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol, https://en.wikipedia.org/wiki/Transmission_Control_Protocol, https://en.wikipedia.org/wiki/User_Datagram_Protocol
 - Sobre Flask: https://flask.palletsprojects.com/en/3.0.x/quickstart/
 - Sobre MongoDb: https://www.mongodb.com/languages/python, https://www.w3schools.com/python/python_mongodb_insert.asp
