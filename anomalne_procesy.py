#!/usr/bin/env python
# coding: utf-8

import eland as ed
import pandas as pd
import numpy as np
import scipy
import warnings
from elasticsearch import Elasticsearch
import urllib3
from requests.auth import HTTPBasicAuth
import requests
from IPy import IP
import uuid
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.ensemble import IsolationForest


def create_index(index):
    es.indices.create(index=index, ignore=400)


def insert_one_data(_index, my_dict):
    for row in my_dict:
        res = es.index(index=_index, id=uuid.uuid4(), body=row)
        print(res)


# Ignorowanie błędów
warnings.simplefilter(action='ignore', category=pd.errors.PerformanceWarning)
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Dane do elastica
username = 'INSERT_USER_HERE'
password = 'INSERT_PASS_HERE'
elasticsearch_ip = '192.168.190.203'

# połączenie do elastica
es = Elasticsearch(f'https://{username}:{password}@{elasticsearch_ip}:9200',
                   verify_certs=False,
                   request_timeout=1500)

train_data = {
    "bool": {
        "must": [],
        "filter": [
            {
                "range": {
                    "@timestamp": {
                        "format": "strict_date_optional_time",
                        "gte": "now-14d",
                        "lte": "now"
                    }
                }
            },
            {
                "exists": {
                    "field": "process.name"
                }
            }
        ],
        "should": [],
        "must_not": [
            {
                "wildcard": {
                    "process.name": {
                        "value": "sssd[krb5*]"
                    }
                }
            },
            {
                "match_phrase": {
                    "process.name": "-"
                }
            },
            {
                "match_phrase": {
                    "process.name": "kibana"
                }
            },
            {
                "match_phrase": {
                    "process.name": "systemd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "services.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "kernel"
                }
            },
            {
                "match_phrase": {
                    "process.name": "taskhostw.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "svchost.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "sshd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "lsass.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "SetupHost.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "chrome.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "setuphost.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "winlogon.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "DismHost.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "TiWorker.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "poqexec.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "wininit.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "smss.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "csrss.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "autochk.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "Registry"
                }
            },
            {
                "match_phrase": {
                    "process.name": "wermgr.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "wsqmcons.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "aciseagentd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "vivaldi.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "firefox.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "FileCoAuth.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "wsqmcons.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "FortiESNAC.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "forticlient.desktop"
                }
            },
            {
                "match_phrase": {
                    "process.name": "Cisco AnyConnect Secure Mobility Client"
                }
            },
            {
                "match_phrase": {
                    "process.name": "MicrosoftEdgeUpdate.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "forticlient.desktop"
                }
            },
            {
                "match_phrase": {
                    "process.name": "OneDrive.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "DismHost.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "multipathd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "CRON"
                }
            },
            {
                "match_phrase": {
                    "process.name": "xinetd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "systemd-journald"
                }
            },
            {
                "match_phrase": {
                    "process.name": "NetworkManager"
                }
            },
            {
                "match_phrase": {
                    "process.name": "AdobeARM.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "AcroCEF.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "msedge.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "packetbeat.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "AdobeARM.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "systemd-udevd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "vncserver.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "VSSVC.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "audispd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "ccassist.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "VeeamGuestHelper.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "EXCEL.EXE"
                }
            },
            {
                "match_phrase": {
                    "process.name": "network"
                }
            },
            {
                "match_phrase": {
                    "process.name": "systemd-fsck"
                }
            },
            {
                "match_phrase": {
                    "process.name": "sssd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "auditd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "EIP.Core.NtlmProxyService.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "spoolsv.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "WerFault.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "explorer.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "CCAStartMulti.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "consent.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "WmiPrvSE.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "EIP.Core.WindowsService.exe"
                }
            },
            {
                "match_phrase": {
                    "process.name": "abrtd"
                }
            },
            {
                "match_phrase": {
                    "process.name": "CCAStart.exe"
                }
            }
        ]
    }
}

columns = ['@timestamp', 'agent.name', 'process.name']

# podłączenie do elastica oraz odpytanie indexu o określone kolumny
eland_connection = ed.DataFrame(
    es_client=es,
    es_index_pattern="-*elastic-cloud-logs-*,.alerts-security.alerts-default,apm-*-transaction*,auditbeat-*,endgame-*,filebeat-*,logs-*,packetbeat-*,traces-apm*,winlogbeat-*",
    columns=columns)

# dane train (baseline)
el_train = eland_connection.es_query(train_data)
pd_df = ed.eland_to_pandas(el_train)
pd_df = pd_df.reset_index(drop=True)

# MACHINE LEARNING  PART

# Przygotowanie danych
X = pd_df.copy()

# Metoda kodowania
encoder = OrdinalEncoder()

# Model
model = IsolationForest(contamination=0.05)

# Tworzenie pustego dataframe do przechowywania wyników
results_df = pd.DataFrame(columns=['@timestamp', 'agent.name', 'process.name', 'ml.rule_name'])

# Pętla przez unikalne nazwy agentów
for agent_name in X['agent.name'].unique():
    # Wybieranie obserwacji tylko dla danego agenta
    X_agent = X[X['agent.name'] == agent_name].copy()
    # print(X_agent)
    # Kodowanie danych
    X_encoded = encoder.fit_transform(X_agent[['process.name']])

    # Standaryzacja danych
    sc = StandardScaler()
    X_encoded = sc.fit_transform(X_encoded)

    # Trenowanie modelu
    model.fit(X_encoded)

    # Przewidywanie anomalii
    preds = model.predict(X_encoded)

    # Zapisanie anomalii
    anomalies = X_agent[preds == -1]

    # Dodawanie kolumny z nazwą reguły ML
    anomalies['ml.rule_name'] = 'NETXP Possible Anomalous Process Found'

    # Dodawanie anomalii do wyników
    results_df = pd.concat([results_df, anomalies], ignore_index=True)

my_dict = results_df.to_dict('records')
index = "ml-2"
insert_one_data(index, my_dict)
