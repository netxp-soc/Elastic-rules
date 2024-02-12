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
import category_encoders as ce
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.svm import OneClassSVM
import uuid


# Wysłanie danych do indexu

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

test_data = {
    "bool": {
      "must": [],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": "now-1d",
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
            "process.name": "firefox.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "msedge.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "consent.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "setupcl.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "VSSVC.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "WerFault.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "vncserver.exe"
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


train_data = {
    "bool": {
      "must": [],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": "now-15d",
              "lte": "now-1d"
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
            "process.name": "firefox.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "msedge.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "consent.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "setupcl.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "VSSVC.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "WerFault.exe"
          }
        },
        {
          "match_phrase": {
            "process.name": "vncserver.exe"
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


columns = ['@timestamp','agent.name', 'process.name']

# podłączenie do elastica oraz odpytanie indexu o określone kolumny
eland_connection = ed.DataFrame(
    es_client = es,
    es_index_pattern = "-*elastic-cloud-logs-*,.alerts-security.alerts-default,apm-*-transaction*,auditbeat-*,endgame-*,filebeat-*,logs-*,packetbeat-*,traces-apm*,winlogbeat-*",
    columns=columns	)

# dane train (baseline)
el_train = eland_connection.es_query(train_data)

pd_df = ed.eland_to_pandas(el_train)

# dane testowe
el_test = eland_connection.es_query(test_data)

pd_test = ed.eland_to_pandas(el_test)

# Stworzenie pustego dataframe, które będzie przechowywało nowe procesy
new_process_df = pd.DataFrame(columns=['@timestamp', 'agent.name', 'process.name', 'ml.rule_name'])

# Wyszukanie unikalnych hostów
unique_agents = pd_df['agent.name'].unique()

for agent in unique_agents:
    # Wyszukanie procesów dla danego hosta w danych treningowych i testowych
    train_processes = set(pd_df[pd_df['agent.name'] == agent]['process.name'])
    new_processes = set(pd_test[pd_test['agent.name'] == agent]['process.name'])

    # Znalezienie procesów, które są w nowych danych, ale nie były w danych treningowych
    new_unique_processes = new_processes - train_processes

    if new_unique_processes:
        #print(f'Pojawiły się nowe procesy na hoście {agent}:', new_unique_processes)
        # Dodanie nowych procesów do dataframe
        for process in new_unique_processes:
            # Znalezienie timestamp dla danego procesu
            timestamp_series = pd_test[(pd_test['agent.name'] == agent) & (pd_test['process.name'] == process)]['@timestamp']
            if not timestamp_series.empty:
                timestamp = timestamp_series.loc[timestamp_series.first_valid_index()]
                # Dodanie informacji do dataframe
                new_row = pd.DataFrame({'@timestamp': [timestamp], 'agent.name': [agent], 'process.name': [process], 'ml.rule_name': ['NETXP New Process Found']})
                new_process_df = pd.concat([new_process_df, new_row], ignore_index=True)
    else:
    	pass
        #print(f'Nie pojawiły się żadne nowe procesy na hoście {agent}.')

my_dict = new_process_df.to_dict('records')

    
index = "ml-1"
create_index(index)
my_dict = new_process_df.to_dict('records')
insert_one_data(index, my_dict)

