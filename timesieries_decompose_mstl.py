from elasticsearch import Elasticsearch
import pandas as pd
import seaborn as sns
import numpy as np
import logging
import matplotlib.pyplot as plt
from statsmodels.tsa.seasonal import MSTL
from scipy.stats import zscore

# ładne wykresy
sns.set_style("darkgrid")
sns.set_context("poster")

logging.basicConfig(level=logging.INFO)

username = 'REDACTED'
password = 'REDACTED'
elasticsearch_ip = '10.7.1.89'

es = Elasticsearch(hosts="https://10.7.1.89:9200", basic_auth=(username, password), verify_certs=False,
                   request_timeout=1500)


def create_index(index_name):
    pass
    #TODO


def fetch_data(index_pattern):
    # Elasticsearch query
    try:
        query = {
            "aggs": {
                "0": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "60m", # wskazujemy jaka wielkość "wiadra" danych
                        "time_zone": "Europe/Warsaw",

                    },
                    "aggs": {
                        "1": {
                            "value_count": { # docelowa metryka - inne dostępne to np "sum" itp (do sprawdzenia w elk)
                                "field": "source.bytes" # docelowy parametr do analizzy
                            }
                        }
                    }
                }
            },
            "size": 0,
            "fields": [
                {
                    "field": "@timestamp",
                    "format": "strict_date_optional_time" # format czasu, keidyś ew. do zmiany
                },

            ],
            "script_fields": {},
            "stored_fields": [
                "*"
            ],
            "runtime_mappings": {},
            "_source": {
                "excludes": []
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "match_phrase": {
                                "agent.type": "endpoint" # dane z integracji edr
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "format": "strict_date_optional_time",
                                    "gte": "now-30d", # wskazujemy jaki zakres czasu
                                    "lte": "now"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }
    except Exception as e:
        logging.error(f"Error fetching data: {e}")
        return pd.DataFrame()
    response = es.search(index=index_pattern, body=query)
    # print("Query Response:", response)
    logging.info("Query Response: %s", response)
    # Extract country names and counts from the response
    data = [
        {
            "timestamp": bucket['key_as_string'],
            "value": bucket['1']['value']
        }
        for bucket in response['aggregations']['0']['buckets']
    ]

    # df = pd.DataFrame(data)
    # print(df) # debugging

    return pd.DataFrame(data)


def plot_timeseries_with_outliers(res, threshold=2.5):
    plt.rc("figure", figsize=(16, 20))
    plt.rc("font", size=8)

    # Rysowanie komponentów dekompozycji
    fig, axes = plt.subplots(nrows=4, ncols=1, sharex=True)

    res.observed.plot(ax=axes[0], legend=False)
    axes[0].set(title='Obserwowane')

    res.trend.plot(ax=axes[1], legend=False)
    axes[1].set(title='Trend')

    res.seasonal.plot(ax=axes[2], legend=False)
    axes[2].set(title='Sezonowość')

    res.resid.plot(ax=axes[3], legend=False)
    axes[3].set(title='Reszta')

    # Obliczanie z-scores dla reszt - treshold to liczba odchyleń standardowych
    resid_z_scores = zscore(res.resid.dropna())
    outliers = np.abs(resid_z_scores) > threshold

    # Rysowanie punktów odstających na wykresie reszt
    axes[3].scatter(res.resid.dropna().index[outliers], res.resid.dropna()[outliers], color='r', label='Punkty odstające')
    axes[3].legend(loc='upper left', bbox_to_anchor=(1, 1))

    plt.tight_layout()
    plt.show()


# Wywołanie funkcji z ramką danych i nazwami kolumn

def timeseries_model(data):
    # dekompozycja szeregu czasowego
    stl_kwargs = {"seasonal_deg": 0}
    model = MSTL(data["value"], periods=(24, 24 * 7), stl_kwargs=stl_kwargs) #, lmbda="auto" parametr lambda w przypadku koneiczności korekty box-cox
    res = model.fit()

    seasonal = res.seasonal  # contains both seasonal components
    trend = res.trend # debugging
    residual = res.resid # debugging

    return res


def main():
    index_pattern = "logs-*"

    data = fetch_data(index_pattern)
    data = data.iloc[1:-1] # usunięcie pustych wierszy z początku i końca
    res = timeseries_model(data) # dane po dekompozycji
    plot_timeseries_with_outliers(res)


if __name__ == "__main__":
    main()
