import requests
from datetime import datetime

KEY = "daffef3f30073b169e9917bf25460985fb5e10028964603e97f39105c30e88e1"
URL = "https://www.virustotal.com/api/v3/files/"
LINE_SIZE = 63


def __convert_headers(headers):
    header_row = ""
    for header in headers:
        header_row += "|_{0}_".format(header["column"]).ljust(LINE_SIZE)
    header_row += "|\n"
    for _ in headers:
        header_row += "|:".ljust(LINE_SIZE, '-')
    header_row += "|\n"
    return header_row


def convert_to_markdown(headers, rows):
    table = __convert_headers(headers)
    for row in rows:
        for header in headers:
            table += "|{0}".format(row[header["field"]]).ljust(LINE_SIZE)
        table += "|\n"
    return table


def create_file_information_table(row_data):
    try:
        headers = [{"field": "md5", "column": "MD5"}, {"field": "sha1", "column": "SHA-1"},
                   {"field": "sha256", "column": "SHA-256"}]
        row = {}
        for header in headers:
            row[header["field"]] = row_data["data"]["attributes"][header["field"]]
        return convert_to_markdown(headers=headers, rows=[row])
    except KeyError:
        raise Exception("failed to get file information, please check  object[data][attributes]")
    except Exception:
        raise Exception("failed to create file information table")


def create_last_analysis_status_table(row_data):
    try:
        headers = [{"field": "total_scans", "column": "Total Scans"},
                   {"field": "malicious_scans", "column": "Malicious Scans"}]
        last_analysis_stats = row_data["data"]["attributes"]["last_analysis_stats"]
        total_scans = 0
        for count in last_analysis_stats.values():
            total_scans += count
        malicious_scans = last_analysis_stats["malicious"]
        data = [{"total_scans": total_scans, "malicious_scans": malicious_scans}]
        return convert_to_markdown(headers=headers, rows=data)
    except KeyError:
        raise Exception("failed to get last analysis stats, please check object[data][attributes][last_analysis_stats]")
    except Exception:
        raise Exception("failed to create last analysis stats table")


def create_last_analysis_results_table(row_data):
    try:
        current_date = datetime.today()
        headers = [{"field": "scan_origin", "column": "Scan Origin"}, {"field": "scan_result", "column": "Scan Result"},
                   {"field": "last_update", "column": "Last Update"}]
        last_analysis_results = row_data["data"]["attributes"]["last_analysis_results"]
        data = []
        for key in last_analysis_results.keys():
            engine_update = datetime.strptime(last_analysis_results[key]["engine_update"], '%Y%m%d')
            last_update = current_date - engine_update
            row = {"scan_origin": key, "scan_result": last_analysis_results[key]["category"],
                   "last_update": last_update.days}
            data.append(row)
        return convert_to_markdown(headers=headers, rows=data)
    except KeyError:
        raise Exception("failed to get analysis results, please check object[data][attributes][last_analysis_results]")
    except Exception as e:
        raise Exception("failed to create last  analysis results table")


# get request from VirusTotal
def get_request(file_hash):
    url_request = "{0}{1}".format(URL, file_hash)
    headers = {'x-apikey': KEY}
    response = requests.get(url_request, headers=headers)
    response.raise_for_status()
    return response.json()


def get_virus_total_data_tables(file_hash):
    information_table = get_file_information_table(file_hash=file_hash)
    analysis_status_table = get_last_analysis_status_table(file_hash=file_hash)
    analysis_results_table = get_last_analysis_results_table(file_hash=file_hash)
    return information_table, analysis_status_table, analysis_results_table


def get_file_information_table(file_hash):
    data = get_request(file_hash)
    return create_file_information_table(row_data=data)


def get_last_analysis_status_table(file_hash):
    data = get_request(file_hash)
    return create_last_analysis_status_table(row_data=data)


def get_last_analysis_results_table(file_hash):
    data = get_request(file_hash)
    return create_last_analysis_results_table(row_data=data)


if __name__ == '__main__':
    try:
        results = get_virus_total_data_tables("84c82835a5d21bbcf75a61706d8ab549")
        for res in results:
            print(res)
    except Exception as err:
        raise SystemExit(err)
