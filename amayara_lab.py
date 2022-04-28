#!/usr/bin/env python3


import os
import json
import requests
import yara
from hashlib import md5, sha1, sha256
from time import sleep
from zipfile import ZipFile


MB_API_KEY = os.environ.get('MB_API_KEY')  # Malware Bazaar API key
VT_API_KEY = os.environ.get('VT_API_KEY')  # Virus Total API key


def get_malware_bazaar_stats(sha256_digest):
    """
    Return Malware Bazaar statistics for the file.
    """
    result = {}

    # Get file report (if exists)
    url = f'https://mb-api.abuse.ch/api/v1/'
    headers = {'Accept': 'application/json', 'API-KEY': MB_API_KEY}
    data = {'query': 'get_info', 'hash': sha256_digest}
    response = requests.post(url, headers=headers, data=data)
    response_json = response.json()

    # If the file report does not exist, just return None
    if response_json['query_status'] == 'hash_not_found':
        return None

    data = response_json['data'][0]
    result['report_url'] = f'https://bazaar.abuse.ch/sample/{sha256_digest}'
    result['yara_rules'] = data.get('yara_rules')
    result['delivery_method'] = data.get('delivery_method')
    result['intelligence'] = data.get('intelligence', {}).get('clamav')

    return result


def get_virus_total_stats(file, sha256_digest):
    """
    Return Virus Total statistics for the file.
    """
    result = {}

    # Get file report (if exists)
    url_report = f'https://www.virustotal.com/api/v3/files/{sha256_digest}'
    headers_report = {'Accept': 'application/json', 'x-apikey': VT_API_KEY}
    response = requests.get(url_report, headers=headers_report)

    # If the file report does not exist, upload the file and analyse it
    if response.status_code == 404:
        url_upload = 'https://www.virustotal.com/api/v3/files'
        files_upload = {'file': (file, open(file, 'rb'))}
        headers_upload = {'x-apikey': VT_API_KEY}
        response = requests.post(url_upload, files=files_upload, headers=headers_upload)
        # Then get file report
        response = requests.get(url_report, headers=headers_report)

    # Return desired info from the analysis object
    result['report_url'] = f'https://www.virustotal.com/gui/file/{sha256_digest}'
    result['suggested_threat_label'] = response.json().get('data', {}).get('attributes', {}).get('popular_threat_classification', {}).get('suggested_threat_label')
    result['last_analysis_stats'] = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats')
    return result


def get_file_digests(file):
    """
    Return the md5, sha1 and sha256 digests for a file.
    """
    md5_digest, sha1_digest, sha256_digest = md5(), sha1(), sha256()

    with open(file, 'rb') as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b''):
            md5_digest.update(byte_block)
            sha1_digest.update(byte_block)
            sha256_digest.update(byte_block)

    return md5_digest, sha1_digest, sha256_digest


def get_paths(folder, extension):
    paths = {}
    for root, dirs, files in os.walk(folder, topdown=False):
        for name in files:
            if name.endswith(extension):
                paths[name] = os.path.join(root, name)

    return paths


# Retrieve paths for apk file(s) and YARA rule(s)
apk_files = get_paths('./files', '.apk')
rules_paths = get_paths('./rules', '.yar')
# Compile rules
rules = yara.compile(filepaths=rules_paths)


def rules_scanner(file):
    """
    Scan a file using the YARA rules in the /rules folder (including subfolders).
    """
    results = {}
    for match in rules.match(file):
        strings_list = []
        for data in match.strings:
            # The string output is a tuple (Location, Identifier, String)
            string = data[2].decode("utf-8")
            if string not in strings_list:
                strings_list.append(string)
        results[match.rule] = strings_list

    return results


def analyse_files_in_apk(apk_file):
    """
    Analyse all the files in an apk.
    """
    results = {}
    # Extract the APK file into a temporary directory
    with ZipFile(apk_file, 'r') as zipObj:
        zipObj.extractall('tmp')
        # Iterate all over the extracted files
        for root, dirs, files in os.walk('tmp', topdown=False):
            for name in files:
                file_path = os.path.join(root, name)
                # Get results for the current file
                result = rules_scanner(file_path)
                if bool(result):
                    results[name] = result
            # Cleanup
                os.remove(file_path)
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir('tmp')

    return(results)


def analyse_apk(apk_file):
    """
    Analyse an apk file and stores the results into a JSON file under the /results folder.
    """
    # Initialise results with file info, digests, VT stats and MB stats
    md5_digest, sha1_digest, sha256_digest = get_file_digests(apk_file)
    vt_stats = get_virus_total_stats(apk_file, sha256_digest.hexdigest())
    mb_stats = get_malware_bazaar_stats(sha256_digest.hexdigest())
    results = {'file_name': os.path.basename(apk_file),
               'digests': {'md5': md5_digest.hexdigest(), 'sha1': sha1_digest.hexdigest(), 'sha256': sha256_digest.hexdigest()},
               'vt_stats': vt_stats, 'mb_stats': mb_stats, 'pithus_report_url': f'https://beta.pithus.org/report/{sha256_digest.hexdigest()}',
               'yara_results': {}}

    # Scan APK and its content
    results['yara_results']['apk'] = rules_scanner(apk_file) or {}
    results['yara_results']['apk_content'] = analyse_files_in_apk(apk_file) or {}

    # Save and print results
    with open(f'./results/result_{md5_digest.hexdigest()}.json', 'w') as json_file:
        json.dump(results, json_file)
    print(results)


def main():
    for apk_file in apk_files.values():
        analyse_apk(apk_file)
        sleep(10)


if __name__ == '__main__':
    main()
