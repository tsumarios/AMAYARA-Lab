#!/usr/bin/env python3


import os
import json
import yara
from hashlib import md5, sha1, sha256
from zipfile import ZipFile


def get_file_digests(file):
    md5_digest, sha1_digest, sha256_digest = md5(), sha1(), sha256()

    with open(file, "rb") as f:
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
    results = {}
    # Extract the APK file into a temporary directory
    with ZipFile(apk_file, 'r') as zipObj:
        zipObj.extractall('tmp')
        # Iterate all over the extracted files
        for root, dirs, files in os.walk("tmp", topdown=False):
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
    # Initialise results with file info and digets
    md5_digest, sha1_digest, sha256_digest = get_file_digests(apk_file)
    results = {'file_name': os.path.basename(apk_file), 'digests': {'md5': md5_digest.hexdigest(),
               'sha1': sha1_digest.hexdigest(), 'sha256': sha256_digest.hexdigest()}, 'result': {}}

    # Scan APK and its content
    results['result']['apk'] = rules_scanner(apk_file) or {}
    results['result']['apk_content'] = analyse_files_in_apk(apk_file) or {}

    # Save and print results
    with open(f'./results/result_{md5_digest.hexdigest()}.json', 'w') as json_file:
        json.dump(results, json_file)
    print(results)


def main():
    for apk_file in apk_files.values():
        analyse_apk(apk_file)


if __name__ == '__main__':
    main()
