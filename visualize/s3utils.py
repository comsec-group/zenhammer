import re
import threading

import boto3
import pandas as pd
from botocore.exceptions import ClientError
from typing import List

BUCKET_NAME = 'blacksmith-evaluation'
client = boto3.client("s3")


def get_file(path: str, filters: list, get_s3_url: bool = False):
    response = client.list_objects(Bucket=BUCKET_NAME, Prefix=path)
    files = []
    for content in response.get('Contents', []):
        filename = content.get('Key')
        for f in filters:
            if f in filename:
                if get_s3_url:
                    files.append(f"s3://{BUCKET_NAME}/{filename}")
                else:
                    files.append(filename)
    return files


def get_folder_in_s3_path():
    result = client.list_objects_v2(Bucket=BUCKET_NAME, Prefix="")
    folder_names = []
    if result.get('Contents') is None:
        print("[-] get_folder_in_s3_path failed.")
        return []
    subfolders = set()
    last_dimm_id = ''
    for o in result.get('Contents'):
        key = o.get('Key')
        data = key.split('/')
        dimm_id = int(data[0].replace('DIMM_', ''))
        ts_folder = data[1]
        if last_dimm_id == '' or dimm_id == last_dimm_id:
            subfolders.add(ts_folder)
        elif dimm_id != last_dimm_id:
            if len(subfolders) > 0:
                last_folder = sorted(subfolders, reverse=True)[0]
                folder_names.append(f"DIMM_{last_dimm_id}/{last_folder}")
                subfolders.clear()
            subfolders.add(ts_folder)
        last_dimm_id = dimm_id
    return folder_names


# def get_folder_in_s3_path(path: str):
#     result = client.list_objects_v2(Bucket=BUCKET_NAME)
#     folder_names = []
#     if result.get('CommonPrefixes') is None:
#         print("[-] get_folder_in_s3_path failed for {}.".format(path))
#         return []
#     for o in result.get('CommonPrefixes'):
#         folder_names.append(o.get('Prefix'))
#     return folder_names

def download_file_to(path: str, destination: str):
    print(f"[+] Downloading file from s3://{BUCKET_NAME}/{path}")

    def download(path: str, destination: str):
        with open(f"{destination}", 'wb') as f:
            client.download_fileobj(f"{BUCKET_NAME}", f"{path}", f)

    x = threading.Thread(target=download, args=(path, destination), daemon=True)
    x.start()
    return x

