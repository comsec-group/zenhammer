#!/usr/bin/env python3

from collections import OrderedDict 
import json
import glob

output_order = [
    '0949766b-8a7a-4f96-b8e8-73476b7223cb',
    'c0e457fd-cadd-40a1-a4a4-676c062e5fd4',
    'a8ed783b-66c1-4d40-a9bd-f0b24e278c67',
    '',
    'fbde499f-af87-4190-bb11-21db5a3579b6',
    '0c79c8d7-9456-48b4-8759-87039e3863ab',
    'f8374e49-f38f-4a9f-83d4-45ef8054bb5b',
    'a319e465-d3d7-4ad0-90c8-03938a983b71',
    '8eecfe96-1001-404f-bc61-dedb723778f0',
    '',
    '69ab848f-2f03-4380-a7d1-4befce75d8d5',
    'df278959-d95b-4ac1-9d62-e3e7e7f64252',
    '244c0826-f606-4191-9443-404cf64deb84',
    '9c34799e-9622-4f2d-8590-1f43c836a716',
    '',
    '72edb55e-37cc-4f22-81ee-cfd3f36decb4',
    'fced2922-cc75-474e-9b01-648e33e00f66',
    '6a9b119a-5de5-4353-83a1-301b0037adb9',
    '265a4bd7-0bce-4794-863d-841e59a1d7df',
    'e022ba20-4e6d-4ee2-9ab9-1a52ee54a1df',
    '',
    '',
    '',
    'f11658ad-3c7e-413f-9840-8859f7365c7c',
    '247f8890-ebf9-451d-97af-24d34240b973',
    '230af0b3-0f59-4d5d-ade5-0fae68606f03',
    '',
    '6f9a200b-bf77-4529-93c6-af5f2a6e0744',
    '3cc054f6-b5e0-40b5-b79f-a6c31256c203',
    '393bda26-4200-44c0-995b-229b883495eb',
    'f9e6d59f-dfea-4263-a9fb-bdb50e47b5a9',
    'c37fb8c3-daa6-4190-9d9c-4e6bd187e904',
    'ce7e4939-6c1e-4be1-9e75-c9fca5497e97',
    '8a7af9ed-4eb5-4598-a9b3-dfda1c6c2750',
    'b92756f8-bf48-482d-aa4c-da73756d2427',
    'a8b35c19-d353-43dd-8e30-0b5a1362b5eb',
    '31497143-e4e4-4a1d-bf57-9ec1ef2ce58d',
    '9c4bc8fa-adba-4c5b-9871-1d35d8b17583',
    'eae49705-4cf7-434e-bed0-871668659a5d',
    'e0c1514b-e614-459c-ab82-31fed2701cc6',
    '45d1b645-3f67-4aea-93b9-dafef492c673']

total_corruptions = dict()

def main():
    for name in glob.glob('portability_experiment/**/sweep-summary.json', recursive=True): 
        dimm_id = name.split('/')[1].replace('_', ' ')
        print(f'===== {dimm_id} ===== ')
        with open(name) as f:
            data = json.load(f)
            for probed_pattern in data['sweeps']:
                pattern_id = probed_pattern['pattern']
                num_corruptions = probed_pattern['flips']['total']
                total_corruptions[pattern_id]=num_corruptions
        for e in output_order:
            if e == '':
                print('')
            else:
                print(total_corruptions[e])



if __name__ == '__main__':
    main()
