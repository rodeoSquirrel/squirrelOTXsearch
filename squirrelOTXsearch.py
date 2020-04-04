##
#   Version Info
#
#   Script: Squirrel OTX Search
#   Description: A cross platform command line tool that search against Alienvault OTX
#                from the comfort of your terminal written for Python3
#   Version: 1.0.1
#
##

import json
import requests
import argparse
import os
import sys
import re
import pandas

from requests.auth import AuthBase

parser = argparse.ArgumentParser(
                prog='squirrelOTXsearch.py',
                usage='%(prog)s [-h] [--key] OTXKEYVALUE [--searchType] CHOICE [--search] SEARCHSTRING',
                description='''
SquirrelOTXSearch v1.0

          )" .
         /    \      (\-./   [Hot dang!]
        /     |    _/ o. \\  /
       |      | .-"      y)-
       |      |/       _/ \\
       \\     /j    _".\\(@)
        \\   ( |    `.''  )
         \\  _`-     |   /
           "  `-._  <_ (
                  `-.,),)
    [@rodeo_squirrel]
    A cross platform command line tool that search against Alienvault OTX from the comfort of your terminal

    For details about the Alienvault OTX DirectConnect API, visit https://otx.alienvault.com/api

    Example Usage:
    Export YARA rules from subsribed pulses
    > python.exe .\\%(prog)s --export=YARA
    Get general data about a file hash
    > python.exe .\\%(prog)s --hash=general --indicator=076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560

    Prerequisites and Warnings:
    - Set an environment variable OTXAPI to store your API key
    - Exports may take a while to return results based on how pulse subscriptions you have, YMMV....

    Dependencies can be met through existing pip packages:
    > pip install requests
    > pip install pandas

                ''',
                epilog='Contact me on GitHub(https://github.com/rodeoSquirrel) or Twitter(@rodeo_squirrel) for issues or feature requests',
                formatter_class=argparse.RawTextHelpFormatter
                                )
parser.add_argument('--text', action='store',
                    help='Search by raw text input, this is the kitchen sink option')
parser.add_argument('--pulseID', action='store',
                    help='Search for indicators by pulse ID')
parser.add_argument('--export', action='store', choices=['YARA'],
                    help='Export indicators for pulses you have subscribed to.')
#parser.add_argument('--export', action='store', choices=['IPv4', 'hash', 'domain', 'hostname', 'YARA'],
#                    help='Export indicators for pulses you have subscribed to.')
parser.add_argument('--ipv4', action='store', choices=['general', 'reputation', 'geo', 'url_list',
                    'passive_dns', 'http_scans'], help='Search for specifics on a particular IPv4 address')
parser.add_argument('--ipv6', action='store',     choices=['general', 'reputation', 'geo', 'url_list', 'passive_dns'],
                    help='Search for specifics on a particular IPv6 address')
parser.add_argument('--domain', action='store', choices=['general', 'geo', 'malware', 'url_list',
                    'passive_dns', 'whois', 'http_scans'], help='Search for specifics on a particular domain')
parser.add_argument('--hostname', action='store', choices=['general', 'geo', 'malware', 'url_list',
                    'passive_dns', 'http_scans'], help='Search for specifics on a particular hostname')
parser.add_argument('--hash', action='store', choices=['general', 'analysis'],
                    help='Search for specifics on a particular file hash')
parser.add_argument('--url', action='store', choices=['general', 'url_list'],
                    help='Search for specifics on a particular URL')
parser.add_argument('--cve', action='store', required=False,
                    help='Search for specifics on a particular CVE')
parser.add_argument('--indicator', action='store', required=False,
                    help='Use this with ipv4/6, domain, hostname, and url searches to specify the indicator string')
parser.add_argument('--format', action='store', choices=['csv', 'json'],
                    default='json', help='Enter format type, csv and json supported')
parser.add_argument('--outfile', action='store', required=False,
                    help='Path to output file, extension will be added automatically')
parser.add_argument('--dumpDir', action='store', required=False,
                    help='Path for dumping exported data to a file')
args = parser.parse_args()

REST_API_domain = 'https://otx.alienvault.com'
search_pulses = '/api/v1/search/pulses?q='
pulse_by_id = '/api/v1/pulses/'
export_indicators = '/api/v1/indicators/export'
ipv4_details = '/api/v1/indicators/IPv4/'
ipv6_details = '/api/v1/indicators/IPv6/'
domain_details = '/api/v1/indicators/domain/'
hostname_details = '/api/v1/indicators/hostname/'
file_details = '/api/v1/indicators/file/'
url_details = '/api/v1/indicators/url/'
cve_details = '/api/v1/indicators/cve/'

otx_key = os.getenv('OTXAPI')
total_pages = 0

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
elif not otx_key:
    sys.exit('WARNING: OTXAPI environment variable not detected. Set the environment variable, open a new terminal session, and try again...')

if args.dumpDir and not os.path.isdir(args.dumpDir):
    os.mkdir(args.dumpDir)

class TokenAuth(AuthBase):
    # Implements a custom authentication scheme
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['X-OTX-API-KEY'] = f'{self.token}'
        return r

def get_OTX_search():
    if args.text:
        API_endpoint = search_pulses
        URI_vars = args.text + '&sort=-modified'
    elif args.pulseID:
        API_endpoint = pulse_by_id
        URI_vars = args.pulseID + '/indicators'
    elif args.export:
        API_endpoint = export_indicators
        URI_vars = '?types=' + args.export
    elif args.ipv4:
        API_endpoint = ipv4_details
        URI_vars = args.indicator + '/' + args.ipv4
    elif args.ipv6:
        API_endpoint = ipv6_details
        URI_vars = args.indicator + '/' + args.ipv6
    elif args.domain:
        API_endpoint = domain_details
        URI_vars = args.indicator + '/' + args.domain
    elif args.hostname:
        API_endpoint = hostname_details
        URI_vars = args.indicator + '/' + args.hostname
    elif args.hash:
        API_endpoint = file_details
        URI_vars = args.indicator + '/' + args.hash
    elif args.url:
        API_endpoint = url_details
        URI_vars = args.indicator + '/' + args.url
    elif args.cve:
        API_endpoint = cve_details
        URI_vars = args.cve + '/general'

    print('Issuing Request for: ' + REST_API_domain + API_endpoint + URI_vars)

    effective_result = []

    try:
        first_request = requests.get(
            url='{api_url}{path}{uri_vars}'.format(
                api_url=REST_API_domain,
                path=API_endpoint,
                uri_vars=URI_vars,
            ), auth=TokenAuth(otx_key)
        )
        first_response = first_request.json()
        first_status = first_request.status_code
        if first_status != 200:
            print(first_request.raise_for_status())
    except Exception as e:
        sys.exit(e)

    if not(args.indicator or args.cve):
        get_next_page = json.dumps(first_response)
        search_result_count = first_response['count']
        search_substring = 'page='
        page_count = search_result_count // 1000
        page_count_remainder = search_result_count % 1000
        page_count_mod = 0

        if page_count_remainder:
            page_count_mod += 1

        total_pages = page_count + page_count_mod
        i = total_pages

        for result in first_response['results']:
            effective_result.append(result)

        while i > 1:
            try:
                next_request = requests.get(
                url='{api_url}{path}{uri_vars}{uri_pages}{pages_int}'.format(
                    api_url=REST_API_domain,
                    path=API_endpoint,
                    uri_vars=URI_vars,
                    uri_pages='&' + search_substring,
                    pages_int=i
                ), auth=TokenAuth(otx_key)
                )
                next_response = next_request.json()
                next_status = next_request.status_code
                if next_status != 200:
                    print(next_request.raise_for_status())
            except Exception as e:
                print(e)

            next_page = json.dumps(next_response)
            next_page_list = json.loads(next_page)

            for result in next_response['results']:
                effective_result.append(result)

                i -= 1
    else:
        effective_result.append(first_response)


    return effective_result

def get_results():
    OTX_search_result = get_OTX_search()
    OTX_JSON_result = json.dumps(OTX_search_result, indent=2)

    # This separate section seems redundant, but it saves some horrid complexity that
    # that exists because of the difference in JSON message structure between a few of the REST endpoints
    if args.ipv4 or args.ipv6 or args.domain or args.hostname or args.url or args.cve:
        print(OTX_JSON_result)
    elif (args.ipv4 or args.ipv6 or args.domain or args.hostname or args.url or args.cve) and args.outfile:
        outfile = args.outfile + '.json'

        # Check if outfile exists append results to it by loading the json blob,
        # appending to it, then overwriting the existing file
        # Else the file does not exist, write out to a new file
        if os.path.isfile(outfile):
            with open(outfile) as f:
                data = json.load(f)
            data.append(OTX_search_result)

            with open(outfile, 'w') as f:
                json.dump(data, f)
        else:
            with open(outfile, 'w') as f:
                contents = []
                contents.append(OTX_search_result)
                json.dump(contents, f)
        f.close()
    elif args.export == 'YARA':
        item_dict = json.loads(OTX_JSON_result)
        alerts_array_length = len(item_dict)
    else:
        pandasToCSV = pandas.read_json(OTX_JSON_result)
        adjustedDataFram = pandas.DataFrame(data=pandasToCSV)
        item_dict = json.loads(OTX_JSON_result)
        alerts_array_length = len(item_dict)
        OTX_out_array = []

    # Condition for writing out to a json file
    if not(args.export) and (args.outfile and args.format == 'json'):
        outfile = args.outfile + '.json'

        # Check if outfile exists append results to it by loading the json blob,
        # appending to it, then overwriting the existing file
        # Else the file does not exist, write out to a new file
        if os.path.isfile(outfile):
            with open(outfile) as f:
                data = json.load(f)
            data.append(OTX_search_result)

            with open(outfile, 'w') as f:
                json.dump(data, f)
        else:
            with open(outfile, 'w') as f:
                contents = []
                contents.append(OTX_search_result)
                json.dump(contents, f)
        f.close()
    # Condition for printing json output to terminal
    elif not(args.export) and (not(args.outfile) and args.format == 'json'):
        print(OTX_JSON_result)
    # Contition for writing out to a csv file
    elif (args.outfile and args.format == 'csv' and args.text):
        outfile = args.outfile + '.csv'

        if os.path.isfile(outfile):
            print_or_append = 'a'
        else:
            print_or_append = 'w'
        with open(outfile, print_or_append) as f:
            for i in range(alerts_array_length):
                if args.text:
                    normalized_data = pandas.json_normalize(adjustedDataFram['indicators'][i])
                else:
                    normalized_data = pandas.json_normalize(adjustedDataFram[i], sep='_')

                if (i == 0 and os.stat(outfile).st_size == 0):
                    OTX_CSV_result = normalized_data.to_csv(
                        header=True, index=False, encoding='utf-8')
                elif (i > 0 or os.stat(outfile).st_size > 0):
                    OTX_CSV_result = normalized_data.to_csv(
                        header=False, index=False, encoding='utf-8')
                OTX_out_array.append(OTX_CSV_result)
            for j in OTX_out_array:
                f.write(j)
        f.close()
    # Condition for printing csv output to terminal
    elif not(args.outfile) and args.format == 'csv' and args.text:
        for i in range(alerts_array_length):
            if args.text:
                normalized_data = pandas.json_normalize(adjustedDataFram['indicators'][i])
            else:
                normalized_data = pandas.json_normalize(adjustedDataFram[i], sep='_')

            if i == 0:
                OTX_CSV_result = normalized_data.to_csv(header=True, index=False, encoding='utf-8')
            else:
                OTX_CSV_result = normalized_data.to_csv(header=False, index=False, encoding='utf-8')

            if OTX_CSV_result:
                OTX_out_array.append(OTX_CSV_result)
        for j in OTX_out_array:
            print(j)
    # Condition for printing indicators by PulseID to a CSV file
    elif args.outfile  and args.pulseID and args.format == 'csv':
        outfile = args.outfile + '.csv'

        if os.path.isfile(outfile):
            print_or_append = 'a'
        else:
            print_or_append = 'w'
        with open(outfile, print_or_append) as f:
            normalized_data = pandas.json_normalize(item_dict)

            if os.stat(outfile).st_size == 0:
                OTX_CSV_result = normalized_data.to_csv(header=True, index=False, encoding='utf-8')
            elif os.stat(outfile).st_size > 0:
                OTX_CSV_result = normalized_data.to_csv(header=False, index=False, encoding='utf-8')

            if OTX_CSV_result:
                OTX_out_array.append(OTX_CSV_result)

            for j in OTX_out_array:
                f.write(j)
        f.close()
    # Condition for printing indicators by PulseID to terminal as CSV
    elif not(args.outfile)  and args.pulseID and args.format == 'csv':
        normalized_data = pandas.json_normalize(item_dict)

        OTX_CSV_result = normalized_data.to_csv(header=True, index=False, encoding='utf-8')

        if OTX_CSV_result:
            OTX_out_array.append(OTX_CSV_result)

        for j in OTX_out_array:
            print(j)
    # Condition for printing YARA export output to terminal
    elif not(args.outfile or args.dumpDir) and args.export == 'YARA':
        for i in range(alerts_array_length):
            print(item_dict[i]['id'])
            print(item_dict[i]['content'])
    # Condition for printing YARA to uniquely named files in a dump directory
    elif not(args.outfile) and (args.dumpDir and args.export == 'YARA'):
        for i in range(alerts_array_length):
            ruleID = item_dict[i]['id']
            YARArule = item_dict[i]['content']
            ruleNameLineRegex = re.compile(r'rule\s+\S+')
            ruleNameRaw1 = ruleNameLineRegex.search(YARArule).group(0)
            ruleNameRaw2 = ruleNameRaw1.strip('rule')
            ruleName = ruleNameRaw2.strip()
            outfile = args.dumpDir + '/' + str(ruleName) + '.yara'

            with open(outfile, 'w') as f:
                f.write(YARArule)
            f.close()
    elif args.format == 'csv':
        print('CSV output is not currently supported for this query response')

def main():
    get_results()

if __name__ == '__main__':
    main()
