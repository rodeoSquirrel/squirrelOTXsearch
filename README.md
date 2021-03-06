# Squirrel OTX Search v1.0.2
A cross platform command line tool that search against Alienvault OTX from the comfort of your terminal written in Python3

For details about the Alienvault OTX DirectConnect API, visit https://otx.alienvault.com/api

Supported functionality includes:
* JSON or CSV output printed to file or terminal
* Search by IP, hash, domain, CVE, freeform keyword, or by Pulse ID
* Export YARA rules from your subscribed Pulses

Coming Soon:
* Export IPs, hashes, domains, and hostnames from your subscribed Pulses

Example Usage:
Export YARA rules from subsribed pulses

    > python.exe squirrelOTXsearch.py --key 12345678987654321 --yara

Get general data about a file hash

    > python.exe squirrelOTXsearch.py --key 12345678987654321 --hash=general --indicator=076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560

Warnings:
- Exports may take a while to return results based on how pulse subscriptions you have, YMMV....

Dependencies can be met via pip

    > pip3 install requests
    > pip3 install pandas

or the included [requirements.txt](./requirements.txt) file

    > pip3 install -r requirements.txt

Todo:
- [ ] Add support for exporting atomic indicators from subscribed Pulses
- [ ] Support CSV output for more of the server responses
