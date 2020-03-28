# squirrelOTX
A cross platform command line tool that search against Alienvault OTX from the comfort of your terminal written in Python3

For details about the Alienvault OTX DirectConnect API, visit https://otx.alienvault.com/api

Example Usage:
Export YARA rules from subsribed pulses
    ```
    > python.exe .\\%(prog)s --key 12345678987654321 --export=YARA
    ```
Get general data about a file hash
    ```
    > python.exe .\\%(prog)s --key 12345678987654321 --hash=general --indicator=076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560
    ```

Warnings:
- Exports may take a while to return results based on how pulse subscriptions you have, YMMV....

Dependencies can be met via pip
    ```
    > pip3 install requests
    > pip3 install pandas
    ```
or the included [requirements.txt](./requirements.txt) file
    ```
    > pip3 install -r requirements.txt
    ```
