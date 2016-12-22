import re
import sys
import getopt
# import csv
# import vars
import requests


########################################################################################################################
#   WLC Configuration Element Extraction Script
#   Extracts key configuration elements from a Cisco WLC configuration for import to the Cisco Meraki Dashboard
#
#   Usage: python3 config-extractor.py -i <inputfile> -o <outputfile> -r <radius-key> -p <pre-shared-key>
#
########################################################################################################################

def main(argv):
    inputfile = ''
    outputfile = './convert-script.cfg'
    radiuskey = 'replace-me'
    psk = 'replace-me'
    hasinput = False
    hasradkey = False
    haspsk = False
    hasoutput = False

    try:
        opts, args = getopt.getopt(argv, "hi:o:r:p:", ["ifile=", "ofile=", "radkey=", "psk="])
    except getopt.GetoptError:
        print('Usage: python3 config-extractor.py -i <inputfile> -o <outputfile> -r <radius-key> -p <pre-shared-key>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: python3 config-extractor.py -i <inputfile> -o <outputfile> -r <radius-key> -p '
                  '<pre-shared-key>\noutputfile will default to \"{0}\"\nradiuskey will default to \"{1}\"\npreshared '
                  'key will default to \"{2}\"'.format(str(outputfile), str(radiuskey), str(psk)))
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
            hasinput = True
        elif opt in ("-o", "--ofile"):
            outputfile = arg
            hasoutput = True
        elif opt in ("-r", "--radkey"):
            radiuskey = arg
            hasradkey = True
        elif opt in ("-p", "--psk"):
            psk = arg
            haspsk = True

    if hasinput is False:
        print('Usage: python3 config-extractor.py -i <inputfile> -o <outputfile> -r <radius-key> -p <pre-shared-key>\n')
        print('Input file must be specified')
        exit()

    if hasoutput is False:
        print('\n*** No output file specified, {0} will be used for output'.format(str(outputfile)))

    if hasradkey is False:
        print('\n*** No default RADIUS secret specified, all RADIUS servers will use {0}'.format(str(radiuskey)))

    if haspsk is False:
        print('\n*** No default PSK specified, all WPA-PSK SSID\'s will use {0} as the PSK'.format(str(psk)))
    print('\n*** All WLAN\'s will be configured to bridge locally to the native VLAN')

    try:
        wlanlines = []
        radiuslines = []
        infile = open(inputfile)

        try:
            for line in infile:
                if re.search(r'\bwlan\b', line):
                    wlanlines.append(line.replace('\n', '').replace('\t', ''))
                elif re.search(r'\bradius\b', line):
                    radiuslines.append(line.replace('\n', '').replace('\t', ''))
                else:
                    pass
        finally:
            infile.close()

    except IOError:
            print("Error: input file does not exist: {0}".format(str(inputfile)))
            exit()
    finally:
        infile.close()

    wlans = {}
    radauthservers = {}
    radacctservers = {}

    for line in wlanlines:
        try:
            ssid = str(re.search(r'\bcreate\s\d{1,2}\s.*', line).group(0)).split()
            ssid.remove(ssid[len(ssid)-1])
            ssid.remove('create')

            try:
                wlans[ssid[0]]['name'] = ssid[1]
            except KeyError:
                wlans[ssid[0]] = {}
                wlans[ssid[0]]['name'] = ssid[1]

        except AttributeError:
            pass

        try:
            radssidlist = str(re.search(r'\bradius_server\sa[uc][tc][ht]\sadd\s\d{1,2}\s\d{1,2}', line).group(0))\
                .split()
            radssidlist.remove('add')
            radssidlist.remove('radius_server')
            radssidlist[0], radssidlist[1], radssidlist[2] = radssidlist[1], radssidlist[0], radssidlist[2]

            try:
                if radssidlist[1] == 'acct':
                    wlans[radssidlist[0]]['acctServerIdx'] = radssidlist[2]
                elif radssidlist[1] == 'auth':
                    wlans[radssidlist[0]]['authServerIdx'] = radssidlist[2]
                    wlans[radssidlist[0]]['authMode'] = '8021x-radius'
                    wlans[radssidlist[0]]['encryptionMode'] = 'wpa-eap'

            except KeyError:
                wlans[radssidlist[0]] = {}
                if radssidlist[1] == 'acct':
                    wlans[radssidlist[0]]['acctServerIdx'] = radssidlist[2]
                elif radssidlist[1] == 'auth':
                    wlans[radssidlist[0]]['authServerIdx'] = radssidlist[2]
                    wlans[radssidlist[0]]['authMode'] = '8021x-radius'
                    wlans[radssidlist[0]]['encryptionMode'] = 'wpa-eap'

        except AttributeError:
            pass

        try:
            ssidsec = str(re.search(r'\bsecurity.*', line).group(0)).split()
            ssidsec.remove('security')
            if ssidsec[0] == 'wpa' and ssidsec[2] == 'psk' and ssidsec[3] == 'enable':

                try:
                    wlans[ssidsec[4]]['authMode'] = 'psk'
                    wlans[ssidsec[4]]['encryptionMode'] = 'wpa'
                    wlans[ssidsec[4]]['psk'] = psk
                except KeyError:
                    wlans[ssidsec[4]] = {}
                    wlans[ssidsec[4]]['authMode'] = 'psk'
                    wlans[ssidsec[4]]['encryptionMode'] = 'wpa'
                    wlans[ssidsec[4]]['psk'] = psk

        except AttributeError:
            pass

    for line in radiuslines:
        if re.search(r'\bauth\b', line):
            try:
                radip = str(re.search(r'\d{1,2}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,5}', line).group(0)).split()
                radauthservers[radip[0]] = {}
                radauthservers[radip[0]]['ip'] = radip[1]
                radauthservers[radip[0]]['key'] = radiuskey
                radauthservers[radip[0]]['port'] = radip[2]
            except AttributeError:
                pass

            try:
                if re.search(r'\brfc3576\b', line):
                    radcoa = str(re.search(r'enable\s\d{1,2}', line).group(0)).split()
                    radcoa[0], radcoa[1] = radcoa[1], radcoa[0].replace('enable', 'True')
                    radauthservers[radcoa[0]]['radCoa'] = radcoa[1]
            except AttributeError:
                pass

            try:
                if re.search(r'\bnetwork\b', line):
                    radnet = str(re.search(r'\d{1,2}\senable', line).group(0)).split()
                    radnet[1] = radnet[1].replace('enable', 'True')
                    radauthservers[radnet[0]]['isNetworkAuth'] = radnet[1]
            except AttributeError:
                pass

        if re.search(r'\bacct\b', line):
            try:
                acctip = str(re.search(r'\d{1,2}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,5}', line).group(0)).split()
                radacctservers[acctip[0]] = {}
                radacctservers[acctip[0]]['ip'] = acctip[1]
                radacctservers[acctip[0]]['port'] = acctip[2]
            except AttributeError:
                pass

            try:
                if re.search(r'\bnetwork\b', line):
                    acctnet = str(re.search(r'\d{1,2}\senable', line).group(0)).split()
                    acctnet[1] = acctnet[1].replace('enable', 'True')
                    radacctservers[acctnet[0]]['isNetworkAcct'] = acctnet[1]
            except AttributeError:
                pass

    print('\nCONFIGURED WLANS:\n')
    for key, value in wlans.items():
        print(key, value)
    print('\nCONFIGURED RADIUS AUTHENTICATION SERVERS:\n')
    for key, value in radauthservers.items():
        print(key, value)
    print('\nCONFIGURED RADIUS ACCOUNTING SERVERS:\n')
    for key, value in radacctservers.items():
        print(key, value)


if __name__ == "__main__":
    main(sys.argv[1:])