
import pyshark # This to import the pyshark library

import os
import configparser
import sys
import pandas as pd

def main():

    print('welcome to main function')

    params =sys.argv[1]
    config = configparser.ConfigParser()
    config.read("Conf.conf")
    params_config =config[params]




    if params_config.get('sniffing'):
        import IDS as ids
        exe = ids.IDS(params_config)
        exe._read_pcap(params_config.get('NIC'), params_config.get('check_ioc'))








if __name__ =="__main__":
    main()



