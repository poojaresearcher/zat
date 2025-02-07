
import os
import sys
import argparse
from pprint import pprint
import time

# Local imports
from zat import zeek_log_reader

if __name__ == '__main__':
    # Example to run the zeek log reader on a given file

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    parser.add_argument('-t', '--tail', action='store_true', help='Turn on log tailing')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Run the zeek reader on a given log file
        reader = zeek_log_reader.ZeekLogReader(args.zeek_log, tail=args.tail, strict=True)
        for row in reader.readrows():
            pprint(row)
           
    dnslog = '/home/logs/current/dns.log'
    sleep_time_in_seconds = 10

    try:
        with open(dnslog, 'r', errors='ignore') as f:
            while True:
                for line in f:
                    if line:
                        print(line.strip())
                        # do whatever you want to do on the line
                time.sleep(sleep_time_in_seconds)
    except IOError as e:
        print('Cannot open the file {}. Error: {}'.format(dnslog, e))
            
