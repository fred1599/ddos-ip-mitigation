"""Script to mitigate a ddos attack by analyzing web log log file"""


import os
import sys
import re
import datetime
import argparse

class NginxLogDao():
    """Data access object for NginxLog"""

    def __init__(self, filename):
        """Initialises this with given filename"""

        assert filename is not None
        assert os.path.exists(filename)

        self.filename = filename
        self.logline = {}

    def log_lines(self, time_size=10):
        """Reads logs lines and returns them as named tuples"""

        PATTERN = re.compile(r"""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})""", re.IGNORECASE)

        with open(self.filename) as f:
            for line in f:
                res = re.search(PATTERN, line)
                ip, date = res.group(1), res.group(2)
                date = datetime.datetime.strptime(
                date, '%d/%b/%Y:%H:%M:%S')
                if ip not in logline:
                    logline[ip] = [date]
                elif ip in logline and date > logline[ip][-1] + datetime.timedelta(seconds=time_size):
                    logline[ip].append(date)
            return logline

    def ips_between(self, dt1, dt2):
        """To modify with new log_lines method"""

        ips = set()
        for log_line in self.log_lines():
            if dt1 <= log_line.time <= dt2:
                ips.add(log_line.ip)
            elif log_line.time > dt2:
                break

        return list(ips)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Analyzes web server logs to find begin and mitigate DDOS attack')
    parser.add_argument('-f', action="store", dest="nginx_log_file",
                        help="The nginx log file", required=True)
    parser.add_argument('-a', action="store_true", dest="analyze",
                        help="Analysis task")
    parser.add_argument('-t', action="store", dest="time",
                        help="Time split for log blocks (default 10)",
                        default=10)
    parser.add_argument('-i', action="store_true", dest="get_ip",
                        help="Get IPs between two timestamps")
    parser.add_argument('-b', action="store", dest="begin_timestamp",
                        help="Begin timestamp (in seconds) for IP gathering")
    parser.add_argument('-e', action="store", dest="end_timestamp",
                        help="Begin timestamp (in seconds) for IP gathering")
    params = parser.parse_args()

    if params.analyze:
        time = int(params.time)
        blocks = NginxLogDao(
            params.nginx_log_file).time_grouped(time_size=time)
        for block in blocks:
            block_start = block[0].time
            timestamp = int(block_start.timestamp())
            print("{} - {} - {}".format(block_start, timestamp, len(block)))
    elif params.get_ip:
        if params.begin_timestamp is None or params.end_timestamp is None:
            print("With option -i you must provide option -b and -e")
            sys.exit(1)

        begin_timestamp = datetime.datetime.fromtimestamp(int(params.begin_timestamp))
        end_timestamp = datetime.datetime.fromtimestamp(int(params.end_timestamp))

        ips = NginxLogDao(params.nginx_log_file).ips_between(begin_timestamp,
                                                             end_timestamp)
        for ip in ips:
            print(ip)
