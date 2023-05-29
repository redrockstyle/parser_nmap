import re
import argparse
import os
import struct
from socket import inet_aton
from enum import Enum
os.system("")   # enable color

version = "v1.2.0"

json_regex_types = {r'Nmap scan report for .*$': "0", r'^[0-9]*/tcp.*open.*': "0",
                    r'Aggressive OS guesses:.*': "0", r'PORT.*': "0", r'Device type:.*$': "0",
                    r'OS details:.*$': "0", "VULNERABLE:": "1"}


class Status(Enum):
    INFO = '[*]'
    ERROR = '[!]'


class Colors:
    HEADER = '\033[95m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'


class Operation(Enum):
    IP_VULNERABLE = 1
    IP_ALL = 2
    IP_OPEN = 3
    ALL_REPORT = 4


class ConstRegex(Enum):
    REG_TITLE = r'Nmap scan report for .*$'
    REG_TITLE_PORT = r'PORT.*'
    REG_TCP_PORT = r'^[0-9]*/tcp.*open.*'
    REG_AGGRESSIVE_OS = r'Aggressive OS guesses:.*'
    REG_DEVICE_TYPE = r'Device type:.*$'
    REG_OS_DETAILS = r'OS details:.*$'
    REG_VULNERABLE = r'VULNERABLE:'
    REG_IP_FROM_TITLE = r'[0-9]+(?:\.[0-9]+){3}'


def drop_operation(msg):
    print(f'{Colors.FAIL}{Status.ERROR.value} Drop operation: {msg}{Colors.END}')
    exit()


def info_operation(msg):
    return f'{Colors.GREEN}{Status.INFO.value} {msg}{Colors.END}'


def header_operation(msg):
    return f'{Colors.HEADER}{msg}{Colors.END}'


def sort_ip(report_nmap):
    unique_elems = [*set(report_nmap)]
    report_nmap = sorted(unique_elems, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])
    return report_nmap


def parse_scan(report_nmap, operation):
    scan = {}
    body = []
    count_open_ports = 0
    count_append = 0
    remember_title = ''
    remember_title_port = ''
    for line_report in report_nmap:
        line_report = line_report.strip()
        if not line_report:
            continue

        if count_append:
            body.append(line_report)
            count_append = 0

        for re_type, count_type_str in json_regex_types.items():
            if re.search(re_type, line_report):
                # ALL REPORT SCAN
                if operation == Operation.ALL_REPORT:
                    if ConstRegex.REG_VULNERABLE.value == re_type:
                        body.append(line_report)
                        count_append = count_type_str
                        break
                    elif ConstRegex.REG_TCP_PORT.value == re_type:
                        line_report = line_report.replace('/tcp', '    ').replace('open', '    ')
                        body.append(line_report)
                        count_open_ports = count_open_ports + 1
                        break
                    elif ConstRegex.REG_TITLE_PORT.value == re_type:
                        remember_title_port = line_report.replace('STATE', '     ')
                        break
                    elif ConstRegex.REG_TITLE.value == re_type:
                        if count_open_ports:
                            body.insert(0, remember_title_port)
                            body.insert(0, remember_title)
                            body.append(f'Total open ports: {count_open_ports}')
                            scan[''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, remember_title)[-1:])] = body
                            count_open_ports = 0
                            body = []
                        remember_title = line_report
                        break
                # VULNERABLE IP
                elif operation == Operation.IP_VULNERABLE:
                    if ConstRegex.REG_VULNERABLE.value == re_type:
                        if remember_title:
                            body.append(''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, remember_title)[-1:]))
                            remember_title = ''
                    elif ConstRegex.REG_TITLE.value == re_type:
                        remember_title = line_report
                # ALL IP
                elif operation == Operation.IP_ALL:
                    if ConstRegex.REG_TITLE.value == re_type:
                        body.append(''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, line_report)[-1:]))
                # OPEN TCP IP
                elif operation == Operation.IP_OPEN:
                    if ConstRegex.REG_TCP_PORT.value == re_type:
                        if remember_title:
                            body.append(''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, remember_title)[-1:]))
                            remember_title = ''
                    elif ConstRegex.REG_TITLE.value == re_type:
                        remember_title = line_report
                else:
                    drop_operation('Unsupported parse operation')
    if operation == Operation.ALL_REPORT:
        if count_open_ports:
            body.insert(0, remember_title_port)
            body.insert(0, remember_title)
            body.append(f'Total open ports: {count_open_ports}')
            scan[''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, remember_title)[-1:])] = body
        return scan
    else:
        return body


def write_to_file(filename, data):
    print(info_operation(f'Generate report to {filename} file...'))
    with open(filename, 'w') as writer:
        if type(data) is list:
            for line in data:
                writer.write(f"{line}\n")
        elif type(data) is dict:
            for ip_str in data:
                for line in data[ip_str]:
                    writer.write(f"{line}\n")
                writer.write('\n')
        writer.write(f"Total IP parsed: {len(data)}")


def print_target(data):
    data[0] = header_operation(data[0])
    data[-1] = header_operation(data[-1])
    for line in data:
        print(line)


def print_scan(data):
    if type(data) is list:
        for line in data:
            print(line)
    elif type(data) is dict:
        for ip_str in data:
            print('\n')
            print_target(data[ip_str])
    print(info_operation(f"Total IP parsed: {len(data)}"))


def main():
    parser = argparse.ArgumentParser(description="TCP Parser NMAP " + version)
    parser.add_argument('-v', '-V', '--version', action='version', version=version)
    parser.add_argument('-s', '--scan', required=True, help='report scan NMAP')
    parser.add_argument('-o', '--output', help='generate file report')
    parser.add_argument('-t', '--target', help='print-parsing for one ip')
    parser.add_argument('-i', '--ip', required=False, type=int, choices=range(1, 4), help="output ip:\
                                                            1 - for VULNERABLE ip;\
                                                            2 - for ALL ip;\
                                                            3 - for ip with OPEN TCP ports")

    args = parser.parse_args()
    if not os.path.isfile(args.scan):
        drop_operation(f'File {args.scan} not found')

    report_nmap = open(args.scan, 'r')
    parse_reg_scan = []
    if args.ip:
        if args.ip == Operation.IP_VULNERABLE.value:
            print(info_operation('Parsing VULNERABLE ip...'))
            parse_reg_scan = sort_ip(parse_scan(report_nmap, Operation.IP_VULNERABLE))
        elif args.ip == Operation.IP_ALL.value:
            print(info_operation(f'Parsing ALL ip...'))
            parse_reg_scan = sort_ip(parse_scan(report_nmap, Operation.IP_ALL))
        elif args.ip == Operation.IP_OPEN.value:
            print(info_operation('Parsing OPEN TCP ip...'))
            parse_reg_scan = sort_ip(parse_scan(report_nmap, Operation.IP_OPEN))
    else:
        print(info_operation('Parsing...'))
        parse_reg_scan = parse_scan(report_nmap, Operation.ALL_REPORT)
        if args.target:
            if parse_reg_scan.get(args.target):
                print_target(parse_reg_scan[args.target])
                return
            else:
                drop_operation("IP address not found")
    if args.output:
        write_to_file(args.output, parse_reg_scan)
    else:
        print_scan(parse_reg_scan)
    print(info_operation('Done'))
    return


if __name__ == '__main__':
    main()
