import re
import argparse
import os
import struct
from socket import inet_aton
from enum import Enum

os.system("")  # enable color

version = "v1.4.1"

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
    REG_PORT_FROM_STRING = r'^[0-9]*'


def drop_operation(msg):
    return f'{Colors.FAIL}{Status.ERROR.value} Drop operation: {msg}{Colors.END}'


def info_operation(msg):
    return f'{Colors.GREEN}{Status.INFO.value} {msg}{Colors.END}'


def header_operation(msg):
    return f'{Colors.HEADER}{msg}{Colors.END}'


def sort_ip(report_nmap):
    unique_elems = [*set(report_nmap)]
    report_nmap = sorted(unique_elems, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])
    return report_nmap


def is_found_line(regex, ports, line):
    if regex and ports:
        if int(re.findall(ConstRegex.REG_PORT_FROM_STRING.value, line)[-1:][0]) in ports and re.search(regex, line):
            return True
    elif regex:
        if re.search(regex, line):
            return True
    elif ports:
        if int(re.findall(ConstRegex.REG_PORT_FROM_STRING.value, line)[-1:][0]) in ports:
            return True
    return False


def parse_scan(report_nmap, ports, regex, operation):
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
            count_append = count_append - 1
            continue

        for re_type, count_type_str in json_regex_types.items():
            if re.search(re_type, line_report):
                # ALL REPORT SCAN
                if operation == Operation.ALL_REPORT:
                    if ConstRegex.REG_VULNERABLE.value == re_type:
                        if not ports and not regex:
                            body.append(line_report)
                            count_append = int(count_type_str)
                        break
                    elif ConstRegex.REG_TCP_PORT.value == re_type:
                        if regex or ports:
                            if is_found_line(regex, ports, line_report):
                                line_report = line_report.replace('/tcp', '    ').replace('open', '    ')
                                body.append(line_report)
                                count_open_ports = count_open_ports + 1
                        else:
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
                    exit()
    if operation == Operation.ALL_REPORT:
        if count_open_ports:
            body.insert(0, remember_title_port)
            body.insert(0, remember_title)
            body.append(f'Total open ports: {count_open_ports}')
            scan[''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, remember_title)[-1:])] = body
        return scan
    else:
        return body


def write_to_file(filename, data, format_out):
    print(info_operation(f'Generate report to {filename} file...'))
    with open(filename, 'w') as writer:
        if type(data) is list:
            for line in data:
                writer.write(f"{line}\n")
        elif type(data) is dict:
            if format_out == 'min':
                for ip_str in data:
                    writer.write(f"{ip_str}\n")
            elif format_out == 'max':
                for ip_str in data:
                    for line in data[ip_str]:
                        writer.write(f"{line}\n")
                    writer.write('\n')

        writer.write(f"Total IP parsed: {len(data)}")
        print(info_operation(f"Total IP parsed: {len(data)}"))


def print_target(data, format_out):
    if format_out == 'max':
        data[0] = header_operation(data[0])
        data[-1] = header_operation(data[-1])
        for line in data:
            print(line)
        print('')
    elif format_out == 'min':
        print(''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, data[0])[-1:]))
    else:
        drop_operation('Unsupported format')
        return


def print_scan(data, format_out):
    if type(data) is list:
        for line in data:
            print(line)
    elif type(data) is dict:
        for ip_str in data:
            print_target(data[ip_str], format_out)
    print(info_operation(f"Total IP: {len(data)}\n"))


def get_ports(ports):
    if ports:
        result = []
        for part in ports.split(','):
            if '-' in part:
                a, b = part.split('-')
                a, b = int(a), int(b)
                result.extend(range(a, b + 1))
            else:
                a = int(part)
                result.append(a)
        return result
    return None


def preprocedure(file, args):
    report_nmap = open(file, 'r')
    parse_reg_scan = []
    if args.ip:
        if args.ip == Operation.IP_VULNERABLE.value:
            print(info_operation(f'Parsing VULNERABLE ip for {file}...'))
            parse_reg_scan = sort_ip(parse_scan(report_nmap, None, None, Operation.IP_VULNERABLE))
        elif args.ip == Operation.IP_ALL.value:
            print(info_operation(f'Parsing ALL ip for {file}...'))
            parse_reg_scan = sort_ip(parse_scan(report_nmap, None, None, Operation.IP_ALL))
        elif args.ip == Operation.IP_OPEN.value:
            print(info_operation(f'Parsing OPEN TCP ip for {file}...'))
            parse_reg_scan = sort_ip(parse_scan(report_nmap, None, None, Operation.IP_OPEN))
    else:
        print(info_operation(f'Parsing {file}...'))
        parse_reg_scan = parse_scan(report_nmap, get_ports(args.ports), args.regex, Operation.ALL_REPORT)
        if args.target:
            if parse_reg_scan.get(args.target):
                print_target(parse_reg_scan[args.target], args.format)
                return
            else:
                print(drop_operation(f"IP address in {file} not found\n"))
                return
    if args.output:
        write_to_file(args.output, parse_reg_scan, args.format)
    else:
        print_scan(parse_reg_scan, args.format)
    return


def main():
    parser = argparse.ArgumentParser(description="TCP Parser NMAP Normal output (-oN) " + version)
    parser.add_argument('-v', '-V', '--version', action='version', version=version)
    parser.add_argument('-s', '--scan', required=True, help='directory or report scan NMAP')
    parser.add_argument('-o', '--output', help='generate file report')
    parser.add_argument('-t', '--target', help='print-parsing for one ip')
    parser.add_argument('-p', '--ports', help='parsing for required ports')
    parser.add_argument('-r', '--regex', help='regex search to string port')
    parser.add_argument('-f', '--format', type=str, choices=['min', 'max'], default='max', help='format output')
    parser.add_argument('-i', '--ip', type=int, choices=range(1, 4), help="output ip:\
                                                            1 - for VULNERABLE ip;\
                                                            2 - for ALL ip;\
                                                            3 - for ip with OPEN TCP ports")

    args = parser.parse_args()
    if os.path.isdir(args.scan):
        for root, _, files in os.walk(args.scan):
            for file in files:
                preprocedure(os.path.join(root, file), args)
    elif os.path.isfile(args.scan):
        preprocedure(args.scan, args)
    else:
        print(drop_operation(f'File/Dir {args.scan} not found'))
        return
    print(info_operation('Done'))
    return


if __name__ == '__main__':
    main()
