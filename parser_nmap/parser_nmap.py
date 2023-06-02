import re
import argparse
import os
import sys
import struct
from socket import inet_aton
from enum import Enum

os.system("")  # enable color

version = "v1.5.2"

json_regex_types = {r'Nmap scan report for .*$': "0", r'^[0-9]*/tcp.*open.*': "0",
                    r'Aggressive OS guesses:.*': "0", r'PORT.*': "0", r'Device type:.*$': "0",
                    r'OS details:.*$': "0", "VULNERABLE:": "1"}


def test():
    return "TEST_SUCCESS"


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
    # for compare
    REG_TITLE = r'Nmap scan report for .*$'
    REG_TITLE_PORT = r'PORT.*'
    REG_TCP_PORT = r'^[0-9]*/tcp.*open.*'
    REG_AGGRESSIVE_OS = r'Aggressive OS guesses:.*'
    REG_DEVICE_TYPE = r'Device type:.*$'
    REG_OS_DETAILS = r'OS details:.*$'
    REG_VULNERABLE = r'VULNERABLE:'
    # for get value
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


def print_as_format(msg, minimal):
    if not minimal:
        print(msg)
    return


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


def parse_scan(report_nmap, ports, regex, operation, os_append=False):
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
                    if os_append and count_open_ports:
                        if ConstRegex.REG_AGGRESSIVE_OS.value == re_type\
                                or ConstRegex.REG_DEVICE_TYPE.value == re_type\
                                or ConstRegex.REG_OS_DETAILS.value == re_type:
                            if regex:
                                if is_found_line(regex, None, line_report):
                                    body.append(line_report)
                            else:
                                body.append(line_report)
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


def write_to_file(fileread, filename, data, minimal):
    with open(filename, 'a+') as writer:
        if len(data):
            writer.write(f'Analyze file: {fileread}\n')
            if type(data) is list:
                for line in data:
                    writer.write(f"{line}\n")
            elif type(data) is dict:
                if minimal:
                    for ip_str in data:
                        writer.write(f"{ip_str}\n")
                else:
                    for ip_str in data:
                        for line in data[ip_str]:
                            writer.write(f"{line}\n")
                        writer.write('\n')
            writer.write(f"Total IP parsed: {len(data)}\n\n\n\n")


def print_target(data, minimal):
    if minimal:
        print(''.join(re.findall(ConstRegex.REG_IP_FROM_TITLE.value, data[0])[-1:]))
    else:
        data[0] = header_operation(data[0])
        data[-1] = header_operation(data[-1])
        for line in data:
            print(line)
        print('')
        return


def print_scan(data, minimal=False):
    if type(data) is list:
        for line in data:
            print(line)
    elif type(data) is dict:
        for ip_str in data:
            print_target(data[ip_str], minimal)


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

# for union (mb not releasing?)
# def normalize_data(data):
#     return data


def preprocedure(file, args):
    report_nmap = open(file, 'r')
    print(info_operation(f"Analyze file: {file}"))
    parse_reg_scan = []
    if args.ip:
        if args.ip == Operation.IP_VULNERABLE.value:
            parse_reg_scan = sort_ip(parse_scan(report_nmap, None, None, Operation.IP_VULNERABLE))
        elif args.ip == Operation.IP_ALL.value:
            parse_reg_scan = sort_ip(parse_scan(report_nmap, None, None, Operation.IP_ALL))
        elif args.ip == Operation.IP_OPEN.value:
            parse_reg_scan = sort_ip(parse_scan(report_nmap, None, None, Operation.IP_OPEN))
    else:
        parse_reg_scan = parse_scan(report_nmap, get_ports(args.port), args.reg, Operation.ALL_REPORT, args.device)
        if args.target:
            if parse_reg_scan.get(args.target):
                print_target(parse_reg_scan[args.target], args.minimal)
                return
            else:
                print_as_format(drop_operation(f"IP address in {file} not found\n"), args.minimal)
                return
    if args.out:
        write_to_file(file, args.out, parse_reg_scan, args.minimal)
    else:
        print_scan(parse_reg_scan, args.minimal)
        if len(parse_reg_scan):
            print(info_operation(f"Total IP: {len(parse_reg_scan)}"))
    return


def main():
    parser = argparse.ArgumentParser(add_help=False, description="TCP Parser NMAP Normal output (-oN) " + version)
    group = parser.add_argument_group('about')
    group.add_argument('-v', '-V', '--version', action='version', version=version)
    group = parser.add_argument_group('inside')
    group.add_argument('-s', '--scan', required=True, help='directory or report scan NMAP')
    group.add_argument('-p', '--port', help='parsing for required ports')
    group.add_argument('-r', '--reg', help='regex search')
    group.add_argument('-m', '--minimal', action='store_true', help='minimal format')
    # group.add_argument('-u', '--union', action='store_true', help='union equal ip')
    group.add_argument('-d', '--device', action='store_true', help='parse OS info')
    group.add_argument('-t', '--target', help='print-parsing for one ip')
    group = parser.add_argument_group('ip only')
    group.add_argument('-i', '--ip', type=int, choices=range(1, 4), help="1 - VULNERABLE;\
                                                            2 - all;\
                                                            3 - with OPEN ports")
    group = parser.add_argument_group('out')
    group.add_argument('-o', '--out', help='generate file report')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    if args.ip:
        if args.target or args.port or args.minimal or args.reg or args.device:
            parser.print_help()
            sys.exit()

    print(info_operation('Parsing...'))
    if args.out and not args.target:
        print(info_operation(f'Generate report to {args.out} file'))
        open(args.out, 'w').close()

    if args.ip:
        if args.ip == Operation.IP_VULNERABLE.value:
            print(info_operation('VULNERABLE IP'))
        elif args.ip == Operation.IP_ALL.value:
            print(info_operation('All IP'))
        elif args.ip == Operation.IP_OPEN.value:
            print(info_operation('Open IP'))

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
