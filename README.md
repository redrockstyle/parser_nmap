# Parser NMAP по запросам страждущих

```
TCP Parser NMAP v1.3.0

options:
  -h, --help            show this help message and exit
  -v, -V, --version     show program's version number and exit
  -s SCAN, --scan SCAN  report scan NMAP
  -o OUTPUT, --output OUTPUT
                        generate file report
  -t TARGET, --target TARGET
                        print-parsing for one ip
  -p PORTS, --ports PORTS
                        parsing for required ports
  -r REGEX, --regex REGEX
                        regex search to string port
  -i {1,2,3}, --ip {1,2,3}
                        output ip: 1 - for VULNERABLE ip; 2 - for ALL ip; 3 - for ip with OPEN TCP ports
```

### Для особо одаренных
| Аргумент -i   | Действие                         |
| ------------- | -------------------------------- |
| 1             | Вывод ip помеченные VULNERABLE   |
| 2             | Вывод всех ip в отчете           |
| 3             | Вывод ip с открытыми TCP портами |
