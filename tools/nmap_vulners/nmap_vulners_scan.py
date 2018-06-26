import uuid

import nmap
import os

from tools.models import nmap_vulners_port_result_db, nmap_scan_db


def parse_port(proto, ip_addr, host_data):
    ports = host_data.get(proto)
    if not ports:
        return

    for port, portData in dict(ports).items():
        print('[NMAP_VULNERS] Host : %s ports (%s)' % (ip_addr, ports))
        nmap_obj, _ = nmap_vulners_port_result_db.objects.get_or_create(ip_address=ip_addr, port=port)
        # nmap_obj.ip_address = ip_addr
        nmap_obj.protocol = proto
        nmap_obj.state = portData.get('state')
        if 'script' in portData and 'vulners' in portData.get('script'):
            nmap_obj.vulners_extrainfo = portData.get('script').get('vulners').strip('\n\t ')
        nmap_obj.save()


def run_nmap_vulners(ip_addr='', project_id=''):
    if not ip_addr:
        raise ValueError('[NMAP_VULNERS] - ip_addr must be specified')

    scan_id = uuid.uuid4()

    nmap_vulners_path = os.path.join(os.getcwd(), 'tools/nmap_vulners/vulners.nse')
    args = '-sV -T4 -Pn --script ' + nmap_vulners_path
    print('[NMAP_VULNERS] - ARGUMENTS -' + args)

    nm = nmap.PortScanner()
    nm = nm.scan(hosts=ip_addr, arguments=args)
    scan = nm.get('scan')

    # Rewrite Nmap results each time
    nmap_vulners_port_result_db.objects.filter(ip_address=ip_addr).delete()

    for host, host_data in scan.items():
        print('[NMAP_VULNERS] ----------------------------------------------------')
        print('[NMAP_VULNERS] Host : %s (%s)' % (host, host_data.get('hostnames')))

        parse_port('tcp', host, host_data)
        parse_port('udp', host, host_data)

        all_data = nmap_vulners_port_result_db.objects.filter(ip_address=host)
        # for a in all_data:
        #     global total_ports, ports_p
        #     ports_p = a.port
        total_ports = len(all_data)
        # print(total_ports)

        all_open_p = nmap_vulners_port_result_db.objects.filter(ip_address=host,
                                                   state='open')
        # for p in all_open_p:
        #     global total_open_p
        total_open_p = len(all_open_p)
        # print(total_open_p)

        all_close_p = nmap_vulners_port_result_db.objects.filter(ip_address=host,
                                                    state='closed')
        total_close_p = len(all_close_p)

        save_scan = nmap_scan_db(scan_id=scan_id,
                                 project_id=project_id,
                                 scan_ip=host,
                                 total_ports=total_ports,
                                 total_open_ports=total_open_p,
                                 total_close_ports=total_close_p,
                                 )
        save_scan.save()

    print('[NMAP_VULNERS] - END - scan of domain {0}'.format(ip_addr))
