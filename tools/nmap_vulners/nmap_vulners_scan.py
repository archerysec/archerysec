import uuid

import nmap
import os
from django.conf import settings

from tools.models import nmap_vulners_port_result_db, nmap_scan_db
from archerysettings.models import nmap_vulners_setting_db


def parse_port(proto, ip_addr, host_data, scan_id, project_id):
    ports = host_data.get(proto)
    if not ports:
        return

    print('[NMAP_VULNERS][%s] Host : %s, proto %s, ports (%s)' % (scan_id, ip_addr, proto, ports))
    for port, portData in dict(ports).items():
        nmap_obj, _ = nmap_vulners_port_result_db.objects.get_or_create(ip_address=ip_addr, port=port)

        nmap_obj.protocol = proto
        nmap_obj.state = portData.get('state')
        nmap_obj.scan_id = scan_id
        nmap_obj.project_id = project_id
        nmap_obj.reason = portData.get('reason')
        nmap_obj.reason_ttl = portData.get('reason_ttl')
        nmap_obj.version = portData.get('version')
        nmap_obj.extrainfo = portData.get('extrainfo')
        nmap_obj.name = portData.get('name')
        nmap_obj.conf = portData.get('conf')
        nmap_obj.method = portData.get('method')
        nmap_obj.type_p = portData.get('type_p')
        nmap_obj.osfamily = portData.get('osfamily')
        nmap_obj.vendor = portData.get('vendor')
        nmap_obj.osgen = portData.get('osgen')
        nmap_obj.accuracy = portData.get('accuracy')
        nmap_obj.cpe = portData.get('cpe')
        nmap_obj.used_state = portData.get('used_state')
        nmap_obj.used_portid = portData.get('used_portid')
        nmap_obj.used_proto = portData.get('used_proto')
        if 'script' in portData and 'vulners' in portData.get('script'):
            nmap_obj.vulners_extrainfo = portData.get('script').get('vulners').strip('\n\t ')

        nmap_obj.save()


def run_nmap_vulners(ip_addr='', project_id=''):
    if not ip_addr:
        raise ValueError('[NMAP_VULNERS] - ip_addr must be specified')

    scan_id = uuid.uuid4()
    nv_version = ''
    nv_online = ''
    nv_timing = ''

    nmap_vulners_path = os.path.join(settings.BASE_DIR, 'tools/nmap_vulners/vulners.nse')
    all_nv = nmap_vulners_setting_db.objects.all()
    for nv in all_nv:
        nv_enabled = bool(nv.enabled)
        nv_online = bool(nv.online)
        nv_version = bool(nv.version)
        nv_timing = int(nv.timing)

    args = ''
    if nv_version:
        args += ' -sV'
    if nv_online:
        args += ' -Pn'
    if nv_timing:
        args += ' -T'+str(nv_timing)
    args += ' --script ' + nmap_vulners_path
    print('[NMAP_VULNERS][%s] - ARGUMENTS -%s' % (scan_id, args))

    nm = nmap.PortScanner()
    nm = nm.scan(hosts=ip_addr, arguments=args)
    scan = nm.get('scan')

    # Rewrite Nmap results each time
    nmap_vulners_port_result_db.objects.filter(ip_address=ip_addr).delete()

    for host, host_data in scan.items():
        print('[NMAP_VULNERS][%s] ----------------------------------------------------' % (scan_id))
        print('[NMAP_VULNERS][%s] Host : %s (%s)' % (scan_id, host, host_data.get('hostnames')))

        parse_port('tcp', host, host_data, scan_id, project_id)
        parse_port('udp', host, host_data, scan_id, project_id)

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

    print('[NMAP_VULNERS][] - END - scan of domain %s' % (scan_id, format(ip_addr)))
