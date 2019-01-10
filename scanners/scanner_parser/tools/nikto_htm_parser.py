from bs4 import BeautifulSoup
from tools.models import nikto_vuln_db
import uuid
import hashlib


def nikto_html_parser(data, project_id, scan_id):
    discription = 'None'
    targetip = 'None'
    hostname = 'None'
    port = 'None'
    uri = 'None'
    httpmethod = 'None'
    testlinks = 'None'
    osvdb = 'None'
    soup = BeautifulSoup(data, 'html.parser')

    for link in soup.find_all(class_='dataTable'):
        # print "------------------------"
        table_rows = link.find_all('tr')
        for tr in table_rows:
            for tt in tr.find_all(class_='column-head'):
                if tt.text == 'Description':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "Description:", ttt.text
                    discription = ttt.text
                if tt.text == 'Target IP':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "Target IP", ttt.text
                    targetip = ttt.test
                if tt.text == 'Target hostname':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "Target hostname", ttt.text
                    hostname = ttt.text
                if tt.text == 'Target Port':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "Target Port", ttt.text
                    port = ttt.text

                if tt.text == 'URI':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "URI:", ttt.text
                    uri = ttt.text
                if tt.text == 'HTTP Method':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "HTTP Method:", ttt.text
                    httpmethod = ttt.text
                if tt.text == 'Test Links':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "Test Links:", ttt.text
                    testlinks = ttt.text
                if tt.text == 'OSVDB Entries':
                    for ttt in tr.find_all('td'):
                        for tttt in ttt.find_all('b'):
                            del tttt
                    # print "OSVDB Entries:", ttt.text
                    osvdb = ttt.text

        vuln_id = uuid.uuid4()

        dup_data = discription + hostname
        duplicate_hash = hashlib.sha256(dup_data).hexdigest()

        match_dup = nikto_vuln_db.objects.filter(
            dup_hash=duplicate_hash).values('dup_hash').distinct()
        lenth_match = len(match_dup)

        if lenth_match == 1:
            duplicate_vuln = 'Yes'
        elif lenth_match == 0:
            duplicate_vuln = 'No'
        else:
            duplicate_vuln = 'None'

        false_p = nikto_vuln_db.objects.filter(
            false_positive_hash=duplicate_hash)
        fp_lenth_match = len(false_p)

        global false_positive
        if fp_lenth_match == 1:
            false_positive = 'Yes'
        elif lenth_match == 0:
            false_positive = 'No'
        else:
            false_positive = 'No'

        dump_data = nikto_vuln_db(
            vuln_id=vuln_id,
            scan_id=scan_id,
            project_id=project_id,
            discription=discription,
            targetip=targetip,
            hostname=hostname,
            port=port,
            uri=uri,
            httpmethod=httpmethod,
            testlinks=testlinks,
            osvdb=osvdb,
            false_positive=false_positive,
            dup_hash=duplicate_hash,
            vuln_duplicate=duplicate_vuln,
            vuln_status = 'Open',

        )
        dump_data.save()
