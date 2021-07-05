import xml.etree.ElementTree as ET

tree = ET.parse('nessus-multi.xml')

root = tree.getroot()

for data in root:
    # for d in data:
    #     if d.tag == 'ReportHost':
    #         host = d.attrib['name']

    for reportHost in data.iter("ReportHost"):
        try:
            for key, value in reportHost.items():
                target = value
        except:
            continue
        for ReportItem in reportHost.iter("ReportItem"):
            for key, value in ReportItem.attrib.items():
                if key == "pluginName":
                    pluginName = value
                    # print ("pluginName = "+str(value))
                if key == "pluginID":
                    pluginID = value
                    # print ("pluginID = "+str(value))
                if key == "protocol":
                    protocol = value
                    # print ("protocol = "+str(value))
                if key == "severity":
                    severity = value
                    # print ("severity = "+str(value))
                if key == "svc_name":
                    svc_name = value
                    # print ("svc_name = "+str(value))
                if key == "pluginFamily":
                    pluginFamily = value
                    # print ("pluginFamily = "+str(value))
                if key == "port":
                    port = value
                    # print ("port = "+str(value))

            try:
                agent = ReportItem.find("agent").text
            except:
                agent = "NA"
            try:
                description = ReportItem.find("description").text
            except:
                description = "NA"
            try:
                fname = ReportItem.find("fname").text
            except:
                fname = "NA"
            try:
                plugin_modification_date = ReportItem.find(
                    "plugin_modification_date"
                ).text
            except:
                plugin_modification_date = "NA"
            try:
                plugin_name = ReportItem.find("plugin_name").text
            except:
                plugin_name = "NA"
            try:
                plugin_publication_date = ReportItem.find(
                    "plugin_publication_date"
                ).text
            except:
                plugin_publication_date = "NA"
            try:
                plugin_type = ReportItem.find("plugin_type").text
            except:
                plugin_type = "NA"
            try:
                risk_factor = ReportItem.find("risk_factor").text
            except:
                risk_factor = "NA"
            try:
                script_version = ReportItem.find("script_version").text
            except:
                script_version = "NA"
            try:
                see_also = ReportItem.find("see_also").text
            except:
                see_also = "NA"
            try:
                solution = ReportItem.find("solution").text
            except:
                solution = "NA"
            try:
                synopsis = ReportItem.find("synopsis").text
            except:
                synopsis = "NA"
            try:
                plugin_output = ReportItem.find("plugin_output").text
            except:
                plugin_output = "NA"
            print(plugin_name)