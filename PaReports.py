import requests
import warnings
# noinspection PyPep8Naming,PyPep8Naming
import xml.etree.ElementTree as et
import csv
import arrow
import time
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import os
import pandas as pd
LOG_FILENAME = ""
key = ""
url = ""
reportnamme = ["DailyDroppedThreats","CountryanIOCDroppedThreats"]
report2 = ["-DailyDroppedThreats.csv","-CountryanIOCDroppedThreats.csv"]
path = ""

def write_csv(pathfile,head1,head2,meta1,meta2):
    with open(pathfile, 'a', newline='') as f:
        csvwriter = csv.writer(f)
        head = [head1, head2]
        csvwriter.writerow(head)
        for child in root2:
            for subchild in child:
                for subsubchild in subchild.findall("entry"):
                    row = []
                    data1 = subsubchild.find(meta1).text
                    data2 = subsubchild.find(meta2).text
                    row.append(data1)
                    row.append(data2)
                    csvwriter.writerow(row)
    f.close()
def email_send(total,total_3):
    from_addr = ""
    to_addr = ""
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = "PaloAlto Metrics"
    body = "PaloAlto: %s and PaloAlto Geo: %s" % (total, total_3)
    msg.attach(MIMEText(body, 'plain'))
    text55 = msg.as_string()
    server = smtplib.SMTP("smtp.stuff.com", 25)
    server.sendmail("", "", text55)
    server.quit()
    logging.info('email sent')
if __name__ == '__main__':
    logging.basicConfig(filename=LOG_FILENAME, level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
    # get current date and subtract 1 day and change date format
    nv = arrow.now()
    date = nv.shift(days=-1).format('YYYYMMDD')
    warnings.filterwarnings('ignore', 'Unverified HTTPS request')


    for report in reportnamme:
            querystring = {
                "key": key,
                "type": "report", "async": "yes", "reporttype": "custom", "reportname": report, }
            root = ''
            while root =='':
                response = requests.get(url, params=querystring, verify=False)
                root = et.fromstring(response.text)
                for elem in root:
                    for subelm in elem:
                        code1 = subelm.text

            querystring2 = {
                "key": key,
                "type": "report", "async": "yes", "reporttype": "custom", "reportname": report, "job-id": code1,
                'action': 'get'}
            response2 = requests.get(url, params=querystring2, verify=False)
            root2 = et.fromstring(response2.text)

            if report == "DailyDroppedThreats":
                if os.path.exists(path+date+"-DailyDroppedThreats.csv") == True:
                    os.remove(path+date+"-DailyDroppedThreats.csv")
                    write_csv(pathfile=path + date + "-DailyDroppedThreats.csv", head1="Threat ID", head2="Count",
                    meta1="threatid", meta2="repeatcnt")
                    logging.info('read CSV and Index files')
                    df1 = pd.read_csv(path + date + "-DailyDroppedThreats.csv", sep=',')
                    df2 = df1.set_index("Threat ID")
                    total_1 = df2['Count'].sum()
                else:
                    write_csv(pathfile=path + date + "-DailyDroppedThreats.csv", head1="Threat ID", head2="Count",
                    meta1="threatid", meta2="repeatcnt")
                    logging.info('read CSV and Index files')
                    df1 = pd.read_csv(path + date + "-DailyDroppedThreats.csv", sep=',')
                    df2 = df1.set_index("Threat ID")
                    total_1 = df2['Count'].sum()
            else:
                if os.path.exists(path+date+"-CountryanIOCDroppedThreats.csv") == True:
                    os.remove(path+date+"-CountryanIOCDroppedThreats.csv")
                    write_csv(pathfile = path+date+"-CountryanIOCDroppedThreats.csv", head1="Rule", head2 ="Count",
                    meta1 = "rule", meta2 = "repeatcnt")
                    df3 = pd.read_csv(path + date + "-CountryanIOCDroppedThreats.csv", sep=',')
                    df4 = df3.set_index("Rule")
                    logging.info('Starting first set of formulas')
                    cell01 = df4.at["External-Dynamic-Block-Outbound", "Count"]
                    cell2 = df4.at["External-Dynamic-Block-Inbound", "Count"]
                    cell3 = df4.at["Country Code Blocks Destination", "Count"]
                    cell4 = df4.at["Country Code Blocks Source", "Count"]
                else:
                    write_csv(pathfile=path + date + "-CountryanIOCDroppedThreats.csv", head1="Rule", head2="Count",
                    meta1="rule", meta2="repeatcnt")
                    df3 = pd.read_csv(path + date + "-CountryanIOCDroppedThreats.csv", sep=',')
                    df4 = df3.set_index("Rule")
                    logging.info('Starting first set of formulas')
                    cell01 = df4.at["External-Dynamic-Block-Outbound", "Count"]
                    cell2 = df4.at["External-Dynamic-Block-Inbound", "Count"]
                    cell3 = df4.at["Country Code Blocks Destination", "Count"]
                    cell4 = df4.at["Country Code Blocks Source", "Count"]

# ADD cell values that I need
logging.info('Starting Second set of formulas')
total_3 = int(cell3) + int(cell4)
total_2 = int(cell01) + int(cell2)
total = int(total_2) + int(total_1)
email_send(total,total_3)