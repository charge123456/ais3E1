from flask import Flask, request, render_template
from shodan import Shodan
from nslookup import Nslookup
import json
import ipaddress
# from cloud_enum
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ip_addr = request.form.get('url')

    return render_template('index.html')


@app.route('/find_ip', methods=['GET', 'POST'])
def find_ip():
    if request.method == 'POST':
        ip_addr = request.form.get('ip')
        if ip_addr == '':
            status = '請輸入 IP!'
        with open('ip-ranges.json') as f:
            data = json.load(f)
        status = 'Not Found!'
        for i in range(0, len(data['prefixes'])):
            if ipaddress.IPv4Address(ip_addr) in ipaddress.IPv4Network(data['prefixes'][i]['ip_prefix']):
                region = data['prefixes'][i]['region']
                service = data['prefixes'][i]['service']
                network_border_group = data['prefixes'][i]['network_border_group']
                status = 'Find!'
                return render_template('findservice.html',ip_addr=ip_addr,region=region,service=service,network_border_group=network_border_group,status=status )
        return render_template('findservice.html',ip_addr=ip_addr,status=status)
    return render_template('findservice.html')



@app.route('/shodan', methods=['GET', 'POST'])
def request_page_from_shodan():
    api = Shodan("FKUorAOJBIpKN7wKztrpUz5Ji7NF1rd4")
    if request.method == 'POST':
        domain_name = request.form.get('url')
        dns_query = Nslookup(dns_servers=['1.1.1.1'])
        ips_record = dns_query.dns_lookup(domain_name)
        ip = api.host(ips_record.answer)
        ports = ip['ports']
        ip = ip['ip_str']

        return render_template('url.html',domain_name=domain_name, ip=ip, ports=ports)
    return render_template('url.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
