from flask import Flask, request, render_template
from shodan import Shodan
from nslookup import Nslookup
import json
import ipaddress
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/find_ip', methods=['GET', 'POST'])
def find_ip():
    if request.method == 'POST':
        a = request.form.get('ip')
        print(a)
        with open('ip-ranges.json') as f:
            data = json.load(f)

        ip_range = []
        for i in range(0, len(data['prefixes'])):
            ip_range.append(data['prefixes'][i]['ip_prefix'])
        for j in range(0, len(ip_range)):
            if a == ipaddress.IPv4Network(ip_range[j]):
                print(ip_range[j])
                print(data['prefixes'][j]['service'])
        else:
            print('NO cloud')
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

        return render_template('url.html', ip=ip, ports=ports)
    return render_template('url.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
