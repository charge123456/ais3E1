from flask import Flask, request, render_template
from shodan import Shodan
from nslookup import Nslookup
import json
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/find_ip', methods=['GET', 'POST'])
def find_ip():
    with open('ip-ranges.json') as f:
        data = json.load(f)
    print(type(data))
    for i in range(0, 255):
        print(data['prefixes'][i]['ip_prefix'], data['prefixes'][i]['service'])
    return 'ok'


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
