
from flask import Flask, render_template, jsonify, request
import requests
import json
import sqlite3
import random
import string

#Conexion a la BDDD

con = sqlite3.connect('database', check_same_thread=False)

cur = con.cursor()

#Rutas
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/token', methods=['POST'])
def token():
    email = request.form.get('email')
    password = request.form.get('password')

    print(request.form)
    print(email, password)

    response = cur.execute('SELECT * FROM usuario WHERE email=? AND password=?', [email, password])

    data = cur.fetchall()

    if not len(data):
        print('Usuario no encontrado')

        return {'error': True}

    else:
        print('Usuario encontrado')

        return {'error': False, 'nombre': data[0][1], 'apellido': data[0][2], 'email': data[0][3], 'password': data[0][4],'company': data[0][5], 'address': data[0][6], 'token': data[0][7]}

@app.route('/api/gentoken', methods=['POST'])
def gentoken():
    email = request.form.get('email')
    password = request.form.get('password')

    print(request.form)
    print(email, password)

    response = cur.execute('SELECT * FROM usuario WHERE email=? AND password=?', [email, password])

    data = cur.fetchall()

    if not len(data):
        print('Usuario no encontrado')

        return {'error': True}

    else:
        print('Usuario encontrado')

        chars = string.ascii_letters + string.digits
        token = ''.join(random.choices(chars, k=6))
        
        try:
            cur.execute('UPDATE usuario SET token=? WHERE email=? AND password=?', [token, email, password])
            con.commit()

            return {'error': False}

        except Exception as e:
            return {'error': True, 'message': e}

@app.route('/api/inventario/dispositivos-de-red/')
def inventario_dispositivos_authfailed():
    token = request.args.get('token')

    if token == None:
        return  {'error': {'message': 'No se ha introducido contraseña o usuario'}}

    cur.execute('SELECT token FROM usuario WHERE token=?', [token])
    res = cur.fetchall()

    if not len(res):
        return {'error': {'message': 'Token no valido'}}


    url = 'http://192.168.56.101:8181/restconf/operational/network-topology:network-topology'

    x = requests.get(url, auth=('admin', 'admin'))

    data = json.loads(x.text)

    topology_id = data['network-topology']['topology'][0]['topology-id']
    nodes = data['network-topology']['topology'][0]['node']

    network_devices = []

    for node in nodes:
        if node['node-id'].startswith('openflow:'):
            network_devices.append(node)

    return {'topology-id': topology_id, 'networks-devices': network_devices}, 200

@app.route('/api/inventario/dispositivos-de-red/<username>/<password>')
def inventario_dispositivos(username, password):
    url = 'http://192.168.56.101:8181/restconf/operational/network-topology:network-topology'

    x = requests.get(url, auth=(username, password))

    data = json.loads(x.text)

    topology_id = data['network-topology']['topology'][0]['topology-id']
    nodes = data['network-topology']['topology'][0]['node']

    network_devices = []

    for node in nodes:
        if node['node-id'].startswith('openflow:'):
            network_devices.append(node)

    return {'topology-id': topology_id, 'networks-devices': network_devices}, 200

@app.route('/api/inventario/hosts/')
def inventario_hosts_authfailed():
    token = request.args.get('token')

    if token == None:
        return  {'error': {'message': 'No se ha introducido contraseña o usuario'}}

    cur.execute('SELECT token FROM usuario WHERE token=?', [token])
    res = cur.fetchall()

    if not len(res):
        return {'error': {'message': 'Token no valido'}}

    url = 'http://192.168.56.101:8181/restconf/operational/network-topology:network-topology'

    x = requests.get(url, auth=('admin', 'admin'))

    data = json.loads(x.text)

    topology_id = data['network-topology']['topology'][0]['topology-id']
    nodes = data['network-topology']['topology'][0]['node']

    hosts = []

    for node in nodes:
        if node['node-id'].startswith('host:'):
            hosts.append(node)

    return {'topology-id': topology_id, 'hosts': hosts}, 200

@app.route('/api/inventario/hosts/<username>/<password>')
def inventario_hosts(username, password):
    url = 'http://192.168.56.101:8181/restconf/operational/network-topology:network-topology'

    x = requests.get(url, auth=(username, password))

    data = json.loads(x.text)

    topology_id = data['network-topology']['topology'][0]['topology-id']
    nodes = data['network-topology']['topology'][0]['node']

    hosts = []

    for node in nodes:
        if node['node-id'].startswith('host:'):
            hosts.append(node)

    return {'topology-id': topology_id, 'hosts': hosts}, 200

@app.route('/api/trazar/', methods=['GET'])
def trazar_error():
    token = request.args.get('token')
    source_node = request.args.get('source_node')
    destination_node = request.args.get('destination_node')

    if token == None:
        return  {'error': {'message': 'No se ha introducido contraseña o usuario'}}

    cur.execute('SELECT token FROM usuario WHERE token=?', [token])
    res = cur.fetchall()

    if not len(res):
        return {'error': {'message': 'Token no valido'}}

    url = 'http://192.168.56.101:8181/restconf/operational/network-topology:network-topology'

    x = requests.get(url, auth=('admin', 'admin'))

    topology_data = json.loads(x.text)
    
    # Parámetros: nodos de inicio y fin
    # source_node = "host:00:00:00:00:00:01"
    # destination_node = "host:00:00:00:00:00:03"

    # Extraer nodos y enlaces
    topology = topology_data["network-topology"]["topology"][0]
    nodes = topology["node"]
    links = topology["link"]

    # Mapa para guardar las direcciones IPv4
    ipv4_map = {}

    # Extraer direcciones IPv4 de nodos host
    for node in nodes:
        if "host-tracker-service:addresses" in node:
            ipv4_map[node["node-id"]] = node["host-tracker-service:addresses"][0].get("ip", "No IPv4")

    # Crear la ruta entre nodos usando los enlaces
    def find_path(links, start, end, visited=None):
        if visited is None:
            visited = set()
        
        if start == end:
            return [start]
        
        visited.add(start)
        for link in links:
            if link["source"]["source-node"] == start and link["destination"]["dest-node"] not in visited:
                path = find_path(links, link["destination"]["dest-node"], end, visited)
                if path:
                    return [start] + path
        return None

    # Generar la ruta
    route = find_path(links, source_node, destination_node)

    routes = []

    # Mostrar la ruta con direcciones IPv4
    if route:
        print("Ruta encontrada:")
        for node in route:
            ipv4 = ipv4_map.get(node, "Sin IPv4")
            print(f"{node} -> IPv4: {ipv4}")
            routes.append({'node': node, 'IPv4': ipv4})

        return {'success': True, 'path': routes}

    else:
        print("No se encontró una ruta entre los nodos.")

        return {'success': False}

@app.route('/api/trazar-post', methods=['POST'])
def trazar():
    source_node = request.form.get('source_node')
    destination_node = request.form.get('destination_node')

    print(request.form)
    print(source_node, destination_node)

    url = 'http://192.168.56.101:8181/restconf/operational/network-topology:network-topology'

    x = requests.get(url, auth=('admin', 'admin'))

    topology_data = json.loads(x.text)
    
    # Parámetros: nodos de inicio y fin
    #source_node = "host:00:00:00:00:00:01"
    #destination_node = "host:00:00:00:00:00:03"

    # Extraer nodos y enlaces
    topology = topology_data["network-topology"]["topology"][0]
    nodes = topology["node"]
    links = topology["link"]

    # Mapa para guardar las direcciones IPv4
    ipv4_map = {}

    # Extraer direcciones IPv4 de nodos host
    for node in nodes:
        if "host-tracker-service:addresses" in node:
            ipv4_map[node["node-id"]] = node["host-tracker-service:addresses"][0].get("ip", "No IPv4")

    # Crear la ruta entre nodos usando los enlaces
    def find_path(links, start, end, visited=None):
        if visited is None:
            visited = set()
        
        if start == end:
            return [start]
        
        visited.add(start)
        for link in links:
            if link["source"]["source-node"] == start and link["destination"]["dest-node"] not in visited:
                path = find_path(links, link["destination"]["dest-node"], end, visited)
                if path:
                    return [start] + path
        return None

    # Generar la ruta
    route = find_path(links, source_node, destination_node)

    routes = []

    # Mostrar la ruta con direcciones IPv4
    if route:
        print("Ruta encontrada:")
        for node in route:
            ipv4 = ipv4_map.get(node, "Sin IPv4")
            print(f"{node} -> IPv4: {ipv4}")
            routes.append({'node': node, 'IPv4': ipv4})

        return {'success': True, 'path': routes}

    else:
        print("No se encontró una ruta entre los nodos.")

        return {'success': False}

@app.route('/api/signup/', methods=['POST'])
def signup():
    try:
        nombre  = request.form.get('nombre')
        apellido = request.form.get('apellido')
        email =  request.form.get('email')
        password = request.form.get('password')
        company = request.form.get('company')
        address = request.form.get('Address')

        print('nombre', nombre)
        print('apellido', apellido) 
        print('email', email)
        print('password', password)
        print('company', company)
        print('address', address)

        cur.execute("INSERT INTO usuario (nombre, apellido, email, password, empresa, direccion) VALUES (?, ?, ?, ?, ?, ?)", [nombre, apellido, email, password, company, address])

        con.commit()

        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': e}

@app.route('/api/login', methods=['POST'])
def login():
    print(request.form)
    email = request.form.get('email')
    password = request.form.get('password')

    print('email', email)
    print('password', password)

    res = cur.execute('SELECT * FROM usuario WHERE email=? AND password=?', [email, password])

    data = cur.fetchall()

    if not len(data):
        return {'exito': False}

    else:
        return {'exito': True, 'username': data[0][1], 'email': data[0][3], 'password': data[0][4]}
'''
    data = res.fetchall()

    for usuario in data:
        if email == usuario[3] and password == usuario[4]:
            print(usuario[3], usuario[4])
            return {'exito': True, 'username': usuario[1]}

    return {'exito': False}
'''

if __name__ == '__main__':
    app.run()
