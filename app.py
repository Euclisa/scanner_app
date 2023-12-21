from flask import Flask, render_template, redirect, url_for, request, jsonify
import psycopg2
from scanner import scanner, Scanner

app = Flask(__name__)


# Decorator checking the existence of a database.
def check_db_exists(func):
    def wrapper(*args, **kwargs):
        if not scanner.db_initialized():
            return redirect(url_for('create_db'))
        scanner.db_connect()
        
        return func(*args, **kwargs)
    return wrapper


# Decorator checking for the absence of a database.
def check_db_not_exists(func):
    def wrapper(*args, **kwargs):
        if scanner.db_initialized():
            scanner.db_connect()
            return redirect(url_for('delete_db'))
            
        return func(*args, **kwargs)
    return wrapper


# Main page
@app.route('/', endpoint='index')
@check_db_exists
def index():
    data = scanner.get_all_summary()
    if data is None:
        data = []

    return render_template('index.html', data=data)


# Database creation page.
@app.route('/create_database', methods=['GET', 'POST'], endpoint='create_db')
@check_db_not_exists
def create_db():
    if request.method == 'GET':
        return render_template('create_db.html')
    if request.method == 'POST':
        status = scanner.create_database()
        if status:
            return jsonify({"status": True, "message": "База данных создана"})
        else:
            return jsonify({"status": False, "message": "База данных не создана"})


# Database deletion page.
@app.route('/delete_db', methods=['GET', 'POST'], endpoint='delete_db')
@check_db_exists
def delete_db():
    if request.method == 'GET':
        return render_template('delete_db.html')
    if request.method == 'POST':
        status = scanner.drop_database()
        #status = True
        if status:
            return jsonify({"status": True, "message": "База данных удалена"})
        else:
            return jsonify({"status": False, "message": "База данных не удалена"})


# Search by IP-address page.
@app.route('/ip_search', methods=['GET', 'POST'], endpoint='ip_search')
@check_db_exists
def ip_search():
    message = None
    if request.method == 'POST':
        ip_address = request.form['ipAddress']

        entries_updated = scanner.fetch_host_info_from_tor(ip_address)

        if entries_updated > 0:
            message = "Адрес " + str(ip_address) + f" обновлен. Обновлено {entries_updated} вхождений."
        else:
            message = f"Информация об '{ip_address}' не найдена."

    return render_template('ip_search.html', message=message)


# Search by IP-address page.
@app.route('/mass_search', methods=['GET', 'POST'], endpoint='mass_search')
@check_db_exists
def mass_search():
    message = None
    if request.method == 'POST':
        entries_updated = scanner.fetch_onions()

        if entries_updated > 0:
            message = f"Обновлено {entries_updated} вхождений."
        else:
            message = f"Информация не найдена."

    return render_template('mass_search.html', message=message)


# Search by filters page.
@app.route('/filter_search', methods=['GET', 'POST'], endpoint='filter_search')
@check_db_exists
def filter_search():
    results = None
    if request.method == 'POST':
        filtr = Scanner.select_filter()

        onion_routing = request.form.get('tor')
        filtr.set_onion_routing_filter(onion_routing == 'on')

        ip = request.form.get('ipAddressHidden')
        port = request.form.get('portHidden')
        country = request.form.get('countryHidden')

        for element in port.split(','):
            if element:
                filtr.add_port_to_filter(int(element))
        
        for element in ip.split(','):
            if element:
                filtr.add_ip_to_filter(element)

        for element in country.split(','):
            if element:
                filtr.add_country_to_filter(element)

        results = scanner.get_filtered_summary(filtr)

    return render_template('filter_search.html', results=results)


# Function for deleting rows in filter_search page.
@app.route('/delete_record', methods=['POST'], endpoint='delete_record')
def delete_record():
    if request.method == 'POST':
        ip_addr = request.json.get('ip_addr')

        status = scanner.delete_host(ip_addr)

        if status:
            return jsonify({"status": True, "message": "Запись удалена"})
        else:
            return jsonify({"status": False, "message": "Запись не удалена"})


# Clear tables page.
@app.route('/clear_tables', methods=['GET', 'POST'], endpoint='clear_tables')
@check_db_exists
def clear_tables():
    if request.method == 'GET':
        return render_template('clear_tables.html')
    if request.method == 'POST':
        status = scanner.clear_tables()

        if status:
            return jsonify({"status": True, "message": "Таблицы удалены"})
        else:
            return jsonify({"status": False, "message": "Таблицы не удалены"})


# Clear IP-address page.
@app.route('/clear_ip', methods=['GET', 'POST'], endpoint='clear_ip')
@check_db_exists
def clear_ip():
    if request.method == 'GET':
        return render_template('clear_ip.html')
    if request.method == 'POST':
        ip_address = request.json.get('ipAddress')
        status = scanner.delete_host(ip_address)
        if status:
            return jsonify({"status": True, "message": "IP-адрес удален"})
        else:
            return jsonify({"status": False, "message": "IP-адрес не удален"})


if __name__ == '__main__':
    app.run()
