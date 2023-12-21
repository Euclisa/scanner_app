from flask import Flask, render_template, redirect, url_for, request, jsonify
import psycopg2
from scanner import Scanner

app = Flask(__name__)
scanner = Scanner()
if not scanner.db_connect():
    raise RuntimeError("Failed to connect to database.")


# Decorator checking the existence of a database.
def check_db_exists(func):
    def wrapper(*args, **kwargs):
        if not scanner.db_initialized():
            return redirect(url_for('create_db'))
        
        return func(*args, **kwargs)
    return wrapper


# Decorator checking for the absence of a database.
def check_db_not_exists(func):
    def wrapper(*args, **kwargs):
        if scanner.db_initialized():
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
# @check_db_not_exists
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
        status = scanner.create_database()
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

        filtr = Scanner.select_filter()
        filtr.add_ip_to_filter(ip_address)

        status = scanner.get_filtered_summary(filtr)

        if status:
            message = "Адрес " + str(ip_address) + " найден в базе данных"
        else:
            message = "Адрес " + str(ip_address) + " не найден в базе данных"

    return render_template('ip_search.html', message=message)


# Search by filters page.
@app.route('/filter_search', methods=['GET', 'POST'], endpoint='filter_search')
@check_db_exists
def filter_search():
    results = None
    if request.method == 'POST':
        filtr = Scanner.select_filter()

        onion_routing = request.form.get('tor')
        filtr.set_onion_routing_filter(onion_routing == 'on')

        port = request.form.get('port')
        if port:
            filtr.add_port_to_filter(int(port))
        
        ip_addr = request.form.get('ipAddress')
        if ip_addr:
            filtr.add_ip_to_filter(ip_addr)

        country = request.form.get('country')
        if ip_addr:
            filtr.add_country_to_filter(country)

        results = scanner.get_filtered_summary(filtr)

    return render_template('filter_search.html', results=results)


# Function for deleting rows in filter_search page.
@app.route('/delete_record', methods=['POST'], endpoint='delete_record')
def delete_record():
    if request.method == 'POST':
        ip_addr = request.form.get('ip_addr')
        # status = scanner.delete_host(ip_addr)
        status = True
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
        # status = scanner.clear_tables()
        status = True
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
        ip_address = request.form.get('ipAddress')
        # status = scanner.delete_host(ip_address)
        status = True
        if status:
            return jsonify({"status": True, "message": "IP-адрес удален"})
        else:
            return jsonify({"status": False, "message": "IP-адрес не удален"})


if __name__ == '__main__':
    app.run(debug=True)
