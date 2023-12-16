import requests
import time
import psycopg2
import os
import json
import logging
from datetime import datetime
from error import raise_error
from providers.onionoo import Onionoo


class Scanner:

    UPDATE_INT = 3600
    CONFIG_PATH = 'config.json'
    ALL_TABLES = {"event_types","events","edit_labels","hosts","open_ports","onion_routing_hosts","tor_exit_hosts"}

    def __init__(self):
        logging.basicConfig(level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger()

        self.onionoo = Onionoo()

        self._read_config()

        try:
            self.conn = psycopg2.connect(database=self.db_name,
                                        user=self.db_user,
                                        password=self.db_password
                                    )
        except psycopg2.Error as e:
            raise_error(self.logger,f"Connection to database '{self.db_name}' failed. Details: {str(e)}")
        
        if self._check_db_clean():
            self._setup_db()
    

    def _setup_db(self):
        cr = self.conn.cursor()

        with open('setup.sql', 'r') as f:
            setup_sql = f.read()

        try:
            cr.execute(setup_sql)
        except Exception as e:
            raise_error(self.logger,f"Could not initialize tables. {e}")
        finally:
            cr.close()
        self.conn.commit()
    

    def _check_db_clean(self):
        tables_present_flags = []
        for table in Scanner.ALL_TABLES:
            tables_present_flags.append(self._table_exists(table))

        if all(tables_present_flags):
            self.logger.debug("All tables were found.")
            return False
        if not any(tables_present_flags):
            self.logger.debug("No tables were found. Database is clean.")
            return True
        raise_error(self.logger,f"Database is partially populated. Some tables are missing or corrupted.")

    

    def _table_exists(self,table_name):
        cur = self.conn.cursor()
    
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s);",
            (table_name,)
        )

        res = cur.fetchone()[0]

        cur.close()

        return res

    def _read_config(self):
        with open(Scanner.CONFIG_PATH,'r') as f:
            config_json = json.loads(f.read())
        self.db_name = config_json['db_name']
        self.db_user = config_json['db_user']
        self.db_password = config_json['db_password']
        self.db_host = config_json['host']
        self.db_port = int(config_json['port'])
    

    def _create_tor_fetch_event(self):
        cur = self.conn.cursor()

        ts = datetime.now()
        event_values = {'ts': ts, 'event_name': "tor_fetch", 'user_name': self.db_user}
        event_sql = "INSERT INTO events (ts, event_name, user_name) VALUES (%(ts)s, %(event_name)s, %(user_name)s) RETURNING id"
        cur.execute(event_sql,event_values)
        event_id = cur.fetchone()[0]

        cur.close()

        return event_id
    
    def _touch_host_addr(self, ip_addr, event_id, edit_label):
        cur = self.conn.cursor()

        data = {'ip_addr': ip_addr, 'last_modified': event_id, 'edit_label': edit_label}
        sql = """INSERT INTO hosts (ip_addr, last_modified_event, last_modified_label) VALUES (%(ip_addr)s, %(last_modified)s, %(edit_label)s)
                ON CONFLICT (ip_addr) DO UPDATE SET last_modified_event = EXCLUDED.last_modified_event, last_modified_label = EXCLUDED.last_modified_label"""
        
        try:
            cur.execute(sql,data)
        except Exception as e:
            raise_error(self.logger,f"Could not touch host addr '{ip_addr}' for event id '{event_id}'.",e)

        cur.close()
    

    def _touch_open_port(self, ip_addr, port, banner=""):
        cur = self.conn.cursor()

        data = {'ip_addr': ip_addr, 'port': port, 'banner': banner}
        sql = """INSERT INTO open_ports (ip_addr, port, banner) VALUES (%(ip_addr)s, %(port)s, %(banner)s)
                ON CONFLICT (ip_addr,port) DO UPDATE SET banner = EXCLUDED.banner"""
        
        try:
            cur.execute(sql,data)
        except Exception as e:
            raise_error(self.logger,f"Could not touch open ports entry for {ip_addr}:{port}.",e)

        cur.close()
    

    def _insert_onion_routing(self, relay):
        cur = self.conn.cursor()

        relay_keys = list(relay.keys())
        columns_str = ', '.join(relay_keys)
        relay_keys_f = list(map(lambda x: f"%({x})s", relay_keys))
        columns_vals_str = ', '.join(relay_keys_f)

        sql = f"""INSERT INTO onion_routing_hosts 
            ({columns_str})
            VALUES ({columns_vals_str})"""
        
        
        try:
            cur.execute(sql,relay)
        except Exception as e:
            raise_error(self.logger,f"Couldn't update database from Onionoo.",e)
        
        cur.close()
    

    def _update_onion_routing(self, relay, event_id):
        or_addr = relay['or_addr']
        or_port = relay['or_port']
        exit_addresses = relay.pop('exit_addresses',None)

        self._touch_host_addr(relay['or_addr'],event_id,'OR')

        cur = self.conn.cursor()

        cur.execute("BEGIN")

        # Delete exit host with corresponding or address

        sql = """DELETE FROM tor_exit_hosts WHERE or_addr = %s"""

        try:
            cur.execute(sql,(or_addr,))
        except:
            raise_error(self.logger,f"Could not delete tor exit hosts bound to {or_addr}.",e)

        
        # Delete onion-routing entry itself

        sql = """DELETE FROM onion_routing_hosts WHERE or_addr = %s"""

        try:
            cur.execute(sql,(or_addr,))
        except:
            raise_error(self.logger,f"Could not delete onion-routing hosts with address '{or_addr}' for reinsertion.",e)
        

        # Finally, delete corresponding open_ports entry. All this for further reinsertion

        sql = """DELETE FROM open_ports WHERE ip_addr = %s AND onion_routing IS TRUE"""
        
        try:
            cur.execute(sql,(or_addr,))
        except Exception as e:
            raise_error(self.logger,f"Could not delete onion-routing open ports for {or_addr}.",e)
    
        
        # Commence insertion in reverse order. Ports first.

        sql = """INSERT INTO open_ports (ip_addr, port, onion_routing) VALUES (%s, %s, TRUE)"""

        try:
            cur.execute(sql,(or_addr,or_port))
        except Exception as e:
            raise_error(self.logger,f"Could not insert onion-routing open port '{ip_addr}:{port}'.",e)

        
        # Then onion-routing info

        self._insert_onion_routing(relay)

        # At last, reinsert exit addresses

        if exit_addresses is not None:
            for exit_addr in exit_addresses:
                self._insert_tor_exit_host(exit_addr,or_addr,event_id)
        

        cur.execute('COMMIT')

        cur.close()
    

    def _insert_tor_exit_host(self, exit_addr, or_addr, event_id):
        cur = self.conn.cursor()

        self._touch_host_addr(exit_addr,event_id,'TE')

        sql = """INSERT INTO tor_exit_hosts (exit_addr, or_addr) VALUES (%s, %s)"""

        try:
            cur.execute(sql,(exit_addr, or_addr))
        except Exception as e:
            raise_error(self.logger,f"Could not touch tor exit information for '{exit_addr}'.",e)
        
        cur.close()


    def fetch_onions(self):
        relays = self.onionoo.details()
        event_id = self._create_tor_fetch_event()

        for relay in relays:
            self._update_onion_routing(relay,event_id)

        self.conn.commit()
    

    def fetch_host_info_from_tor(self, ip_addr):
        pass
    


if __name__ == "__main__":
    scanner = Scanner()
    scanner.fetch_onions()