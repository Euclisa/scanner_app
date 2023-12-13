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
    ALL_TABLES = {"event_types","events","hosts","open_ports","tor"}

    def __init__(self):
        logging.basicConfig(level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger()

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
    
    def _touch_host_addr(self, ip_addr, event_id):
        cur = self.conn.cursor()

        data = {'ip_addr': ip_addr, 'last_modified': event_id}
        sql = """INSERT INTO hosts (ip_addr, last_modified) VALUES (%(ip_addr)s, %(last_modified)s)
                ON CONFLICT (ip_addr) DO UPDATE SET last_modified = EXCLUDED.last_modified"""
        
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
        

    def fetch_onions(self):
        relays = Onionoo.details()

        cur = self.conn.cursor()

        event_id = self._create_tor_fetch_event()

        for relay in relays:
            relay_keys = list(relay.keys())
            columns_str = ', '.join(relay_keys)
            relay_keys_f = list(map(lambda x: f"%({x})s", relay_keys))
            columns_vals_str = ', '.join(relay_keys_f)
            
            self._touch_host_addr(relay['or_addr'],event_id)
            self._touch_open_port(relay['or_addr'],relay['or_port'])

            sql = f"""INSERT INTO tor 
                ({columns_str})
                VALUES ({columns_vals_str})"""
            
            
            try:
                cur.execute(sql,relay)
            except Exception as e:
                raise_error(self.logger,f"Couldn't update database from Onionoo.",e)
        
        cur.close()

        self.conn.commit()
    


if __name__ == "__main__":
    scanner = Scanner()
    scanner.fetch_onions()