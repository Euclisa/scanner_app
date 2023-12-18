import requests
import time
import psycopg2
import os
import json
import logging
import re
from datetime import datetime
from error import raise_error
from providers.onionoo import Onionoo


class Scanner:

    UPDATE_INT = 3600
    CONFIG_PATH = 'config.json'
    ALL_TABLES = {"event_types","events","edit_labels","hosts","open_ports","onion_routing_hosts","tor_exit_hosts"}

    class select_filter:

        _FILTRED_ENTRY_QUERY = """SELECT h.ip_addr, p.port, o.or_port, o.contact, o.running, o.country, o.nickname, t.exit_addr FROM hosts h
                        LEFT JOIN onion_routing_hosts o ON h.ip_addr = o.or_addr
                        LEFT JOIN open_ports p ON h.ip_addr = p.ip_addr
                        LEFT JOIN tor_exit_hosts t ON t.exit_addr = h.ip_addr
                        """

        def __init__(self):
            self._ip_addrs = None
            self._ports = set([])
            self._onion_routing = None
            self._countries = None
        
        
        def add_ip_to_filter(self, ip_addr: str) -> bool:
            def is_valid_ipv4():
                ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                return bool(re.match(ipv4_pattern, ip_addr))

            if is_valid_ipv4():
                if self._ip_addrs is None:
                    self._ip_addrs = set([ip_addr])
                else:
                    self._ip_addrs.add(ip_addr)
                return True
    
            return False
        
        def add_port_to_filter(self, port: int) -> bool:
            def is_valid_port():
                return port > 0 and port < 65536
            
            if is_valid_port():
                if self._ports is None:
                    self._ports = set([port])
                else:
                    self._ports.add(port)
                return True
    
            return False
        
        def set_onion_routing_filter(self, onion_routing: bool) -> bool:
            self._onion_routing = onion_routing
            
            return True
        
        def add_country_to_filter(self, country: str):
            def is_valid_county_code():
                return len(country) == 2
            
            if is_valid_county_code():
                if self._countries is None:
                    self._countries = set([country])
                else:
                    self._countries.add(country)
                return True
            
            return False
        
        
        def render_select_query(self):
            sql = Scanner.select_filter._FILTRED_ENTRY_QUERY
            
            filters = []

            if self._ip_addrs is not None:
                ip_filters = [f"h.ip_addr = '{ip}'" for ip in self._ip_addrs]
                ip_filters_str = '(' + ' OR '.join(ip_filters) + ')'
                filters.append(ip_filters_str)
            if self._ports:
                ports_filters = [f"p.port = {str(p)}" for p in self._ports]
                ports_filters_str = '(' + ' OR '.join(ports_filters) + ')'
                filters.append(ports_filters_str)
            if self._onion_routing is not None:
                onion_routing_filter_str = "o.or_port IS "
                onion_routing_filter_str += "NOT " if self._onion_routing else ""
                onion_routing_filter_str += "NULL"
                filters.append(onion_routing_filter_str)
            if self._countries is not None:
                country_filters = [f"o.country = '{c}'" for c in self._countries]
                country_filters_str = '(' + ' OR '.join(country_filters) + ')'
                filters.append(country_filters_str)
            
            if filters:
                sql += "WHERE " + ' AND '.join(filters)
            
            return sql


        


    def __init__(self):
        logging.basicConfig(level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger()

        self.onionoo = Onionoo()

        self._read_config()

        self.conn = None
    

    def _setup_db(self):

        with self.conn.cursor() as cur:
            with open('setup.sql', 'r') as f:
                setup_sql = f.read()

            try:
                cur.execute(setup_sql)
            except Exception as e:
                raise_error(self.logger,f"Could not initialize tables. {e}")


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

        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s);",
                (table_name,)
            )

            res = cur.fetchone()[0]

        return res

    def _read_config(self):
        with open(Scanner.CONFIG_PATH,'r') as f:
            config_json = json.loads(f.read())
        self.db_name = config_json['db_name']
        self.db_user = config_json['db_user']
        self.db_password = config_json['db_password']
        self.db_host = config_json['host']
        self.db_port = int(config_json['port'])
        self.superuser_name = config_json['superuser_name']
        self.superuser_password = config_json['superuser_password']
    

    def _create_tor_fetch_event(self):

        with self.conn.cursor() as cur:
            ts = datetime.now()
            event_values = {'ts': ts, 'event_name': "tor_fetch", 'user_name': self.db_user}
            event_sql = "INSERT INTO events (ts, event_name, user_name) VALUES (%(ts)s, %(event_name)s, %(user_name)s) RETURNING id"
            cur.execute(event_sql,event_values)
            event_id = cur.fetchone()[0]

        return event_id
    
    def _touch_host_addr(self, ip_addr, event_id, edit_label):

        with self.conn.cursor() as cur:
            data = {'ip_addr': ip_addr, 'last_modified': event_id, 'edit_label': edit_label}
            sql = """INSERT INTO hosts (ip_addr, last_modified_event, last_modified_label) VALUES (%(ip_addr)s, %(last_modified)s, %(edit_label)s)
                    ON CONFLICT (ip_addr) DO UPDATE SET last_modified_event = EXCLUDED.last_modified_event, last_modified_label = EXCLUDED.last_modified_label"""
            
            try:
                cur.execute(sql,data)
            except Exception as e:
                raise_error(self.logger,f"Could not touch host addr '{ip_addr}' for event id '{event_id}'.",e)
    

    def _touch_open_port(self, ip_addr, port, banner=""):

        with self.conn.cursor() as cur:
            data = {'ip_addr': ip_addr, 'port': port, 'banner': banner}
            sql = """INSERT INTO open_ports (ip_addr, port, banner) VALUES (%(ip_addr)s, %(port)s, %(banner)s)
                    ON CONFLICT (ip_addr,port) DO UPDATE SET banner = EXCLUDED.banner"""
            
            try:
                cur.execute(sql,data)
            except Exception as e:
                raise_error(self.logger,f"Could not touch open ports entry for {ip_addr}:{port}.",e)
    

    def _insert_onion_routing(self, relay):

        with self.conn.cursor() as cur:
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
    

    def _update_onion_routing(self, relay, event_id):
        or_addr = relay['or_addr']
        or_port = relay['or_port']
        exit_addresses = relay.pop('exit_addresses',None)

        self._touch_host_addr(relay['or_addr'],event_id,'OR')

        with self.conn.cursor() as cur:
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
    

    def _insert_tor_exit_host(self, exit_addr, or_addr, event_id):

        with self.conn.cursor() as cur:
            self._touch_host_addr(exit_addr,event_id,'TE')

            sql = """INSERT INTO tor_exit_hosts (exit_addr, or_addr) VALUES (%s, %s)"""

            try:
                cur.execute(sql,(exit_addr, or_addr))
            except Exception as e:
                raise_error(self.logger,f"Could not touch tor exit information for '{exit_addr}'.",e)


    def fetch_onions(self):
        relays = self.onionoo.details()
        event_id = self._create_tor_fetch_event()

        for relay in relays:
            self._update_onion_routing(relay,event_id)

        self.conn.commit()
    

    def fetch_host_info_from_tor(self, ip_addr):
        pass
    

    def _get_superuser_connection(self):
        try:
            super_conn = psycopg2.connect(user=self.superuser_name,
                                        password=self.superuser_password)
        except Exception as e:
            raise_error(self.logger,f"Connection to superuser of psql failed.",e)
        
        return super_conn


    def db_initialized(self):
        try:
            if self.conn is not None:
                return True
            
            with self._get_superuser_connection() as super_conn:
                with super_conn.cursor() as cur:
                    cur.execute("""SELECT datname FROM pg_database WHERE datname = %s""",(self.db_name,))

                    return cur.fetchone() is not None

        except Exception as e:
            raise_error(self.logger,f"Failed to check for db existence.",e)
    

    def db_connect(self) -> bool:
        try:
            if self.conn is not None:
                return True

            if not self.db_initialized():
                msg = f"Database '{self.db_name}' does not exist. Details: {str(e)}"
                return False
    
            try:
                self.conn = psycopg2.connect(user=self.db_user,
                                            password=self.db_password,
                                            database=self.db_name)
            except Exception as e:
                msg = f"Database '{self.db_name}' exists but failed to connect. Details: {e}"
                return False
            
            try:
                is_db_clean = self._check_db_clean()
            except:
                msg = f"Failed to connect to database. Database is corrupted. Details: {str(e)}"
                return False
            
            if is_db_clean:
                self._setup_db()
            
        except Exception as e:
            msg = f"Failed to connect to database '{self.db_name}'. Details: {str(e)}"
            return False
        
        return True
    

    def drop_database(self):
        try:
            with self._get_superuser_connection() as super_conn:
                with super_conn.cursor() as cur:
                    cur.execute("""DROP DATABASE %s""",(self.db_name,))
                super_conn.commit()

        except Exception as e:
            msg = f"Failed to drop database {self.db_name}. Details: {str(e)}"
            return False

        return True
    

    def create_database(self):
        try:
            if self.db_initialized():
                return True

            with self._get_superuser_connection() as super_conn:
                with super_conn.cursor() as cur:
                    cur.execute("""CREATE DATABASE %s""",(self.db_name,))
                super_conn.commit()
            
            self._setup_db()

        except Exception as e:
            msg = f"Failed to create database {self.db_name}. Details: {str(e)}"
            return False

        return True
    

    def get_all_summary(self):
        empty_filter = Scanner.select_filter()
        return self.get_filtered_summary(empty_filter)
    

    def delete_host(self, ip_addr) -> bool:

        try:
            with self.conn.cursor() as cur:
                cur.execute("BEGIN")
    
                sql = """DELETE FROM tor_exit_hosts WHERE exit_addr = %s OR or_addr = %s"""
                cur.execute(sql,(ip_addr,ip_addr))

                sql = """DELETE FROM onion_routing_hosts WHERE or_addr = %s"""
                cur.execute(sql,(ip_addr,))

                sql = """DELETE FROM open_ports WHERE ip_addr = %s"""
                cur.execute(sql,(ip_addr,))

                sql = """DELETE FROM hosts WHERE ip_addr = %s"""
                cur.execute(sql,(ip_addr,))

                cur.execute("COMMIT")
            
            self.conn.commit()

        except Exception as e:
            msg = f"Failed to delete '{ip_addr}'. Details: {str(e)}"
            return False
        
        return True
    

    def clear_tables(self) -> bool:

        try:
            with self.conn.cursor() as cur:
                tables_str = ', '.join(Scanner.ALL_TABLES)
                cur.execute(f"DROP TABLE {tables_str} CASCADE")

        except Exception as e:
            msg = f"Failed to delete '{ip_addr}'. Details: {str(e)}"
            return False
        
        return True
    

    def get_filtered_summary(self, filter_):
        
        try:
            with self.conn.cursor() as cur:
                sql = filter_.render_select_query()
                cur.execute(sql)
                summaries = cur.fetchall()

                host_ports = dict()

                clean_summaries = []

                for host in summaries:
                    clean_summary = dict()
                    clean_summary['ip_addr'] = ip_addr = host[0]
                    clean_summary['or_port'] = host[2]
                    port = host[1]
                    clean_summary['contact'] = host[3]
                    clean_summary['running'] = host[4]
                    clean_summary['country'] = host[5]
                    clean_summary['nickname']= host[6]
                    clean_summary['exit_addr'] = host[7]

                    if ip_addr not in host_ports:
                        host_ports[ip_addr] = [port]
                        clean_summaries.append(clean_summary)
                    else:
                        host_ports[ip_addr].append(port)
                
                for i,host in enumerate(clean_summaries):
                    host['ports'] = host_ports[host['ip_addr']]
                    host['is_exit'] = host['exit_addr'] is not None
                    host['is_onion_routing'] = host['or_port'] is not None
                
                return clean_summaries

        except Exception as e:
            msg = f"Failed to select filtered. Details: {str(e)}"
            print(msg)
            return None
                    


if __name__ == "__main__":
    
    def test_filtered_fetch(scanner):
        filtr = Scanner.select_filter()
        filtr.add_port_to_filter(9001)
        filtr.add_port_to_filter(9002)
        filtr.add_ip_to_filter("66.41.17.62")
        filtr.add_ip_to_filter("185.146.232.243")
        filtr.add_country_to_filter('us')
        filtr.add_country_to_filter('ro')
        print(scanner.get_filtered_summary(filtr))
    
    def test_all_summary(scanner):
        print(scanner.get_all_summary())

    scanner = Scanner()
    scanner.create_database()
    if(not scanner.db_connect()):
        print("Fail!")
        exit(1)
    
    #test_filtered_fetch(scanner)
    test_all_summary(scanner)
    

    #scanner.fetch_onions()