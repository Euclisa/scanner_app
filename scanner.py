import requests
import time
import psycopg2
import os
import json
import logging
from logger import logger
from error import raise_error


class Scanner:

    UPDATE_INT = 3600
    CONFIG_PATH = 'config.json'
    ALL_TABLES = {"event_types","events","hosts","open_ports","tor"}

    def __init__(self, last_updated_fn='last_updated'):
        logging.basicConfig(level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger()

        self.last_updated_fn = last_updated_fn

        self._read_config()

        try:
            self.conn = psycopg2.connect(database=self.db_name,
                                        user=self.db_user,
                                        password=self.db_password,
                                        host=self.db_host,
                                        port=self.db_port
                                    )
        except psycopg2.Error as e:
            self._error(f"Connection to database '{self.db_name}' failed. Details: {str(e)}")
        
        self._check_db_consistency()

        self._setup_db()


    def _error(self,msg):
        self.logger.error(msg)
        raise RuntimeError(msg)
    

    def _setup_db(self):
        with open('setup.sql', 'r') as f:
            setup_sql = f.read()

        try:
            cr.execute(setup_sql)
        except:
            self._error(f"Could not initialize tables.")
    

    def _check_db_consistency(self):
        tables_present_flags = []
        for table in Scanner.ALL_TABLES:
            tables_present_flags.append(self._table_exists(table))
                
        if all(tables_present_flags):
            self.logger.debug("All tables was found.")
            return
        if not any(tables_present_flags):
            self.logger.debug("No tables were found. Database is clean.")
            return
        raise_error(self.logger,f"Database is partially populated. Some tables are missing or corrupted.")

    

    def _table_exists(self,table_name):
        cur = self.conn.cursor()
    
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s);",
            (table_name,)
        )

        cur.close()

    def _read_config(self):
        with open(Scanner.CONFIG_PATH,'r') as f:
            config_json = json.loads(f.read())
        self.db_name = config_json['db_name']
        self.db_user = config_json['db_user']
        self.db_password = config_json['db_password']
        self.db_host = config_json['host']
        self.db_port = int(config_json['port'])
    
    
    