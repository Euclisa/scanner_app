CREATE TABLE IF NOT EXISTS event_types (
    event_name VARCHAR(20) PRIMARY KEY,
    event_description VARCHAR(255)
);

INSERT INTO event_types (event_name, event_description) VALUES ('tor_fetch', 'Hosts information was fetched from Tor Project resources.');
INSERT INTO event_types (event_name, event_description) VALUES ('shodan_fetch', 'Hosts information was fetched with Shodan.');

CREATE TABLE IF NOT EXISTS events
(
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP WITH TIME ZONE NOT NULL,
    event_name VARCHAR(20) NOT NULL REFERENCES event_types(event_name),
    user_name VARCHAR(32) NOT NULL,
    comment VARCHAR(255)
);


CREATE TABLE IF NOT EXISTS hosts (
    ip_addr INET PRIMARY KEY,
    last_modified SERIAL NOT NULL REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS open_ports (
    ip_addr INET REFERENCES hosts(ip_addr),
    port INTEGER,
    banner TEXT,

    PRIMARY KEY(ip_addr,port)
);


CREATE TABLE IF NOT EXISTS tor (
    or_addr INET PRIMARY KEY REFERENCES hosts(ip_addr),
    or_port INTEGER NOT NULL,
    nickname VARCHAR(19) NOT NULL,
    fingerprint CHAR(40) NOT NULL,
    --exit_addresses INET[] REFERENCES hosts(ip_addr),
    last_seen TIMESTAMP NOT NULL,
    last_changed_address_or_port TIMESTAMP NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    running BOOLEAN NOT NULL,
    --flags BIT(12),    -- 'MiddleOnly', 'Authority', 'Stable', 'Valid', 'Guard', 'HSDir', 'V2Dir', 'Fast', 'BadExit', 'Running', 'Exit', 'StaleDesc'
    country CHAR(2),
    verified_host_names VARCHAR(255)[],
    unverified_host_names VARCHAR(255)[],
    contact TEXT,

    FOREIGN KEY (or_addr, or_port) REFERENCES open_ports(ip_addr, port)
);
