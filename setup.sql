CREATE TABLE IF NOT EXISTS event_types (
    event_name VARCHAR(20) PRIMARY KEY,
    event_description VARCHAR(255) NOT NULL
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


CREATE TABLE IF NOT EXISTS edit_labels
(
    id CHAR(2) PRIMARY KEY,
    label_description VARCHAR(255) NOT NULL
);


INSERT INTO edit_labels (id, label_description) VALUES ('TE', 'Host information was found in some Tor relay Exit addresses list.');
INSERT INTO edit_labels (id, label_description) VALUES ('OR', 'Host information was found in Onion Relays list.');


CREATE TABLE IF NOT EXISTS hosts (
    ip_addr INET PRIMARY KEY,
    last_modified_event SERIAL NOT NULL REFERENCES events(id),
    last_modified_label CHAR(2) REFERENCES edit_labels(id)
);

CREATE TABLE IF NOT EXISTS open_ports (
    ip_addr INET REFERENCES hosts(ip_addr),
    port INTEGER,
    banner TEXT,
    onion_routing BOOLEAN NOT NULL,

    PRIMARY KEY(ip_addr,port)
);


CREATE TABLE IF NOT EXISTS onion_routing_hosts (
    or_addr INET PRIMARY KEY REFERENCES hosts(ip_addr),
    or_port INTEGER NOT NULL,
    nickname VARCHAR(19) NOT NULL,
    fingerprint CHAR(40) NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    last_changed_address_or_port TIMESTAMP NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    running BOOLEAN NOT NULL,
    flags BIT(12),    -- 'MiddleOnly', 'Authority', 'Stable', 'Valid', 'Guard', 'HSDir', 'V2Dir', 'Fast', 'BadExit', 'Running', 'Exit', 'StaleDesc'
    country CHAR(2),
    verified_host_names VARCHAR(255)[],
    unverified_host_names VARCHAR(255)[],
    contact TEXT,

    FOREIGN KEY (or_addr, or_port) REFERENCES open_ports(ip_addr, port)
);


CREATE TABLE IF NOT EXISTS tor_exit_hosts (
    exit_addr INET PRIMARY KEY REFERENCES hosts(ip_addr),
    or_addr INET REFERENCES onion_routing_hosts(or_addr)
);