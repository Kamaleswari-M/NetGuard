import sqlite3
from datetime import datetime


DATABASE_NAME = "netguard.db"


def get_connection():
    return sqlite3.connect(DATABASE_NAME)


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

def create_tables():

    connection = get_connection()
    cursor = connection.cursor()

    # Store captured network traffic
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            details TEXT
        )
    """)

    # Store security alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT,
            source_ip TEXT,
            severity TEXT,
            message TEXT
        )
    """)

    connection.commit()
    connection.close()


# =========================================================
# SAVE NETWORK TRAFFIC
# =========================================================

def save_traffic(
        source_ip,
        destination_ip,
        protocol,
        source_port=None,
        destination_port=None,
        details=None):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO traffic (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        details
    ))

    connection.commit()
    connection.close()


# =========================================================
# SAVE SECURITY ALERT
# =========================================================

def save_alert(
        alert_type,
        source_ip,
        severity,
        message):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            alert_type,
            source_ip,
            severity,
            message
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert_type,
        source_ip,
        severity,
        message
    ))

    connection.commit()
    connection.close()