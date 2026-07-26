from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DATABASE_NAME = "netguard.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def dashboard():

    connection = get_connection()
    cursor = connection.cursor()

    # Total traffic
    cursor.execute("SELECT COUNT(*) FROM traffic")
    total_packets = cursor.fetchone()[0]

    # TCP count
    cursor.execute(
        "SELECT COUNT(*) FROM traffic WHERE protocol = 'TCP'"
    )
    tcp_count = cursor.fetchone()[0]

    # UDP count
    cursor.execute(
        "SELECT COUNT(*) FROM traffic WHERE protocol = 'UDP'"
    )
    udp_count = cursor.fetchone()[0]

    # DNS count
    cursor.execute(
        "SELECT COUNT(*) FROM traffic WHERE protocol = 'DNS'"
    )
    dns_count = cursor.fetchone()[0]

    # ICMP count
    cursor.execute(
        "SELECT COUNT(*) FROM traffic WHERE protocol = 'ICMP'"
    )
    icmp_count = cursor.fetchone()[0]

    # Total alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    alert_count = cursor.fetchone()[0]

    # Latest 20 traffic records
    cursor.execute("""
        SELECT *
        FROM traffic
        ORDER BY id DESC
        LIMIT 20
    """)

    traffic = cursor.fetchall()

    # Latest 10 alerts
    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
    """)

    alerts = cursor.fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        total_packets=total_packets,
        tcp_count=tcp_count,
        udp_count=udp_count,
        dns_count=dns_count,
        icmp_count=icmp_count,
        alert_count=alert_count,
        traffic=traffic,
        alerts=alerts
    )


if __name__ == "__main__":
    app.run(debug=True)