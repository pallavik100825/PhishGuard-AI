import sqlite3
from datetime import datetime


# ============================================================
# DATABASE PATH
# ============================================================

DATABASE_PATH = "database/phishguard.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    connection = get_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # URL SCAN TABLE
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_score REAL NOT NULL,
            threat_level TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # MESSAGE SCAN TABLE
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_score REAL NOT NULL,
            threat_level TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# SAVE URL SCAN
# ============================================================

def save_scan(url, result, risk_score, threat_level):

    connection = get_connection()
    cursor = connection.cursor()

    scanned_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO scan_history
        (
            url,
            result,
            risk_score,
            threat_level,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        result,
        risk_score,
        threat_level,
        scanned_at
    ))

    connection.commit()
    connection.close()


# ============================================================
# SAVE MESSAGE SCAN
# ============================================================

def save_message_scan(
    message,
    result,
    risk_score,
    threat_level
):

    connection = get_connection()
    cursor = connection.cursor()

    scanned_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO message_scan_history
        (
            message,
            result,
            risk_score,
            threat_level,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        message,
        result,
        risk_score,
        threat_level,
        scanned_at
    ))

    connection.commit()
    connection.close()


# ============================================================
# GET URL SCAN HISTORY
# ============================================================

def get_scan_history():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            url,
            result,
            risk_score,
            threat_level,
            scanned_at
        FROM scan_history
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return scans


# ============================================================
# GET MESSAGE SCAN HISTORY
# ============================================================

def get_message_scan_history():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            message,
            result,
            risk_score,
            threat_level,
            scanned_at
        FROM message_scan_history
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return scans


# ============================================================
# GET COMBINED SCAN HISTORY
# ============================================================

def get_all_scan_history():

    connection = get_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # URL SCANS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            'URL' AS scan_type,
            url AS content,
            result,
            risk_score,
            threat_level,
            scanned_at
        FROM scan_history
    """)

    url_scans = cursor.fetchall()

    # --------------------------------------------------------
    # MESSAGE SCANS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            'MESSAGE' AS scan_type,
            message AS content,
            result,
            risk_score,
            threat_level,
            scanned_at
        FROM message_scan_history
    """)

    message_scans = cursor.fetchall()

    connection.close()

    # --------------------------------------------------------
    # COMBINE BOTH TYPES
    # --------------------------------------------------------

    all_scans = list(url_scans) + list(message_scans)

    # Newest scans first
    all_scans.sort(
        key=lambda scan: scan["scanned_at"],
        reverse=True
    )

    return all_scans


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_stats():

    connection = get_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # URL SCANS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COUNT(*) AS total
        FROM scan_history
    """)

    url_total = cursor.fetchone()["total"]

    # --------------------------------------------------------
    # MESSAGE SCANS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            COUNT(*) AS total
        FROM message_scan_history
    """)

    message_total = cursor.fetchone()["total"]

    # --------------------------------------------------------
    # TOTAL SCANS
    # --------------------------------------------------------

    total_scans = url_total + message_total

    # --------------------------------------------------------
    # PHISHING / SCAM DETECTED
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scan_history
        WHERE result LIKE '%PHISHING%'
    """)

    url_threats = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM message_scan_history
        WHERE result LIKE '%SCAM%'
           OR result LIKE '%SPAM%'
    """)

    message_threats = cursor.fetchone()["total"]

    threats_detected = url_threats + message_threats

    # --------------------------------------------------------
    # SAFE SCANS
    # --------------------------------------------------------

    safe_scans = total_scans - threats_detected

    # --------------------------------------------------------
    # AVERAGE RISK
    # --------------------------------------------------------

    cursor.execute("""
        SELECT AVG(risk_score) AS average_risk
        FROM (
            SELECT risk_score
            FROM scan_history

            UNION ALL

            SELECT risk_score
            FROM message_scan_history
        )
    """)

    result = cursor.fetchone()

    average_risk = result["average_risk"]

    if average_risk is None:
        average_risk = 0.0

    average_risk = round(
        float(average_risk),
        2
    )

    # --------------------------------------------------------
    # HIGH THREATS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM (
            SELECT threat_level
            FROM scan_history

            UNION ALL

            SELECT threat_level
            FROM message_scan_history
        )
        WHERE threat_level = 'HIGH'
    """)

    high_threats = cursor.fetchone()["total"]

    # --------------------------------------------------------
    # MEDIUM THREATS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM (
            SELECT threat_level
            FROM scan_history

            UNION ALL

            SELECT threat_level
            FROM message_scan_history
        )
        WHERE threat_level = 'MEDIUM'
    """)

    medium_threats = cursor.fetchone()["total"]

    # --------------------------------------------------------
    # LOW THREATS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM (
            SELECT threat_level
            FROM scan_history

            UNION ALL

            SELECT threat_level
            FROM message_scan_history
        )
        WHERE threat_level = 'LOW'
    """)

    low_threats = cursor.fetchone()["total"]

    # --------------------------------------------------------
    # SAFE THREATS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM (
            SELECT threat_level
            FROM scan_history

            UNION ALL

            SELECT threat_level
            FROM message_scan_history
        )
        WHERE threat_level = 'SAFE'
    """)

    safe_threats = cursor.fetchone()["total"]

    connection.close()

    # --------------------------------------------------------
    # RETURN STATISTICS
    # --------------------------------------------------------

    return {
        "total_scans": total_scans,

        "url_scans": url_total,

        "message_scans": message_total,

        "phishing_scans": threats_detected,

        "safe_scans": safe_scans,

        "threats_detected": threats_detected,

        "average_risk": average_risk,

        "avg_risk": average_risk,

        "high_threats": high_threats,

        "medium_threats": medium_threats,

        "low_threats": low_threats,

        "safe_threats": safe_threats,

        # Extra aliases for dashboard compatibility
        "high_count": high_threats,

        "medium_count": medium_threats,

        "low_count": low_threats,

        "safe_count": safe_threats
    }


# ============================================================
# INITIALIZE DATABASE
# ============================================================

create_database()