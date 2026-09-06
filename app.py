from flask import Flask, render_template, request
import joblib
import re
import ipaddress
import pandas as pd

from urllib.parse import urlparse

from database.database import (
    create_database,
    save_scan,
    save_message_scan,
    get_all_scan_history,
    get_dashboard_stats
)

from message_model.message_model import analyze_message


# ============================================================
# PHISHGUARD AI - FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# DATABASE
# ============================================================

create_database()


# ============================================================
# LOAD URL MODEL
# ============================================================

MODEL_PATH = "models/url_model.pkl"

model_package = joblib.load(MODEL_PATH)

model = model_package["model"]

# V4 uses "feature_names"
FEATURE_NAMES = model_package["feature_names"]


# ============================================================
# MODEL CLASS MAPPING
# ============================================================
#
# V4 training:
#
# 0 = LEGITIMATE
# 1 = PHISHING
#
# This is IMPORTANT.
# ============================================================

PHISHING_CLASS = 1
LEGITIMATE_CLASS = 0


# ============================================================
# SUSPICIOUS WORDS
# ============================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "bank",
    "banking",
    "payment",
    "wallet",
    "paypal",
    "recover",
    "unlock",
    "suspend",
    "alert",
    "invoice",
    "billing",
    "authenticate",
    "auth"
]


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url):

    url = str(url).strip()

    if not url:
        return False, "Please enter a URL."

    if any(char.isspace() for char in url):
        return False, "URL cannot contain spaces."

    parse_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parse_url
    ):
        parse_url = "http://" + parse_url

    try:
        parsed = urlparse(parse_url)

    except Exception:
        return False, "The URL format is invalid."

    if parsed.scheme.lower() not in [
        "http",
        "https"
    ]:
        return False, (
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        return False, (
            "The URL does not contain a valid domain."
        )

    hostname = parsed.hostname.lower().strip()

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:
        ipaddress.ip_address(hostname)
        return True, ""

    except ValueError:
        pass

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    if "." not in hostname:
        return False, (
            "Please enter a valid website URL, "
            "such as https://example.com."
        )

    if len(hostname) > 253:
        return False, "The domain name is too long."

    domain_labels = hostname.split(".")

    for label in domain_labels:

        if not label:
            return False, (
                "The domain name contains an empty section."
            )

        if len(label) > 63:
            return False, (
                "A domain section is too long."
            )

        if not re.match(
            r"^[a-zA-Z0-9-]+$",
            label
        ):
            return False, (
                "The domain name contains invalid characters."
            )

        if (
            label.startswith("-")
            or label.endswith("-")
        ):
            return False, (
                "The domain name contains an invalid hyphen."
            )

    tld = domain_labels[-1]

    if len(tld) < 2:
        return False, (
            "The domain extension appears to be invalid."
        )

    if not re.match(
        r"^[a-zA-Z]+$",
        tld
    ):
        return False, (
            "The domain extension appears to be invalid."
        )

    return True, ""


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url_for_analysis(url):

    url = str(url).strip()

    if re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):
        return url

    return "https://" + url


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):

    original_url = str(url).strip()

    parse_url = original_url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parse_url
    ):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""

    domain_parts = [
        part
        for part in hostname.split(".")
        if part
    ]

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(hostname)

        is_domain_ip = 1

    except ValueError:

        is_domain_ip = 0

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    if is_domain_ip == 1:

        subdomain_count = 0

    elif len(domain_parts) >= 2:

        subdomain_count = max(
            len(domain_parts) - 2,
            0
        )

    else:

        subdomain_count = 0

    # --------------------------------------------------------
    # BASIC FEATURES
    # --------------------------------------------------------

    url_length = len(original_url)

    domain_length = len(hostname)

    tld_length = 0

    if len(domain_parts) >= 2:

        tld_length = len(
            domain_parts[-1]
        )

    number_of_letters = sum(
        char.isalpha()
        for char in original_url
    )

    number_of_digits = sum(
        char.isdigit()
        for char in original_url
    )

    number_of_equals = original_url.count("=")

    number_of_question_marks = original_url.count("?")

    number_of_ampersands = original_url.count("&")

    special_characters = sum(
        not char.isalnum()
        and char not in [
            ":",
            "/",
            ".",
            "-",
            "_",
            "?",
            "=",
            "&"
        ]
        for char in original_url
    )

    is_https = int(
        parsed.scheme.lower() == "https"
    )

    # --------------------------------------------------------
    # EXTRA APPLICATION FEATURES
    # --------------------------------------------------------

    has_at_symbol = original_url.count("@")

    hyphen_count = original_url.count("-")

    dot_count = original_url.count(".")

    path_length = len(
        parsed.path
    )

    query_length = len(
        parsed.query
    )

    fragment_length = len(
        parsed.fragment
    )

    # --------------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------------

    url_lower = original_url.lower()

    suspicious_keyword_count = sum(
        1
        for word in SUSPICIOUS_WORDS
        if word.lower() in url_lower
    )

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "is_domain_ip": is_domain_ip,
        "tld_length": tld_length,
        "subdomains": subdomain_count,
        "letters": number_of_letters,
        "digits": number_of_digits,
        "equals": number_of_equals,
        "question_marks": number_of_question_marks,
        "ampersands": number_of_ampersands,
        "special_characters": special_characters,
        "https": is_https,
        "at_symbol": has_at_symbol,
        "hyphens": hyphen_count,
        "dots": dot_count,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "suspicious_keywords": suspicious_keyword_count
    }


# ============================================================
# SECURITY RULE ENGINE
# ============================================================

def analyze_security_rules(url):

    parse_url = str(url).strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parse_url
    ):
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""

    rule_score = 0

    indicators = []

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if parsed.scheme.lower() != "https":

        rule_score += 10

        indicators.append(
            "The website is not using a secure HTTPS connection."
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    is_ip_address = False

    try:

        ipaddress.ip_address(hostname)

        is_ip_address = True

        rule_score += 25

        indicators.append(
            "The website uses an IP address instead of a domain name."
        )

    except ValueError:

        is_ip_address = False

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in parse_url:

        rule_score += 20

        indicators.append(
            "The URL contains an @ symbol, which can be used to hide the real destination."
        )

    # --------------------------------------------------------
    # HYPHENS
    # --------------------------------------------------------

    hyphen_count = parse_url.count("-")

    if hyphen_count >= 3:

        rule_score += 10

        indicators.append(
            "The URL contains multiple hyphens."
        )

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    dot_count = hostname.count(".")

    if (
        not is_ip_address
        and
        dot_count >= 3
    ):

        rule_score += 10

        indicators.append(
            "The domain contains many subdomain levels."
        )

    # --------------------------------------------------------
    # LONG URL
    # --------------------------------------------------------

    if len(parse_url) > 100:

        rule_score += 10

        indicators.append(
            "The URL is unusually long."
        )

    # --------------------------------------------------------
    # DIGITS
    # --------------------------------------------------------

    digit_count = sum(
        char.isdigit()
        for char in parse_url
    )

    if digit_count >= 5:

        rule_score += 5

        indicators.append(
            "The URL contains many numbers."
        )

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    found_words = []

    url_lower = parse_url.lower()

    for word in SUSPICIOUS_WORDS:

        if word.lower() in url_lower:

            found_words.append(word)

    if found_words:

        keyword_score = min(
            len(set(found_words)) * 5,
            20
        )

        rule_score += keyword_score

        indicators.append(
            "The URL contains words commonly associated with "
            "account or security scams: "
            +
            ", ".join(
                sorted(
                    set(found_words)
                )
            )
        )

    rule_score = min(
        rule_score,
        100
    )

    return (
        round(rule_score, 2),
        indicators
    )


# ============================================================
# HYBRID RISK CALCULATION
# ============================================================

def calculate_hybrid_score(
    ml_probability,
    rule_score,
    url_analysis
):

    ml_score = ml_probability * 100

    # --------------------------------------------------------
    # SECURITY EVIDENCE FACTOR
    # --------------------------------------------------------

    evidence_factor = (
        0.25
        +
        0.75 * (
            rule_score / 100
        )
    )

    adjusted_ml_score = (
        ml_score
        *
        evidence_factor
    )

    # --------------------------------------------------------
    # COMBINE SIGNALS
    # --------------------------------------------------------

    hybrid_score = (
        adjusted_ml_score * 0.70
        +
        rule_score * 0.30
    )

    # --------------------------------------------------------
    # STRONG IP INDICATOR
    # --------------------------------------------------------

    if url_analysis["is_domain_ip"] == 1:

        if ml_score >= 70:

            hybrid_score = max(
                hybrid_score,
                80
            )

        elif rule_score >= 50:

            hybrid_score = max(
                hybrid_score,
                65
            )

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if (
        url_analysis["at_symbol"] > 0
        and
        ml_score >= 70
    ):

        hybrid_score = max(
            hybrid_score,
            80
        )

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    if (
        url_analysis["suspicious_keywords"] >= 2
        and
        ml_score >= 80
    ):

        hybrid_score = max(
            hybrid_score,
            70
        )

    # --------------------------------------------------------
    # LONG SUSPICIOUS PATH
    # --------------------------------------------------------

    if (
        url_analysis["path_length"] >= 80
        and
        ml_score >= 80
        and
        rule_score >= 10
    ):

        hybrid_score = max(
            hybrid_score,
            70
        )

    # --------------------------------------------------------
    # CLEAN HTTPS URL
    # --------------------------------------------------------

    clean_https = (
        url_analysis["https"] == 1
        and
        url_analysis["is_domain_ip"] == 0
        and
        url_analysis["at_symbol"] == 0
        and
        url_analysis["suspicious_keywords"] == 0
        and
        rule_score <= 10
    )

    if clean_https:

        # Prevent an overconfident ML model from making
        # an otherwise clean HTTPS URL high-risk.
        hybrid_score = min(
            hybrid_score,
            30
        )

    # --------------------------------------------------------
    # LIMIT
    # --------------------------------------------------------

    hybrid_score = max(
        0,
        min(
            hybrid_score,
            100
        )
    )

    return round(
        hybrid_score,
        2
    )


# ============================================================
# URL SCANNER
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def home():

    result = None
    risk_score = None
    threat_level = None
    reasons = []
    url = ""
    validation_error = None
    url_analysis = None
    ml_risk = None
    rule_risk = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        is_valid, error_message = validate_url(
            url
        )

        if not is_valid:

            validation_error = error_message

            return render_template(
                "index.html",
                result=result,
                risk_score=risk_score,
                threat_level=threat_level,
                reasons=reasons,
                url=url,
                validation_error=validation_error,
                url_analysis=url_analysis,
                ml_risk=ml_risk,
                rule_risk=rule_risk
            )

        # ----------------------------------------------------
        # NORMALIZE
        # ----------------------------------------------------

        analysis_url = normalize_url_for_analysis(
            url
        )

        # ----------------------------------------------------
        # EXTRACT FEATURES
        # ----------------------------------------------------

        url_analysis = extract_url_features(
            analysis_url
        )

        # ====================================================
        # MODEL INPUT
        # ====================================================

        feature_map = {

            "URLLength":
                url_analysis["url_length"],

            "DomainLength":
                url_analysis["domain_length"],

            "IsDomainIP":
                url_analysis["is_domain_ip"],

            "TLDLength":
                url_analysis["tld_length"],

            "NoOfSubDomain":
                url_analysis["subdomains"],

            "NoOfLettersInURL":
                url_analysis["letters"],

            "NoOfDegitsInURL":
                url_analysis["digits"],

            "NoOfEqualsInURL":
                url_analysis["equals"],

            "NoOfQMarkInURL":
                url_analysis["question_marks"],

            "NoOfAmpersandInURL":
                url_analysis["ampersands"],

            "NoOfOtherSpecialCharsInURL":
                url_analysis["special_characters"],

            "IsHTTPS":
                url_analysis["https"]
        }

        missing_model_features = [
            feature
            for feature in FEATURE_NAMES
            if feature not in feature_map
        ]

        if missing_model_features:

            validation_error = (
                "Model feature configuration error: "
                +
                ", ".join(
                    missing_model_features
                )
            )

            return render_template(
                "index.html",
                result=result,
                risk_score=risk_score,
                threat_level=threat_level,
                reasons=reasons,
                url=url,
                validation_error=validation_error,
                url_analysis=url_analysis,
                ml_risk=ml_risk,
                rule_risk=rule_risk
            )

        model_feature_values = [
            feature_map[feature]
            for feature in FEATURE_NAMES
        ]

        feature_data = pd.DataFrame(
            [
                model_feature_values
            ],
            columns=FEATURE_NAMES
        )

        # ----------------------------------------------------
        # ML PREDICTION
        # ----------------------------------------------------

        probabilities = model.predict_proba(
            feature_data
        )[0]

        try:

            phishing_index = list(
                model.classes_
            ).index(
                PHISHING_CLASS
            )

            ml_probability = probabilities[
                phishing_index
            ]

        except ValueError:

            ml_probability = 0.0

        ml_risk = round(
            ml_probability * 100,
            2
        )

        # ----------------------------------------------------
        # SECURITY RULES
        # ----------------------------------------------------

        rule_risk, rule_reasons = (
            analyze_security_rules(
                analysis_url
            )
        )

        # ----------------------------------------------------
        # HYBRID SCORE
        # ----------------------------------------------------

        risk_score = calculate_hybrid_score(
            ml_probability,
            rule_risk,
            url_analysis
        )

        # ----------------------------------------------------
        # CLASSIFICATION
        # ----------------------------------------------------

        if risk_score >= 80:

            result = "PHISHING DETECTED"

            threat_level = "HIGH"

        elif risk_score >= 50:

            result = "PHISHING DETECTED"

            threat_level = "MEDIUM"

        elif risk_score >= 20:

            result = "URL APPEARS SAFE"

            threat_level = "LOW"

        else:

            result = "URL APPEARS SAFE"

            threat_level = "SAFE"

        # ----------------------------------------------------
        # REASONS
        # ----------------------------------------------------

        reasons = rule_reasons

        if not reasons:

            if threat_level == "SAFE":

                reasons = [
                    "No major structural warning signs were detected."
                ]

            elif threat_level == "LOW":

                reasons = [
                    "The model detected some unusual URL characteristics, "
                    "but there is limited independent security evidence."
                ]

            else:

                reasons = [
                    "The machine-learning model detected elevated phishing risk."
                ]

        # ----------------------------------------------------
        # SAVE SCAN
        # ----------------------------------------------------

        save_scan(
            url,
            result,
            risk_score,
            threat_level
        )

    return render_template(
        "index.html",
        result=result,
        risk_score=risk_score,
        threat_level=threat_level,
        reasons=reasons,
        url=url,
        validation_error=validation_error,
        url_analysis=url_analysis,
        ml_risk=ml_risk,
        rule_risk=rule_risk
    )


# ============================================================
# MESSAGE SCANNER
# ============================================================

@app.route(
    "/message",
    methods=["GET", "POST"]
)
def message_scanner():

    message = ""
    result = None
    risk_score = None
    threat_level = None
    validation_error = None

    # URLs detected inside the message
    embedded_urls = []

    if request.method == "POST":

        message = request.form.get(
            "message",
            ""
        ).strip()

        # ----------------------------------------------------
        # MESSAGE VALIDATION
        # ----------------------------------------------------

        if not message:

            validation_error = (
                "Please enter a message to analyze."
            )

        elif len(message) < 3:

            validation_error = (
                "Please enter a longer message."
            )

        else:

            # ------------------------------------------------
            # STEP 1: MESSAGE / NLP ANALYSIS
            # ------------------------------------------------

            message_analysis = analyze_message(message)

            message_risk = float(
                message_analysis["risk_score"]
            )

            result = message_analysis["result"]
            risk_score = message_risk
            threat_level = message_analysis["threat_level"]

            # ------------------------------------------------
            # STEP 2: FIND URLs INSIDE THE MESSAGE
            # ------------------------------------------------

            url_pattern = re.compile(
                r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
            )

            found_urls = url_pattern.findall(message)

            cleaned_urls = []

            for found_url in found_urls:

                cleaned_url = found_url.rstrip(
                    ".,!?;:)]}>'\""
                )

                if (
                    cleaned_url
                    and cleaned_url not in cleaned_urls
                ):
                    cleaned_urls.append(cleaned_url)

            # ------------------------------------------------
            # STEP 3: ANALYZE EACH EMBEDDED URL
            # ------------------------------------------------

            for found_url in cleaned_urls:

                is_valid, error_message = validate_url(
                    found_url
                )

                if not is_valid:
                    continue

                try:

                    analysis_url = normalize_url_for_analysis(
                        found_url
                    )

                    url_analysis = extract_url_features(
                        analysis_url
                    )

                    # ----------------------------------------
                    # MAP URL FEATURES TO V4 MODEL FEATURES
                    # ----------------------------------------

                    feature_map = {
                        "URLLength":
                            url_analysis["url_length"],

                        "DomainLength":
                            url_analysis["domain_length"],

                        "IsDomainIP":
                            url_analysis["is_domain_ip"],

                        "TLDLength":
                            url_analysis["tld_length"],

                        "NoOfSubDomain":
                            url_analysis["subdomains"],

                        "NoOfLettersInURL":
                            url_analysis["letters"],

                        "NoOfDegitsInURL":
                            url_analysis["digits"],

                        "NoOfEqualsInURL":
                            url_analysis["equals"],

                        "NoOfQMarkInURL":
                            url_analysis["question_marks"],

                        "NoOfAmpersandInURL":
                            url_analysis["ampersands"],

                        "NoOfOtherSpecialCharsInURL":
                            url_analysis["special_characters"],

                        "IsHTTPS":
                            url_analysis["https"]
                    }

                    missing_features = [
                        feature
                        for feature in FEATURE_NAMES
                        if feature not in feature_map
                    ]

                    if missing_features:
                        continue

                    model_feature_values = [
                        feature_map[feature]
                        for feature in FEATURE_NAMES
                    ]

                    feature_data = pd.DataFrame(
                        [model_feature_values],
                        columns=FEATURE_NAMES
                    )

                    # ----------------------------------------
                    # URL ML PREDICTION
                    # ----------------------------------------

                    probabilities = model.predict_proba(
                        feature_data
                    )[0]

                    try:

                        phishing_index = list(
                            model.classes_
                        ).index(
                            PHISHING_CLASS
                        )

                        url_ml_probability = float(
                            probabilities[phishing_index]
                        )

                    except ValueError:

                        url_ml_probability = 0.0

                    url_ml_risk = round(
                        url_ml_probability * 100,
                        2
                    )

                    # ----------------------------------------
                    # SECURITY RULE ENGINE
                    # ----------------------------------------

                    url_rule_risk, url_reasons = (
                        analyze_security_rules(
                            analysis_url
                        )
                    )

                    # ----------------------------------------
                    # HYBRID URL RISK
                    # ----------------------------------------

                    url_final_risk = calculate_hybrid_score(
                        url_ml_probability,
                        url_rule_risk,
                        url_analysis
                    )

                    # ----------------------------------------
                    # URL THREAT LEVEL
                    # ----------------------------------------

                    if url_final_risk >= 80:
                        url_threat_level = "HIGH"

                    elif url_final_risk >= 50:
                        url_threat_level = "MEDIUM"

                    elif url_final_risk >= 20:
                        url_threat_level = "LOW"

                    else:
                        url_threat_level = "SAFE"

                    if not url_reasons:
                        url_reasons = [
                            "No major structural warning signs were detected."
                        ]

                    # ----------------------------------------
                    # SAVE EMBEDDED URL DETAILS FOR UI
                    # ----------------------------------------

                    embedded_urls.append({
                        "url": found_url,
                        "risk_score": round(url_final_risk, 2),
                        "ml_risk": url_ml_risk,
                        "rule_risk": round(url_rule_risk, 2),
                        "threat_level": url_threat_level,
                        "reasons": url_reasons,
                        "https": url_analysis["https"],
                        "is_domain_ip": url_analysis["is_domain_ip"],
                        "suspicious_words":
                            url_analysis["suspicious_keywords"]
                    })

                except Exception:
                    # Never allow one malformed URL to break
                    # the complete message scan.
                    continue

            # ------------------------------------------------
            # STEP 4: COMBINE MESSAGE + URL RISK
            # ------------------------------------------------

            if embedded_urls:

                highest_url_risk = max(
                    item["risk_score"]
                    for item in embedded_urls
                )

                # Security-first approach:
                # strongest signal determines final risk.
                risk_score = max(
                    message_risk,
                    highest_url_risk
                )

                if risk_score >= 80:
                    threat_level = "HIGH"
                    result = "SCAM / PHISHING DETECTED"

                elif risk_score >= 50:
                    threat_level = "MEDIUM"
                    result = "SCAM / PHISHING DETECTED"

                elif risk_score >= 20:
                    threat_level = "LOW"
                    result = "MESSAGE REQUIRES CAUTION"

                else:
                    threat_level = "SAFE"
                    result = "MESSAGE APPEARS SAFE"

            # ------------------------------------------------
            # STEP 5: SAVE MESSAGE SCAN
            # ------------------------------------------------

            save_message_scan(
                message,
                result,
                risk_score,
                threat_level
            )

    # --------------------------------------------------------
    # RENDER MESSAGE SCANNER
    # --------------------------------------------------------

    return render_template(
        "message.html",
        message=message,
        result=result,
        risk_score=risk_score,
        threat_level=threat_level,
        validation_error=validation_error,
        embedded_urls=embedded_urls
    )


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
def history():

    scans = get_all_scan_history()

    return render_template(
        "history.html",
        scans=scans
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    stats = get_dashboard_stats()

    all_scans = get_all_scan_history()

    recent_scans = all_scans[:5]

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )