"""
Configuration file for netpredict.
Defines paths, feature definitions, hyperparameters, and risk thresholds.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"

# Default raw dataset path (CICIDS2017 Tuesday captures: SSH-Patator, FTP-Patator, BENIGN)
DEFAULT_RAW_FILE = DATA_RAW_DIR / "Tuesday-WorkingHours.pcap_ISCX.csv"

# Columns to strictly drop (Identifiers that cause trivial memorization or data leakage)
COLUMNS_TO_DROP = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Timestamp",
    "Unnamed: 0",
]

# Label definitions
LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"

# Temporal Sequence Parameters
SEQUENCE_LENGTH = 5     # Lookback window (5 consecutive network flow windows)
FORECAST_HORIZON = 1    # Forecast horizon (predicting risk in next window t + 1)
BATCH_SIZE = 32
EPOCHS = 15
LR_MAX_ITER = 1000
RANDOM_STATE = 42

# Prototype Risk Level Thresholds (Configurable)
DEFAULT_RISK_THRESHOLDS = {
    "LOW": (0.00, 0.25),
    "MEDIUM": (0.25, 0.50),
    "HIGH": (0.50, 0.75),
    "CRITICAL": (0.75, 1.00),
}

# Triage Action mapping
PRIORITY_ACTION_MAP = {
    "CRITICAL": "Investigate immediately (High probability of impending or active attack)",
    "HIGH": "Investigate soon (Elevated anomaly density across recent windows)",
    "MEDIUM": "Monitor closely (Moderate temporal variance; track source hosts)",
    "LOW": "Normal monitoring (Traffic metrics adhere to baseline behavior)",
}

# Prototype Disclaimer
PROTOTYPE_DISCLAIMER = (
    "NOTICE: This is a hackathon research prototype. Risk thresholds and "
    "forecast probabilities are experimental decision-support metrics and not official "
    "cybersecurity regulatory standards."
)
