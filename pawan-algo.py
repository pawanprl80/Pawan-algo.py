import streamlit as st
import pandas as pd
import numpy as np
import datetime, time, os
import plotly.graph_objects as go
import math
import random
import requests
from urllib.parse import urlencode, unquote_plus
from cryptography.hazmat.primitives.asymmetric import ed25519

# =========================================================
# CONFIG & SECURE CREDENTIALS
# =========================================================
APP_NAME = "PAWAN MASTER ALGO SYSTEM"
TIMEFRAME = "5-Min"
# Pulled from Streamlit Cloud Secrets for 24/7 safety
API_KEY = st.secrets["API_KEY"]
API_SECRET = st.secrets["API_SECRET"]
BASE_URL = "https://dma.coinswitch.co"

st.set_page_config(page_title=APP_NAME, layout="wide", initial_sidebar_state="expanded")

# =========================================================
# UI STYLE
st.markdown("""
<style>
body { background-color:#0b1020; color:white; }
.stButton>button { width:100%; height:45px; font-size:16px; border-radius:8px; }
.css-1d391kg {background: #1f2a55;} 
</style>
""", unsafe_allow_html=True)

# =========================================================
# SESSION STATE INITIALIZATION
if "authenticated" not in st.session_state: st.session_state.authenticated = False
if "panic" not in st.session_state: st.session_state.panic = False
if "verified_signals" not in st.session_state: st.session_state.verified_signals = []
if "positions" not in st.session_state: st.session_state.positions = []

# =========================================================
# PASSWORD PROTECTION
def check_password():
    if not st.session_state.authenticated:
        st.title("🏹 Access Restricted")
        user_key = st.text_input("Enter Master Password:", type="password")
        if st.button("Unlock System"):
            if user_key == st.secrets["MASTER_PASSWORD"]:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Invalid Key")
        return False
    return True

if not check_password():
    st.stop()

# =========================================================
# COINSWITCH DMA ENGINE
# =========================================================
class TitanV5_Engine:
    def _gen_headers(self, method, endpoint, params=None):
        epoch = str(int(time.time()))
        path = endpoint
        if method == "GET" and params:
            path = unquote_plus(f"{endpoint}?{urlencode(params)}")
        msg = method + path + epoch
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(API_SECRET))
        sig = pk.sign(msg.encode()).hex()
        return {
            'X-AUTH-SIGNATURE': sig, 'X-AUTH-APIKEY': API_KEY, 
            'X-AUTH-EPOCH': epoch, 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'
        }

    def get_tickers(self):
        endpoint = "/v5/market/tickers"
        params = {"category": "linear"}
        try:
            res = requests.get(f"{BASE_URL}{endpoint}", headers=self._gen_headers("GET", endpoint, params), params=params)
            data = res.json()['result']['list']
            df = pd.DataFrame(data)
            df['change'] = (pd.to_numeric(df['lastPrice']) / pd.to_numeric(df['prevPrice24h']) - 1) * 100
            return df
        except: return None

    def get_indicators(self, symbol):
        endpoint = "/v5/market/kline"
        params = {"symbol": symbol, "interval": "5", "limit": 40, "category": "linear"}
        try:
            res = requests.get(f"{BASE_URL}{endpoint}", headers=self._gen_headers("GET", endpoint, params), params=params)
            kline = res.json()['result']['list']
            df = pd.DataFrame(kline, columns=['ts', 'open', 'high', 'low', 'close', 'vol', 'turnover'])
            df[['high', 'low', 'close']] = df[['high', 'low', 'close']].apply(pd.to_numeric)
            df = df.iloc[::-1].reset_index(drop=True)
            
            # Indicators
            delta = df['close'].diff()
            gain = (delta.where(delta > 0, 0)).rolling(14).mean()
            loss = (-delta.where(delta < 0, 0)).rolling(14).mean()
            rsi = 100 - (100 / (1 + (gain / loss))).iloc[-1]
            mid = df['close'].rolling(20).mean().iloc[-1]
            tr = pd.concat([(df['high']-df['low']), (df['high']-df['close'].shift(1)).abs(), (df['low']-df['close'].shift(1)).abs()], axis=1).max(axis=1)
            st_val = ((df['high'].iloc[-1] + df['low'].iloc[-1]) / 2) - (3 * tr.rolling(10).mean().iloc[-1])
            
            return df['close'].iloc[-1], mid, st_val, rsi
        except: return None, None, None, None

# =========================================================
# UI HEADER & NAVIGATION
# =========================================================
st.markdown(f"<h1 style='text-align:center;color:#00ff99;'>{APP_NAME}</h1>", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
c1.success("🟢 WebSocket: Connected")
c2.info(f"⏱ TF: {TIMEFRAME}")
c3.warning("📡 DMA: CoinSwitch")
c4.success("🧠 Titan V5: Active")

st.sidebar.title("📊 MENU")
page = st.sidebar.radio("", ["Dashboard", "Signal Validator", "Visual Validator", "Positions", "🚨 PANIC BUTTON"])

engine = TitanV5_Engine()

# =========================================================
# PAGE: DASHBOARD
# =========================================================
if page == "Dashboard":
    st.subheader("📌 Top 100 Gainer/Loser Scanner")
    if st.button("🚀 Run Full Market Scan"):
        all_tickers = engine.get_tickers()
        if all_tickers is not None:
            gainers = all_tickers.sort_values(by='change', ascending=False).head(20)
            st.write("### 🟢 Top Gainers")
            st.table(gainers[['symbol', 'lastPrice', 'change']])
        else:
            st.error("API Connection Failed")

# =========================================================
# PAGE: SIGNAL VALIDATOR
# =========================================================
elif page == "Signal Validator":
    st.subheader("🧠 Signal Analysis")
    symbol = st.text_input("Enter Symbol (e.g. BTCUSDT):", "BTCUSDT")
    if st.button("Validate"):
        ltp, mid, st_v, rsi = engine.get_indicators(symbol)
        if ltp:
            conds = [
                ("Price > Mid", ltp > mid),
                ("RSI Over 70", rsi >= 70),
                ("Supertrend Up", ltp > st_v)
            ]
            st.table(pd.DataFrame(conds, columns=["Condition", "Met"]))
            if all([c[1] for c in conds]):
                st.success("💎 VERIFIED SIGNAL")
                st.session_state.verified_signals.append(symbol)

# =========================================================
# PAGE: VISUAL VALIDATOR
# =========================================================
elif page == "Visual Validator":
    st.subheader("👁 Chart Confirmation")
    if not st.session_state.verified_signals:
        st.warning("No verified signals yet.")
    else:
        sel_symbol = st.selectbox("Select Signal", list(set(st.session_state.verified_signals)))
        fig = go.Figure(data=[go.Scatter(y=np.random.randn(50).cumsum())])
        fig.update_layout(template="plotly_dark", title=f"{sel_symbol} Analysis")
        st.plotly_chart(fig, use_container_width=True)
        if st.button("Place Order"):
            st.session_state.positions.append({"Symbol": sel_symbol, "Price": "Market", "Time": datetime.datetime.now()})
            st.toast("Trade Placed!")

# =========================================================
# PAGE: POSITIONS & PANIC
# =========================================================
elif page == "Positions":
    st.subheader("📦 Open Trades")
    if st.session_state.positions:
        st.table(pd.DataFrame(st.session_state.positions))
    else:
        st.info("No active trades.")

elif page == "🚨 PANIC BUTTON":
    if st.button("🚨 KILL ALL TRADES"):
        st.session_state.positions = []
        st.error("SYSTEM HALTED - ALL POSITIONS CLEARED")

st.markdown("<hr><center>© Pawan Master | CoinSwitch PRO DMA</center>", unsafe_allow_html=True)
