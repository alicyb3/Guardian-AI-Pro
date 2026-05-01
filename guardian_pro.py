import streamlit as st
from transformers import pipeline
import pandas as pd
import sqlite3
from datetime import datetime
import requests
import base64
import re

# --- إعدادات الصفحة ---
st.set_page_config(page_title="Guardian AI Pro", page_icon="🛡️", layout="wide")

# --- إدارة حالة الصفحة (Session State) ---
if 'started' not in st.session_state:
    st.session_state.started = False

# --- قاعدة البيانات (تمت إضافة عمود confidence) ---
conn = sqlite3.connect('security_logs_v2.db', check_same_thread=False)
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, type TEXT, input TEXT, result TEXT, confidence TEXT)')
conn.commit()

# --- تحميل موديل الذكاء الاصطناعي ---
@st.cache_resource
def load_model():
    return pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

classifier = load_model()

# --- دالة فحص الروابط (VirusTotal) ---
def check_url_vt(url):
    api_key = "b1f92903de3aea83666b463b5349ba86643bfb3f32699673b884fe2fc0578c29"
    if api_key == "ضع_مفتاحك_هنا": return 0
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": api_key})
        if res.status_code == 200:
            return res.json()['data']['attributes']['last_analysis_stats']['malicious']
        return 0
    except: return 0

# --- دالة تتبع الـ IP ---
def get_ip_info(ip):
    try:
        return requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,proxy,query").json()
    except: return None

# --- CSS للتحكم بالواجهات ---
if not st.session_state.started:
    st.markdown("""
       <style>
    .block-container { padding: 0rem; }
    
    /* تنسيق الحاسبة - الهيبة الكاملة */
    .hero-section {
        background-image: linear-gradient(rgba(12, 36, 97, 0.85), rgba(12, 36, 97, 0.85)),
                          url('https://img.freepik.com/free-vector/cyber-security-concept_23-2148532223.jpg');
        background-size: cover; background-position: center;
        height: 85vh; display: flex; flex-direction: column;
        justify-content: center; align-items: center; color: white; text-align: center;
    }

    .hero-title { 
        font-size: 60px !important; 
        font-weight: bold; 
        margin-bottom: 20px; 
        line-height: 1.2; 
        width: 90%;
    }

    /* تنسيق الموبايل - الترتيب التلقائي */
    @media (max-width: 600px) {
        .hero-title { font-size: 30px !important; }
        .hero-section { height: auto !important; padding: 100px 10px !important; }
    }

    /* ألوان نصوص الجامعة والزر */
    .hero-section p { color: white !important; font-size: 1.3rem !important; }
    .start-btn button {
        background-color: #4a69bd !important; color: white !important;
        font-size: 26px !important; padding: 15px 70px !important;
        border-radius: 50px !important; border: none !important; transition: 0.3s;
    }
    .start-btn button:hover { transform: scale(1.1); background-color: #1e3799 !important; }
    </style>
        """, unsafe_allow_html=True)
else:
    st.markdown("""
        <style>
        .block-container { padding-top: 2rem; padding-left: 5rem; padding-right: 5rem; }
        .stButton>button { background-color: #0c2461; color: white; font-weight: bold; border-radius: 8px; width: 100%; }
        h1, h2 { color: #0c2461; text-align: center; }
        .sidebar-text { text-align: center; font-weight: bold; color: #0c2461; font-size: 18px; }
        </style>
        """, unsafe_allow_html=True)

# --- 1. واجهة البداية (Landing Page) ---
if not st.session_state.started:
    st.markdown("""
        <div class="hero-section">
            <div class="hero-title">Guardian AI Pro</div>
            <p style="font-size: 28px;">نظام الحماية الذكي للتحليل والتعقب الرقمي</p>
            <p style="font-size: 20px; opacity: 0.8;">جامعة المثنى - قسم هندسة الأمن السيبراني</p>
            <br>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 0.4, 1])
    with col2:
        st.markdown('<div class="start-btn">', unsafe_allow_html=True)
        if st.button("Start | دخول"):
            st.session_state.started = True
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

# --- 2. واجهة العمل (Main App) ---
else:
    # الهيدر الداخلي
    col_l, col_r = st.columns([1, 6])
    with col_l:
        st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    with col_r:
        st.markdown("<h1 style='text-align: right;'>نظام الحماية الذكي للتحليل والتعقب</h1>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["🔍 تحليل التهديدات", "📍  IPتتبع المصدر", "📜 السجل التاريخي"])

    # التبويب الأول: الفحص
    with tab1:
        st.markdown("### 📥 فحص الرسائل والروابط المشبوهة")
        u_input = st.text_area("أدخل المحتوى (نص أو رابط) للفحص الجنائي:", height=150)
        
        if st.button("إجراء الفحص الذكي"):
            if u_input.strip():
                with st.spinner('جاري تحليل المحتوى...'):
                    # تحليل الذكاء الاصطناعي
                    res = classifier(u_input, candidate_labels=["Spam", "Phishing", "Safe"])
                    label = res['labels'][0]
                    # إضافة استخراج درجة الثقة
                    confidence = f"{round(res['scores'][0] * 100, 2)}%"
                    
                    # حفظ البيانات بالسجل (مع خانة الدرجة الجديدة)
                    c.execute("INSERT INTO logs VALUES (?,?,?,?,?)", 
                              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "AI Analysis", u_input, label, confidence))
                    conn.commit()
                    
                    # عرض النتائج
                    st.divider()
                    if label == "Safe":
                        st.success(f"✅ النتيجة: المحتوى يبدو آمناً (التصنيف: {label} | الثقة: {confidence})")
                    else:
                        st.error(f"⚠️ تحذير: تم كشف محتوى مشبوه! (التصنيف: {label} | الثقة: {confidence})")
                    
                    # فحص الروابط تقنياً
                    urls = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})', u_input)
                    if urls:
                        st.markdown("---")
                        st.subheader("🔗 نتائج فحص الروابط (VirusTotal):")
                        for link in urls:
                            f_url = link if link.startswith("http") else "http://" + link
                            mal_count = check_url_vt(f_url)
                            if mal_count > 0:
                                st.warning(f"❌ الرابط **{link}** خطر! تم كشفه بـ {mal_count} محرك أمني.")
                            else:
                                st.info(f"✅ الرابط **{link}** نظيف حسب قواعد البيانات العالمية.")

    # التبويب الثاني: تتبع الـ IP
    with tab2:
        st.markdown("### 📍 تعقب العنوان الرقمي (IP Tracking)")
        ip_in = st.text_input("أدخل عنوان الـ IP المراد تتبعه:")
        if st.button("كشف الموقع"):
            if ip_in:
                info = get_ip_info(ip_in)
                if info and info['status'] == 'success':
                    c1, c2, c3 = st.columns(3)
                    c1.metric("🌍 الدولة", info['country'])
                    c2.metric("🏙️ المدينة", info['city'])
                    c3.metric("🛡️ VPN", "نعم" if info.get('proxy') else "لا")
                    st.info(f"🌐 الشركة المزودة: {info['isp']}")
                    st.link_button("📍 عرض الموقع على الخرائط", f"https://www.google.com/maps/search/?api=1&query={info['city']},{info['country']}")
                    
                    # حفظ عملية التتبع بالسجل (مع خانة فارغة للـ confidence لتوحيد الجدول)
                    c.execute("INSERT INTO logs VALUES (?,?,?,?,?)", 
                              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "IP Tracking", ip_in, f"{info['country']} - {info['city']}", "-"))
                    conn.commit()
                else:
                    st.error("❌ تعذر العثور على معلومات لهذا العنوان.")

    # التبويب الثالث: السجل (الآن سيعرض البيانات)
    with tab3:
        st.markdown("### 📜 سجل العمليات المؤرشفة")
        df = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
        if not df.empty:
            st.dataframe(df, use_container_width=True)
            if st.button("🗑️ مسح السجل بالكامل"):
                c.execute("DELETE FROM logs")
                conn.commit()
                st.rerun()
        else:
            st.info("السجل فارغ حالياً. قم بإجراء عمليات فحص لتظهر هنا.")

    # السايد بار الرسمي
    st.sidebar.markdown("<div class='sidebar-text'>جامعة المثنى<br>كلية هندسة الذكاء الاصطناعي و الأمن السيبراني<br>قسم هندسة الأمن السيبراني</div>", unsafe_allow_html=True)
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 الخروج من النظام"):
        st.session_state.started = False
        st.rerun()
